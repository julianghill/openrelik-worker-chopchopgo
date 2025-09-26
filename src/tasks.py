import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from celery import signals
from celery.utils.log import get_task_logger

from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.logging import Logger
from openrelik_worker_common.task_utils import (
    create_task_result,
    get_input_files,
)

from .app import celery


WORKER_NAME = "openrelik-worker-chopchopgo"
TASK_NAME = f"{WORKER_NAME}.tasks.analyze_logs"
SUPPORTED_FORMATS = {"json", "csv"}
DEFAULT_TARGET = os.getenv("CHOPCHOPGO_DEFAULT_TARGET", "syslog")
DEFAULT_RULES_ROOT = os.getenv(
    "CHOPCHOPGO_RULES_DIR", "/opt/chopchopgo/rules"
)
BINARY_PATH = os.getenv("CHOPCHOPGO_BINARY", "chopchopgo")

TARGET_RULE_SUBPATHS = {
    "syslog": Path("linux") / "builtin",
    "journald": Path("linux") / "builtin",
    "auditd": Path("linux") / "auditd",
}

TASK_METADATA = {
    "display_name": "ChopChopGo Linux Log Analyzer",
    "description": "Parse Linux logs with ChopChopGo and export Sigma-based detections",
    "task_config": [
        {
            "name": "output_format",
            "label": "Output format (json/csv)",
            "description": "Select the desired output format. Defaults to json if left empty.",
            "type": "text",
            "required": False,
        },
        {
            "name": "target",
            "label": "ChopChopGo target",
            "description": (
                "Optional target passed to ChopChopGo (-target). Defaults to syslog."
            ),
            "type": "text",
            "required": False,
        },
        {
            "name": "rules_path",
            "label": "Rules directory",
            "description": (
                "Custom rules directory to pass with -rules."
                " Defaults to built-in rules for the chosen target."
            ),
            "type": "text",
            "required": False,
        },
    ],
}

COMPATIBLE_INPUTS = {
    "data_types": [],
    "mime_types": ["text/plain", "application/octet-stream"],
    "filenames": ["*.log", "*.txt", "*"],
}

log_root = Logger()
logger = log_root.get_logger(__name__, get_task_logger(__name__))


def _determine_output_format(task_config: Optional[Dict[str, str]]) -> str:
    raw_value = (task_config or {}).get("output_format")
    if raw_value is None:
        return "json"

    configured = str(raw_value).strip().lower()
    if configured in SUPPORTED_FORMATS:
        return configured

    if configured:
        logger.warning(
            "Unsupported output_format '%s'. Falling back to json.", configured
        )
    return "json"


def _determine_target(task_config: Optional[Dict[str, str]]) -> str:
    raw_value = (task_config or {}).get("target")
    if raw_value is None:
        return DEFAULT_TARGET

    target_candidate = str(raw_value).strip()
    return target_candidate or DEFAULT_TARGET


def _resolve_rules_path(target: str, rules_override: Optional[str]) -> Optional[str]:
    if rules_override:
        override_path = Path(rules_override)
        return str(override_path) if override_path.is_dir() else None

    default_subpath = TARGET_RULE_SUBPATHS.get(target, Path("linux") / "builtin")
    candidate = Path(DEFAULT_RULES_ROOT) / default_subpath

    return str(candidate) if candidate.is_dir() else None


@signals.task_prerun.connect
def on_task_prerun(sender, task_id, task, args, kwargs, **_):
    log_root.bind(
        task_id=task_id,
        task_name=task.name,
        worker_name=TASK_METADATA.get("display_name"),
    )


@celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def analyze_logs(
    self,
    pipe_result: Optional[str] = None,
    input_files: Optional[List[Dict]] = None,
    output_path: Optional[str] = None,
    workflow_id: Optional[str] = None,
    task_config: Optional[Dict[str, str]] = None,
) -> str:
    log_root.bind(workflow_id=workflow_id)
    logger.info("Starting ChopChopGo analysis for workflow %s", workflow_id)

    files = get_input_files(pipe_result, input_files or [], filter=COMPATIBLE_INPUTS)
    if not files:
        raise RuntimeError("No compatible input files provided to ChopChopGo")

    output_format = _determine_output_format(task_config)
    target = _determine_target(task_config)
    rules_path = _resolve_rules_path(target, (task_config or {}).get("rules_path"))

    if not rules_path:
        raise RuntimeError(
            "Unable to locate rules directory. Provide 'rules_path' in task configuration."
        )

    output_files = []

    total_files = len(files)

    for index, input_file in enumerate(files, start=1):
        file_path = input_file.get("path")
        if not file_path:
            logger.warning("Skipping input without path: %s", input_file)
            continue

        display_name = input_file.get("display_name") or Path(file_path).name
        output_display_name = f"{Path(display_name).stem}_chopchopgo"

        output_file = create_output_file(
            output_path,
            display_name=output_display_name,
            extension=output_format,
            data_type=f"openrelik:chopchopgo:{output_format}",
        )

        command = [
            BINARY_PATH,
            "-target",
            target,
            "-rules",
            rules_path,
            "-file",
            file_path,
            "-out",
            output_format,
        ]

        logger.debug("Running ChopChopGo command: %s", command)

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            logger.error(
                "ChopChopGo failed for %s: %s", file_path, result.stderr or result.stdout
            )
            raise RuntimeError(
                f"ChopChopGo exited with code {result.returncode} while processing {display_name}"
            )

        if result.stderr:
            logger.debug("ChopChopGo stderr for %s: %s", file_path, result.stderr)

        output_data = result.stdout or ""
        Path(output_file.path).write_text(output_data, encoding="utf-8")

        output_files.append(output_file.to_dict())
        self.send_event(
            "task-progress",
            data={
                "current": index,
                "total": total_files,
                "message": f"Processed {display_name}",
            },
        )

    if not output_files:
        raise RuntimeError("ChopChopGo did not produce any outputs")

    logger.info("ChopChopGo analysis completed: %d file(s) processed", len(output_files))

    return create_task_result(
        output_files=output_files,
        workflow_id=workflow_id,
        command=" ".join(command),
        meta={
            "output_format": output_format,
            "target": target,
            "rules_path": rules_path,
        },
    )
