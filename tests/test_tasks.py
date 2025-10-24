import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import tasks


TASK_FN = tasks.analyze_logs.__wrapped__.__func__


class DummyOutputFile:
    def __init__(self, path: Path):
        self.path = str(path)

    def to_dict(self):
        return {"path": self.path}


class DummyTask(SimpleNamespace):
    def __init__(self):
        super().__init__()
        self.dispatched = []

    def send_event(self, event_type, data=None):
        self.dispatched.append((event_type, data))


@pytest.fixture
def tmp_log(tmp_path):
    log_path = tmp_path / "syslog.log"
    log_path.write_text("example log\n", encoding="utf-8")
    return log_path


@pytest.fixture
def rules_dir(tmp_path, monkeypatch):
    rules_root = tmp_path / "rules"
    (rules_root / "linux" / "builtin").mkdir(parents=True)
    (rules_root / "linux" / "auditd").mkdir(parents=True)
    monkeypatch.setattr(tasks, "DEFAULT_RULES_ROOT", str(rules_root))
    return rules_root


def test_analyze_logs_generates_json(tmp_path, tmp_log, rules_dir, monkeypatch):
    task = DummyTask()

    monkeypatch.setattr(
        tasks,
        "get_input_files",
        lambda pipe_result, files, filter=None: [{
            "path": str(tmp_log),
            "display_name": Path(tmp_log).name,
        }],
    )

    created_files = []

    def fake_create_output_file(output_path, display_name, extension, data_type):
        out_path = tmp_path / f"{display_name}.{extension}"
        created_files.append(out_path)
        return DummyOutputFile(out_path)

    monkeypatch.setattr(tasks, "create_output_file", fake_create_output_file)

    recorded_commands = []

    class DummyCompletedProcess:
        def __init__(self, stdout="[]", stderr="", returncode=0):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    def fake_run(command, capture_output, text, check):
        recorded_commands.append(command)
        return DummyCompletedProcess(stdout=json.dumps([{"message": "hit"}]))

    monkeypatch.setattr(tasks.subprocess, "run", fake_run)

    result = TASK_FN(
        task,
        pipe_result=None,
        input_files=[{"path": str(tmp_log)}],
        output_path=str(tmp_path),
        workflow_id="wf1",
        task_config={
            "output_format": ["json"],
            "target": ["syslog"],
            "rule_bundle": "linux/builtin",
        },
    )

    decoded = json.loads(base64.b64decode(result).decode("utf-8"))
    assert created_files, "An output file should be created"
    written = created_files[0].read_text(encoding="utf-8")
    assert "message" in written
    assert decoded["meta"]["output_format"] == "json"
    assert recorded_commands[0][-2:] == ["-out", "json"], "-out flag should use requested format"


def test_analyze_logs_invalid_format_defaults_to_json(tmp_path, tmp_log, rules_dir, monkeypatch):
    task = DummyTask()

    monkeypatch.setattr(
        tasks,
        "get_input_files",
        lambda *args, **kwargs: [{"path": str(tmp_log), "display_name": "sample"}],
    )

    def fake_create_output_file(output_path, display_name, extension, data_type):
        out_path = tmp_path / f"{display_name}.{extension}"
        return DummyOutputFile(out_path)

    monkeypatch.setattr(tasks, "create_output_file", fake_create_output_file)

    def fake_run(command, capture_output, text, check):
        return DummyCompletedProcess(stdout="[]")

    class DummyCompletedProcess:
        def __init__(self, stdout="[]", stderr="", returncode=0):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    monkeypatch.setattr(tasks.subprocess, "run", fake_run)

    result = TASK_FN(
        task,
        pipe_result=None,
        input_files=[{"path": str(tmp_log)}],
        output_path=str(tmp_path),
        workflow_id="wf2",
        task_config={"output_format": "unsupported"},
    )

    decoded = json.loads(base64.b64decode(result).decode("utf-8"))
    assert decoded["meta"]["output_format"] == "json"


def test_analyze_logs_none_target_defaults_to_syslog(tmp_path, tmp_log, rules_dir, monkeypatch):
    task = DummyTask()

    monkeypatch.setattr(
        tasks,
        "get_input_files",
        lambda *args, **kwargs: [{"path": str(tmp_log), "display_name": "sample"}],
    )

    def fake_create_output_file(output_path, display_name, extension, data_type):
        out_path = tmp_path / f"{display_name}.{extension}"
        return DummyOutputFile(out_path)

    monkeypatch.setattr(tasks, "create_output_file", fake_create_output_file)

    recorded_commands = []

    class DummyCompletedProcess:
        def __init__(self, stdout="[]", stderr="", returncode=0):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    def fake_run(command, capture_output, text, check):
        recorded_commands.append(command)
        return DummyCompletedProcess(stdout="[]")

    monkeypatch.setattr(tasks.subprocess, "run", fake_run)

    result = TASK_FN(
        task,
        pipe_result=None,
        input_files=[{"path": str(tmp_log)}],
        output_path=str(tmp_path),
        workflow_id="wf-target",
        task_config={"output_format": "json", "target": None},
    )

    decoded = json.loads(base64.b64decode(result).decode("utf-8"))
    assert decoded["meta"]["target"] == "syslog"
    assert recorded_commands[0][1:3] == ["-target", "syslog"]


def test_rule_bundle_selection_overrides_default(tmp_path, tmp_log, rules_dir, monkeypatch):
    task = DummyTask()

    monkeypatch.setattr(
        tasks,
        "get_input_files",
        lambda *args, **kwargs: [{"path": str(tmp_log), "display_name": "sample"}],
    )

    def fake_create_output_file(output_path, display_name, extension, data_type):
        out_path = tmp_path / f"{display_name}.{extension}"
        return DummyOutputFile(out_path)

    monkeypatch.setattr(tasks, "create_output_file", fake_create_output_file)

    recorded_commands = []

    class DummyCompletedProcess:
        def __init__(self):
            self.stdout = "[]"
            self.stderr = ""
            self.returncode = 0

    def fake_run(command, capture_output, text, check):
        recorded_commands.append(command)
        return DummyCompletedProcess()

    monkeypatch.setattr(tasks.subprocess, "run", fake_run)

    result = TASK_FN(
        task,
        pipe_result=None,
        input_files=[{"path": str(tmp_log)}],
        output_path=str(tmp_path),
        workflow_id="wf-bundle",
        task_config={
            "output_format": "json",
            "target": "syslog",
            "rule_bundle": "linux/auditd",
        },
    )

    decoded = json.loads(base64.b64decode(result).decode("utf-8"))
    assert decoded["meta"]["target"] == "syslog"
    rules_arg_index = recorded_commands[0].index("-rules") + 1
    assert recorded_commands[0][rules_arg_index].endswith("linux/auditd")


def test_analyze_logs_none_format_defaults_to_json(tmp_path, tmp_log, rules_dir, monkeypatch):
    task = DummyTask()

    monkeypatch.setattr(
        tasks,
        "get_input_files",
        lambda *args, **kwargs: [{"path": str(tmp_log), "display_name": "sample"}],
    )

    def fake_create_output_file(output_path, display_name, extension, data_type):
        out_path = tmp_path / f"{display_name}.{extension}"
        return DummyOutputFile(out_path)

    monkeypatch.setattr(tasks, "create_output_file", fake_create_output_file)

    def fake_run(command, capture_output, text, check):
        return DummyCompletedProcess(stdout="[]")

    class DummyCompletedProcess:
        def __init__(self, stdout="[]", stderr="", returncode=0):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    monkeypatch.setattr(tasks.subprocess, "run", fake_run)

    result = TASK_FN(
        task,
        pipe_result=None,
        input_files=[{"path": str(tmp_log)}],
        output_path=str(tmp_path),
        workflow_id="wf3",
        task_config={"output_format": None},
    )

    decoded = json.loads(base64.b64decode(result).decode("utf-8"))
    assert decoded["meta"]["output_format"] == "json"


def test_analyze_logs_raises_on_failure(tmp_path, tmp_log, rules_dir, monkeypatch):
    task = DummyTask()

    monkeypatch.setattr(
        tasks,
        "get_input_files",
        lambda *args, **kwargs: [{"path": str(tmp_log), "display_name": "sample"}],
    )

    def fake_create_output_file(output_path, display_name, extension, data_type):
        out_path = tmp_path / f"{display_name}.{extension}"
        return DummyOutputFile(out_path)

    monkeypatch.setattr(tasks, "create_output_file", fake_create_output_file)

    class DummyCompletedProcess:
        def __init__(self, stdout="", stderr="boom", returncode=1):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    def fake_run(command, capture_output, text, check):
        return DummyCompletedProcess()

    monkeypatch.setattr(tasks.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError):
        TASK_FN(
            task,
            pipe_result=None,
            input_files=[{"path": str(tmp_log)}],
            output_path=str(tmp_path),
            workflow_id="wf3",
            task_config={"output_format": "json"},
        )


def test_analyze_logs_parse_failure_message(tmp_path, tmp_log, rules_dir, monkeypatch):
    task = DummyTask()

    monkeypatch.setattr(
        tasks,
        "get_input_files",
        lambda *args, **kwargs: [{"path": str(tmp_log), "display_name": "access"}],
    )

    def fake_create_output_file(output_path, display_name, extension, data_type):
        out_path = tmp_path / f"{display_name}.{extension}"
        return DummyOutputFile(out_path)

    monkeypatch.setattr(tasks, "create_output_file", fake_create_output_file)

    class DummyCompletedProcess:
        def __init__(self):
            self.stdout = ""
            self.stderr = "2025/10/24 18:36:32 Failed to parse events: Failed to match timestamp"
            self.returncode = 1

    monkeypatch.setattr(tasks.subprocess, "run", lambda *a, **k: DummyCompletedProcess())

    with pytest.raises(RuntimeError) as exc:
        TASK_FN(
            task,
            pipe_result=None,
            input_files=[{"path": str(tmp_log)}],
            output_path=str(tmp_path),
            workflow_id="wf-parse",
            task_config={"output_format": "json", "target": "syslog"},
        )

    assert "could not parse" in str(exc.value)
