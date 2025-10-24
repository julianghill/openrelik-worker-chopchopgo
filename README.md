# OpenRelik worker · ChopChopGo

This worker wraps [ChopChopGo](https://github.com/M00NLIG7/ChopChopGo) so analysts can hunt through
Linux log artefacts straight from the OpenRelik UI. It ships the published
`v1.0.0-release-1` binary and the upstream Sigma rule pack, exposes the most common CLI
options through task configuration, and returns detections as JSON or CSV artefacts per
input file.

## What you can run from the OpenRelik UI

- **ChopChopGo log analysis (`analyze_logs`)** – supply one or more text-based Linux logs
  (for example `syslog` or `auditd` traces). The worker chooses the
  appropriate rule directory, runs ChopChopGo once per file, and stores the findings in
  the requested format.
- **Rule overrides** – advanced users can point the task at a custom rules directory
  (mounted into the container) without rebuilding the image. The UI exposes the field and
  the worker validates the provided path before execution.

Both behaviours are available in a single task definition so you can keep simple workflows
lightweight while still supporting bespoke hunts.

## Task configuration

| Field | Description |
| --- | --- |
| `output_format` | Autocomplete selector exposed as `json` or `csv`. Defaults to `json` when left blank. |
| `target` | Autocomplete selector for the ChopChopGo parser (`syslog` or `auditd`). Empty/unknown choices fall back to `syslog`. |
| `rule_bundle` | Optional autocomplete selector that lists the packaged Sigma directories (`linux/builtin`, `linux/auditd`, `linux/process_creation`, …). When omitted, the worker auto-selects a bundle that matches the target. |
| `rules_path` | Advanced text field that overrides the bundle with a custom directory you mounted into the container. |

## Deployment

Add the worker to your OpenRelik `docker-compose.yml`:

```
openrelik-worker-chopchopgo:
  container_name: openrelik-worker-chopchopgo
  build:
    context: ./openrelik-worker-chopchopgo
  image: ghcr.io/openrelik/openrelik-worker-chopchopgo:latest
  restart: always
  environment:
    - REDIS_URL=redis://openrelik-redis:6379
    - OPENRELIK_PYDEBUG=0
  volumes:
    - ./data:/usr/share/openrelik/data
  command: "celery --app=src.app worker --task-events --concurrency=2 --loglevel=INFO -Q openrelik-worker-chopchopgo"
```

If you use Tilt for local development, mirror the `docker_build` stanza from other workers so
that code changes under `src/` and `tests/` sync into the container without a rebuild.

## Local development

```
uv sync --group test
uv run pytest -s --cov=src
```

To run the worker against a local Redis broker:

```
REDIS_URL=redis://localhost:6379/0 \
uv run celery --app=src.app worker --task-events --concurrency=1 --loglevel=INFO
```

### Sample artefacts

The repository includes `tests/fixtures/syslog_chopchopgo_trigger.log`, a minimal
syslog extract containing a `rm /var/log/syslog` event. Uploading it through OpenRelik (or
running ChopChopGo manually) produces a detection for the builtin "Commands to Clear or
Remove the Syslog" Sigma rule—handy for smoke testing the pipeline end-to-end.

## Notes

- The Docker image downloads the official ChopChopGo release during build and caches the
  ruleset under `/opt/chopchopgo/rules`. Adjust `CHOPCHOPGO_VERSION` in the Dockerfile if you
  need to pin a different release.
- `rules_path` must point to a directory accessible inside the container. Use additional
  volume mounts in `docker-compose.yml` if you plan to ship custom rule bundles.
- Output artefacts are named `<input>_chopchopgo.<ext>` and tagged with
  `openrelik:chopchopgo:<format>` so downstream workers can filter them easily.
- Non-zero ChopChopGo exit codes surface as task failures with the captured stderr included in
  the worker logs.

## Credits

Credit for ChopChopGo goes to M00NL1G7. This worker merely packages the tool for OpenRelik automation.
