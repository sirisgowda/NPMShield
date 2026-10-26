# NPMShield

A hybrid static and dynamic analysis pipeline for detecting malicious npm packages.

## Layout

- `engine/` has the static analyzer (`static_analyzer.py`, `ast_scan.js`), the sandbox runner (`sandbox_runner.py`, `sandbox/Dockerfile`), the fusion step (`fusion.py`) and the dashboard generator (`make_dashboard.py`).
- `results/` has the fused verdicts, extracted IOCs, JSON outputs and `dashboard.html`.
- `docs/` has the review presentations.

## Setup

The AST scanner needs two npm packages:

    npm install acorn acorn-walk

The sandbox runs packages inside Docker. Build the image from `engine/sandbox/`.

## Safety

No malware samples are included in this repository. The Discord webhook token seen in one sample has been redacted from all result files.