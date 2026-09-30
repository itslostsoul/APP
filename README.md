# AMAS: Automated Malware Analysis Sandbox

Drop in a suspicious file, run it inside a locked-down, disposable Docker container, and get a plain-English
verdict with the evidence behind it. Heuristic triage, **not** an antivirus.

## Quick start (Windows)
1. Install **Docker Desktop** (running) and **JDK 17+**. For the dashboard also install **Python 3.9+**.
2. Double-click `run.bat`. It compiles on first run.
3. Drop a file onto the window and press **Analyze sample**. The first run builds the sandbox images, so allow a minute.
4. Press **Open dashboard** for the 3D behavior map, or run `dashboard.bat`.

Linux/macOS: `./run.sh` and `./dashboard.sh`.

Try the included `samples/dummy_virus.sh` and `samples/test_payload.py`. They are harmless demo files.

## Command line
```
run.bat suspicious.py          analyze without the GUI
run.bat -v sample.sh           also print system calls
run.bat --replay trace.txt --sample sample.sh --exit 1     re-score a saved strace, no Docker needed
```
Exit codes: 0 clean, 10 suspicious, 20 likely malicious, 30 malicious, 1 analysis failed.
Environment: `AMAS_TIMEOUT` (seconds, default 60), `AMAS_REPORTS`, `AMAS_HOME`.

## How it is contained
`--network none`, 512 MB RAM (no swap), 1 CPU, 128 processes, all capabilities dropped, `no-new-privileges`,
read-only root filesystem, small writable `/tmp`, non-root user, sample mounted read-only, container destroyed afterwards.
Docker containers share the host kernel: do not analyze anything you would not trust Docker to contain.

## Scoring
Findings add points: sandbox escape +30, persistence +25, credential files +25, network +20, network tools +20,
listeners +15, hidden files +15, writes outside /tmp +10, tampering +10, child processes (5 each, max 10), timeout +15.
15+ suspicious, 40+ likely malicious, 70+ malicious. If Docker itself fails, the result is "Analysis failed", never a verdict.

## Limits
- Windows `.exe` files are refused (the sandbox is Linux). Linux ELF binaries built for glibc may not start on the Alpine images.
- The sample must be readable by uid 10001 inside the container.
- Malware that detects sandboxes or sleeps past the time limit can look clean.

## Rebuilding the dashboard
The bundled `dashboard/static/app.js` works offline. To rebuild: `cd dashboard && npm install && npm run build`.

## Credits
Archivo and JetBrains Mono are bundled under the SIL Open Font License (`assets/fonts`, `dashboard/static/fonts`).
The dashboard's 3D view uses three.js and 3d-force-graph (MIT), bundled into `dashboard/static/app.js`.
