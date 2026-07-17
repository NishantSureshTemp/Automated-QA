import subprocess, json, time, sys
from pathlib import Path
from datetime import datetime

ROSTER = Path("roster.json")
OUT    = Path("results.csv")

def main():
    # 1. record start time AFTER service is up
    start = datetime.now().strftime("%Y-%m-%d %H:%M:%S.000")
    print(f"[setup] start timestamp: {start}")
    print("[setup] service restarted")
    
    # 2. restart service first
    print("[setup] restarting SecureAiService...")
    subprocess.run(["net", "stop", "SecureAiService"], capture_output=True)
    time.sleep(3)
    subprocess.run(["net", "start", "SecureAiService"], capture_output=True)
    time.sleep(5)

    # 3. launch httpbin fixture
    httpbin = subprocess.Popen(
        ["python", "-c",
         "import requests, time, os; print(f'fixture PID: {os.getpid()}', flush=True);"
         "[requests.get('https://httpbin.org/get') or time.sleep(30) for _ in range(20)]"],
        stdout=subprocess.PIPE, text=True
    )
    pid_line = httpbin.stdout.readline().strip()
    fixture_pid = pid_line.split("PID:")[-1].strip()
    print(f"[setup] httpbin fixture PID: {fixture_pid}")

    # 4. patch roster with real PID
    cfg = json.loads(ROSTER.read_text())
    cfg["tcp_stats_test"]["by_pid"] = {
        fixture_pid: {"label": "httpbin fixture", "domain": "httpbin.org"}
    }
    ROSTER.write_text(json.dumps(cfg, indent=2))
    print("[setup] roster patched")

    #5. launch python+torch fixture for library detection test
    python_ai = subprocess.Popen(
        ["python", "-c",
        "import torch, time, os; print(f'python fixture PID: {os.getpid()}', flush=True);"
        "time.sleep(300)"],
        stdout=subprocess.PIPE, text=True
    )
    pid_line2 = python_ai.stdout.readline().strip()
    python_pid = pid_line2.split("PID:")[-1].strip()
    print(f"[setup] python+torch fixture PID: {python_pid}")

    # 6. wait for scanner cycles and registration to complete
    print("[setup] waiting 200 seconds for scanner cycles and registration...")
    time.sleep(180)

    # 7. run schannel fixture shortly before suite runs
    print("[setup] running schannel fixture...")
    subprocess.run(
        ["powershell", "-Command",
         "Invoke-WebRequest -Uri 'https://copilot.microsoft.com' -UseBasicParsing"],
        capture_output=True
    )
    print("[setup] schannel fixture done")
    time.sleep(20)  # give scanner time to catch the TLS event

    # 8. run the suite
    print("[setup] running suite...")
    subprocess.run([
        "python", "overall.py",
        "--start", start,
        "--roster", str(ROSTER),
        "--out", str(OUT),
    ])

    # 9. clean up
    print("[setup] cleaning up fixtures...")
    httpbin.terminate()
    print(f"[setup] done -- results in {OUT}")

if __name__ == "__main__":
    main()