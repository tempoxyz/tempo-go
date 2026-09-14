"""Build first, then run with `uv run tests/differential/run.py` from repo root."""
import argparse
import fcntl
import pathlib
import re
import signal
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=int, default=1000)
    parser.add_argument("--seconds", type=int, default=12)
    args = parser.parse_args()
    if args.cases < 1 or args.seconds < 6:
        parser.error("cases must be positive and seconds at least 6")
    root = pathlib.Path(__file__).resolve().parents[2]
    go = root / "bin/tempo-dff"
    rust = root / "tests/differential/rust/target/debug/tempo-go-oracle"
    # DFF uses a fixed Unix socket and shared-memory key, so serialize runs.
    with open("/tmp/tempo-go-dff.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        corpus = subprocess.check_output([go, "-role", "corpus", "-count", str(args.cases)], timeout=60)
        go_output = subprocess.check_output([go, "-role", "replay"], input=corpus, timeout=120)
        rust_output = subprocess.check_output([rust, "--stdin"], input=corpus, timeout=120)
        if go_output != rust_output:
            pairs = zip(go_output.splitlines(), rust_output.splitlines())
            first = next((i + 1 for i, pair in enumerate(pairs) if pair[0] != pair[1]), "length")
            raise RuntimeError(f"deterministic corpus mismatch at seed {first}")
        print(f"PASS: {args.cases} deterministic Go/Rust encoding and signing-domain comparisons", flush=True)
        if pathlib.Path("/tmp/dff").exists():
            raise RuntimeError("DFF's fixed socket already exists; use an isolated host")
        # Preserve logs/findings for inspection, including failed runs.
        directory = pathlib.Path(tempfile.mkdtemp(prefix="tempo-go-dff-"))
        print(f"DFF evidence: {directory}", flush=True)
        processes, logs = [], []
        try:
            for name, command in [
                ("server", [go, "-role", "server"]),
                ("go", [go, "-role", "go"]),
                ("rust", [rust]),
            ]:
                log = open(directory / f"{name}.log", "w")
                logs.append(log)
                processes.append(subprocess.Popen(command, cwd=directory, stdout=log, stderr=subprocess.STDOUT))
                if name == "server":
                    deadline = time.monotonic() + 15
                    while not pathlib.Path("/tmp/dff").exists():
                        if processes[0].poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("DFF server did not start; inspect server.log")
                        time.sleep(0.05)
                else:
                    deadline = time.monotonic() + 15
                    while not (directory / f"{name}.ready").exists() or f"Registered new client: {name}" not in (directory / "server.log").read_text():
                        if processes[-1].poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError(f"DFF {name} client did not register")
                        time.sleep(0.05)
            deadline = time.monotonic() + args.seconds
            while time.monotonic() < deadline:
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError("DFF participant exited before run completed")
                time.sleep(0.1)
        finally:
            if processes and processes[0].poll() is None:
                processes[0].send_signal(signal.SIGTERM)
            for process in processes:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for log in logs:
                log.close()
        text = (directory / "server.log").read_text()
        if "Values are different" in text or "crashed" in text or (directory / "findings").exists():
            raise RuntimeError("DFF reported a disagreement or participant failure")
        counts = re.findall(r"Iterations: (\d+),.*Clients: go,rust", text)
        if not counts or int(counts[-1]) == 0:
            raise RuntimeError("no evidence of comparisons with both clients")
        print(f"PASS: DFF reported at least {counts[-1]} comparisons with go,rust and no disagreements")


if __name__ == "__main__":
    main()
