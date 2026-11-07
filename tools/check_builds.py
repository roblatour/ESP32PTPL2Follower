import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=("pre_v3", "v3_0", "v3_1", "s31"), default="v3_1")
    args = parser.parse_args()
    build = ROOT / f"build_matrix_{args.profile}"
    build.mkdir(exist_ok=True)
    policies = ((0, 0), (1, 0), (1, 1))
    for index, ptp in enumerate(policies, 1):
        label = f"{index:02d}_ptp_{ptp[0]}{ptp[1]}"
        definitions = {
            "FOLLOWER_PTP_AUTH_ENABLED": ptp[0],
            "FOLLOWER_PTP_AUTH_REQUIRED": ptp[1],
        }
        command = [sys.executable, str(ROOT / "tools" / "build.py"),
                   "--profile", args.profile, "--build-dir", build.name]
        for name, value in definitions.items():
            command.extend(("--define", f"{name}={value}"))
        print(f"Building {label}; local deployment header only; keep firmware/build artifacts private", flush=True)
        with (build / f"{label}.log").open("w", encoding="utf-8") as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=False)
        if result.returncode:
            print(f"FAIL: {label}; see {build / (label + '.log')}", flush=True)
            return result.returncode
        print(f"PASS: {label}", flush=True)
    print(f"PASS: {len(policies)} PTP firmware policy builds; compile evidence only; empty rings permit unsigned-only mixed mode but block required mode", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
