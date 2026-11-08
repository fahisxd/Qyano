"""Measure fresh-process and in-process command latency; no network commands."""

import argparse
import statistics
import subprocess
import time


def process_run(executable, command):
    started = time.perf_counter()
    subprocess.run([executable, *command], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True)
    return (time.perf_counter() - started) * 1000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", help="path to installed qy executable")
    parser.add_argument("--runs", type=int, default=30)
    args = parser.parse_args()
    from qyano.cli.router import dispatch

    for command in (("hash", "hello"), ("h", "hello")):
        first = process_run(args.executable, command)
        repeats = [process_run(args.executable, command) for _ in range(args.runs)]
        started = time.perf_counter()
        for _ in range(10000):
            dispatch(list(command))
        warm = (time.perf_counter() - started) * 1000 / 10000
        print(f"{' '.join(command)}: first fresh process {first:.2f} ms; "
              f"subsequent fresh-process median {statistics.median(repeats):.2f} ms "
              f"(min {min(repeats):.2f}, max {max(repeats):.2f}); "
              f"in-process warm mean {warm:.4f} ms")


if __name__ == "__main__":
    main()
