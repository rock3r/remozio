#!/usr/bin/env python3
"""Summarize the xctest crash reports that macOS wrote during a failed CI job.

The hosted Mac runner is discarded when its job ends, so a crashed test leaves only a log line that it started. macOS
writes a crash report (`.ips`) for the process, and this script keeps the part a reviewer needs from it.

The repository is public, so a report is never copied as it is. The summary keeps only:

- the process name, the OS version, the exception and the termination reason;
- the frames of the thread that crashed, each as image name, symbol and offset.

It drops the other threads, the register state, the image paths (they hold the runner's user name), the process
paths and every field this script does not name. Only reports whose process name starts with `xctest` and that were
modified at or after `--since` are read. ReportCrash can write a report a few seconds after the process died, so
the script waits up to `--wait` seconds (15 by default) for the first one. A run without such reports writes nothing and exits 0; so does a report
that cannot be parsed, which only produces a warning.
"""
import argparse
import json
from pathlib import Path
import sys
import time

REPORT_DIRECTORIES = (Path.home() / 'Library/Logs/DiagnosticReports', Path('/Library/Logs/DiagnosticReports'))
MAXIMUM_FRAMES = 128


def parse(text):
    """Returns the header and body of an `.ips` file: one JSON line, then a JSON document."""
    header, separator, body = text.partition('\n')
    if not separator:
        raise ValueError('the report has no body')
    return json.loads(header), json.loads(body)


def text(value, limit=200):
    return str(value)[:limit] if value is not None else '?'


def summarize(header, body):
    process = body.get('procName') or header.get('app_name') or '?'
    lines = [f'process: {text(process)}', f'os: {text(header.get("os_version"))}',
             f'time: {text(body.get("captureTime") or header.get("timestamp"))}']
    exception = body.get('exception') or {}
    if exception:
        lines.append('exception: ' + ' '.join(text(exception.get(key)) for key in ('type', 'signal', 'subtype')
                                               if exception.get(key) is not None))
    termination = body.get('termination') or {}
    if termination:
        lines.append(f'termination: {text(termination.get("namespace"))} {text(termination.get("indicator"))}')
    images = body.get('usedImages') or []
    threads = body.get('threads') or []
    index = body.get('faultingThread')
    if not isinstance(index, int) or not 0 <= index < len(threads):
        lines.append('crashed thread: not in the report')
        return '\n'.join(lines) + '\n'
    thread = threads[index]
    lines.append(f'crashed thread {index}: {text(thread.get("queue") or thread.get("name") or "")}')
    frames = thread.get('frames') or []
    for number, frame in enumerate(frames[:MAXIMUM_FRAMES]):
        image = '?'
        image_index = frame.get('imageIndex')
        if isinstance(image_index, int) and 0 <= image_index < len(images):
            image = text(images[image_index].get('name'))
        symbol = text(frame.get('symbol'), limit=1000) if frame.get('symbol') else '???'
        offset = frame.get('symbolLocation', frame.get('imageOffset'))
        lines.append(f'{number:3} {image:30} {symbol} + {text(offset)}')
    if len(frames) > MAXIMUM_FRAMES:
        lines.append(f'... {len(frames) - MAXIMUM_FRAMES} more frames')
    return '\n'.join(lines) + '\n'


def reports(directories, since):
    for directory in directories:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob('*.ips')):
            try:
                if path.name.startswith('xctest') and path.stat().st_mtime >= since:
                    yield path
            except OSError:
                continue


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--since', type=float, required=True, help='job start, in seconds since the epoch')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--directory', type=Path, action='append', help='report directory (tests only)')
    parser.add_argument('--wait', type=float, default=15, help='seconds to wait for a late report')
    arguments = parser.parse_args(argv)
    directories = arguments.directory or REPORT_DIRECTORIES
    deadline = time.monotonic() + max(0, arguments.wait)
    found = list(reports(directories, arguments.since))
    while not found and time.monotonic() < deadline:
        time.sleep(min(1, max(0, deadline - time.monotonic())))
        found = list(reports(directories, arguments.since))
    written = 0
    for path in found:
        try:
            summary = summarize(*parse(path.read_text(errors='replace')))
        except (OSError, ValueError, AttributeError, TypeError) as error:
            print(f'::warning::Could not read crash report {path.name}: {type(error).__name__}')
            continue
        arguments.output.mkdir(parents=True, exist_ok=True)
        (arguments.output / (path.stem + '.txt')).write_text(summary)
        written += 1
    print(f'Summarized {written} xctest crash report(s).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
