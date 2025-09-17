#!/usr/bin/env python3

import asyncio
from pathlib import Path
import json
import glob
import sys
import logging
import os
import socket
import argparse
import termios


class DisableEcho:
    def __init__(self, file=sys.stdin):
        self.fd = file.fileno()

    def __enter__(self):
        self.restore = termios.tcgetattr(self.fd)

        noecho = self.restore.copy()
        noecho[3] &= ~termios.ECHO
        termios.tcsetattr(self.fd, termios.TCSADRAIN, noecho)

    def __exit__(self, exc_type, exc_value, traceback):
        termios.tcsetattr(self.fd, termios.TCSADRAIN, self.restore)


logger = logging.getLogger(__name__)

done_files = set()
file_gone = object()


async def connect_stdin() -> asyncio.StreamReader:
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    return reader


async def monitor_path(path):
    while os.path.exists(path):
        await asyncio.sleep(0.2)
    return file_gone


async def handle_request(request, response_path):
    stdin = await connect_stdin()

    print(end="\a")
    print(f"User {request['user']} wants to sign a program.")
    print(f"Selected certificate: {request['certificate']}.")
    print()
    print(f"This is the program description: {request['description']!r}")
    print()
    print("Enter the token password to continue. 'q + enter' to cancel.")
    print()

    with DisableEcho():
        inp = (await stdin.readline()).decode().strip()

    if inp.lower() == "q":
        response = {"result": "cancelled"}
    else:
        response = {"result": "approve", "code": inp}

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(str(response_path))
    sock.send(json.dumps(response).encode())

    print("Done", end=5*"\n")


async def handle_file(request_path, response_path):
    with open(request_path, "rb") as f:
        request = json.load(f)

    file_mon = asyncio.create_task(monitor_path(request_path))
    request_task = asyncio.create_task(handle_request(request, response_path))

    done, pending = await asyncio.wait([file_mon, request_task], return_when=asyncio.FIRST_COMPLETED)

    if request_task in pending:
        print("Gone")

    request_task.cancel()
    file_mon.cancel()
    await asyncio.gather(file_mon, request_task, return_exceptions=True)


async def file_monitor(req_dir: Path, resp_dir: Path):
    while True:
        files = set(req_dir.glob("[!.]*")) - done_files
        if files:
            try:
                file = next(iter(files))
                resp = resp_dir / file.name
                await handle_file(file, resp)
            except:
                logger.exception(f"Failed request {file}")
            finally:
                done_files.add(file)
        else:
            await asyncio.sleep(0.5)



async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("rundir", type=Path)
    args = parser.parse_args()

    req_dir = args.rundir / "requests"
    resp_dir = args.rundir / "responses"

    fm = asyncio.create_task(file_monitor(req_dir, resp_dir))
    await fm

asyncio.run(main())
