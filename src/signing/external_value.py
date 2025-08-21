import random
import string
import json
import os
import time
import socket
import select

from django.conf import settings


def random_file_name():
    return "".join(random.choices(string.ascii_letters + string.digits, k=16))


class ExternalValue:
    def __init__(self, req_data: dict):
        self.req_data = req_data
        name = random_file_name()
        self.tmp_request_file = f"/tmp/handtokening-requests/.{name}"
        self.request_file = f"/tmp/handtokening-requests/{name}"
        self.response_file = f"/tmp/handtokening-responses/{name}"
        self.socket = None

    def __enter__(self):
        to_write = json.dumps(self.req_data)
        with open(self.tmp_request_file, "w") as f:
            f.write(to_write)

        os.rename(self.tmp_request_file, self.request_file)

        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.socket.bind(self.response_file)

        return self

    def __exit__(self, ex_type, ex_value, ex_traceback):
        try:
            os.remove(self.request_file)
        except Exception:
            pass

        try:
            if self.socket:
                self.socket.close()
                self.socket = None

            os.remove(self.response_file)
        except Exception:
            pass

    def read(self, timeout=0) -> None | dict:
        read_ready, _, _ = select.select([self.socket], [], [], timeout)
        if not read_ready:
            return None

        response = json.loads(self.socket.recv(1024))

        return response

    def read_for(self, timeout=0) -> dict:
        result = self.read(timeout)
        if result is None:
            raise TimeoutError("No response received in time")
