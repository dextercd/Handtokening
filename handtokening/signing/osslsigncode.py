from dataclasses import dataclass, field
import itertools
import os
from pathlib import Path
import random
import re
import shlex
import subprocess
import tempfile


@dataclass
class OSSLSignCodePkcs11:
    module: str
    provider: str | None = None
    engine: str | None = None


@dataclass
class OSSLSignCodeResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def success(self):
        return self.returncode == 0


@dataclass
class OSSLSignCodeCommand:
    # Where to find the osslsigncode program
    program_path: str | Path = "osslsigncode"

    # Where the certificate and key is located. Can be PKCS #11 URLs.
    cert_path: str | Path | None = None
    key_path: str | Path | None = None

    # Where to read the program and write the result (the program with a signature added).
    in_path: str | Path | None = None
    out_path: str | Path | None = None

    # Info needed for signing with objects from a PKCS #11 module.
    pkcs11: OSSLSignCodePkcs11 | None = None

    # Information to add to the signed file. The description is shown on the
    # Windows User Account Control prompt.
    description: str | None = None
    url: str | None = None

    # List of URLs to RFC 3161 timestamping servers. Can be empty.
    timestamp_servers: list[str] = field(default_factory=list)

    # Pin for accessing PKCS #11 objects.
    pin: str | None = None

    def shuffle_timestamp_servers(self):
        random.shuffle(self.timestamp_servers)

    def _require_fields(self, *field_names: list[str]):
        for field_name in field_names:
            if not getattr(self, field_name, None):
                raise RuntimeError(
                    f"Missing value for osslsigncode sign command: '{field_name}'"
                )

    @property
    def pkcs11_mode(self) -> str:
        if self.pkcs11 is None:
            return None
        elif self.pkcs11.provider:
            return "provider"
        elif self.pkcs11.engine:
            return "engine"
        else:
            raise RuntimeError("No osslsigncode pkcs11 provider or engine specified")

    def build_command(self) -> list[str]:
        self._require_fields("cert_path", "key_path", "in_path", "out_path")

        command = [
            str(self.program_path),
            "sign",
        ]

        if self.pkcs11:
            if self.pkcs11_mode == "provider":
                command.extend(["-provider", self.pkcs11.provider])
            elif self.pkcs11_mode == "engine":
                command.extend(["-pkcs11engine", self.pkcs11.engine])

            command.extend(["-pkcs11module", self.pkcs11.module])

        is_pkcs11_cert = self.cert_path.startswith("pkcs11:")

        command.extend(
            [
                "-pkcs11cert" if is_pkcs11_cert else "-certs",
                str(self.cert_path),
                "-key",
                str(self.key_path),
                "-in",
                str(self.in_path),
                "-out",
                str(self.out_path),
            ]
        )

        if self.description:
            command.extend(["-n", self.description])

        if self.url:
            command.extend(["-i", self.url])

        command.extend(
            itertools.chain.from_iterable(
                ["-ts", ts.url] for ts in self.timestamp_servers
            )
        )

        return command

    def run(self):
        command = self.build_command()
        env = None

        pin_path: str | None = None

        if self.pin:
            if self.pkcs11_mode == "provider":
                env = os.environ.copy()
                env["PKCS11_PIN"] = self.pin
                env["PKCS11_FORCE_LOGIN"] = "1"
            elif self.pkcs11_mode == "engine":
                pinfd, pin_path = tempfile.mkstemp()
                os.write(pinfd, self.pin.encode())
                os.close(pinfd)

                command.extend(["-readpass", pin_path])

        result = subprocess.run(command, capture_output=True, text=True, env=env)

        if pin_path:
            os.unlink(pin_path)

        return OSSLSignCodeResult(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )


_pkcs11_pin_re = re.compile(r"pin-value=[^;]*")


def command_log_string(command: list[str]) -> str:
    """Format the command arguments for logging.

    The pin-value PKCS #11 URL argument is redacted via a simple regex.
    """
    return " ".join(
        shlex.quote(_pkcs11_pin_re.sub("pin-value=[redacted]", arg)) for arg in command
    )
