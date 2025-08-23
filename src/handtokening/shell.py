import re
import shlex


pkcs11_pin_re = re.compile(r"pin-value=[^;]*")


def quote_cmd(args: list[str]) -> str:
    return " ".join(shlex.quote(arg) for arg in args)


def quote_cmd_hide_secrets(args: list[str]) -> str:
    return quote_cmd([pkcs11_pin_re.sub("pin-value=[redacted]", arg) for arg in args])
