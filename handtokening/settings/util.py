import logging
from os import environ


logger = logging.getLogger(__name__)


false_values = ["0", "false", "no"]
true_values = ["1", "true", "yes"]


def env_bool(name: str, default: bool) -> bool:
    if (strval := environ.get(name)) is None:
        return default

    clean = strval.strip().lower()

    if clean in false_values:
        return False
    elif clean in true_values:
        return True
    else:
        logging.warning(
            "Environment variable '%s' value %r is not a recognised boolean value. Using default %s",
            name,
            strval,
            default,
        )
        return default
