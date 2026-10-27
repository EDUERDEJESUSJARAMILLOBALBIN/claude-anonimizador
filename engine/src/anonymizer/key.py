"""The user's HMAC key: in the macOS Keychain, or in a 0600 file elsewhere."""

from __future__ import annotations

import os
import secrets
import subprocess
from pathlib import Path

from .env import variable

# Kept from v0.1 on purpose: renaming the Keychain item would create a new key and change
# every pseudonym the user already has.
KEYCHAIN_SERVICE = "anonimizador"
KEYCHAIN_ACCOUNT = "clave-hmac"
SECURITY = "/usr/bin/security"


def get_or_create() -> bytes:
    # An explicit ANONYMIZER_HOME (tests outside Claude Code) uses a file and never touches the
    # Keychain. Inside a session it is ignored: a project cannot plant a key it knows.
    home = variable("ANONYMIZER_HOME")
    if home is None and Path(SECURITY).exists():
        return _keychain()
    return _file(Path(home or Path.home() / ".anonimizador").expanduser() / "hmac.key")


def _keychain() -> bytes:
    found = subprocess.run(
        [SECURITY, "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"],
        capture_output=True,
        text=True,
    )
    if found.returncode == 0:
        return bytes.fromhex(found.stdout.strip())
    new = secrets.token_hex(32)
    # `security` only accepts the secret as an argument, so it is briefly visible in the process
    # list of the same user, who can read their own Keychain anyway.
    subprocess.run(
        [SECURITY, "add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w", new],
        check=True,
        capture_output=True,
    )
    return bytes.fromhex(new)


def _file(path: Path) -> bytes:
    if path.exists():
        return bytes.fromhex(path.read_text().strip())
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    new = secrets.token_hex(32)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(new)
    return bytes.fromhex(new)
