"""Linux private-directory storage. Never writes decrypted notebook data to disk."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import secrets
import stat
import uuid
import zlib
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAX_BYTES = 16 * 1024 * 1024
KDF = {"name": "scrypt", "n": 131072, "r": 8, "p": 1}


class NotebookError(ValueError):
    pass


def now():
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value, length=None):
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise NotebookError("Invalid encrypted notebook format.") from error
    if length is not None and len(raw) != length:
        raise NotebookError("Invalid encrypted notebook field size.")
    return raw


def _derive(passphrase, salt):
    if (
        not isinstance(passphrase, str)
        or len(passphrase) < 14
        or len(passphrase.encode()) > 1024
    ):
        raise NotebookError(
            "Use a unique notebook passphrase of 14 to 1024 bytes (at least 14 characters)."
        )
    return Scrypt(salt=salt, length=32, n=KDF["n"], r=KDF["r"], p=KDF["p"]).derive(
        passphrase.encode()
    )


def private_dir(path, create=False):
    """Open directory components with O_NOFOLLOW; keep an anchored leaf descriptor."""
    path = Path(os.path.abspath(os.path.expanduser(path)))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            last = index == len(path.parts[1:]) - 1
            if part in (".", ".."):
                raise NotebookError("Ambiguous directory path.")
            if create and last:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            # Ancestors need traversal permission, not directory listing.
            # Keep O_NOFOLLOW and require a readable, owner-private leaf.
            access = os.O_RDONLY if last else getattr(os, "O_PATH", os.O_RDONLY)
            next_fd = os.open(
                part, access | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise NotebookError(
                "Notebook/output directory must be owned by the current user with mode 0700."
            )
        return fd
    except Exception:
        os.close(fd)
        raise


def check_private_file(fd):
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
        or info.st_size > MAX_BYTES
    ):
        raise NotebookError(
            "Refused unsafe notebook file (owner, mode, size, type, or hard link)."
        )


class Vault:
    NAME = "notebook.enc"

    def __init__(self, path):
        self.path = Path(os.path.abspath(os.path.expanduser(path)))
        self.fd = private_dir(self.path)
        self.key = None
        self.header = None

    @classmethod
    def create(cls, path, passphrase, state):
        fd = private_dir(path, create=True)
        os.close(fd)
        vault = cls(path)
        try:
            with vault.lock():
                if vault.exists(cls.NAME) or vault.exists("deleted.json"):
                    raise NotebookError(
                        "Notebook already exists or this directory contains a deletion receipt."
                    )
                vault.header, vault.key = vault._new_header(passphrase)
                vault._save(state)
            return vault
        except Exception:
            vault.close()
            raise

    def exists(self, name):
        try:
            os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def _read(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            check_private_file(fd)
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise NotebookError("Notebook exceeds storage limit.")
            return data
        finally:
            os.close(fd)

    @contextmanager
    def lock(self):
        fd = os.open(
            ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=self.fd
        )
        try:
            check_private_file(fd)
            fcntl.flock(fd, fcntl.LOCK_EX)
            info = os.fstat(self.fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise NotebookError("Notebook directory permissions changed.")
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _new_header(self, passphrase, identity=None):
        key = AESGCM.generate_key(bit_length=256)
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        header = {
            "format": "cstk-notebook-1",
            "id": identity or str(uuid.uuid4()),
            "kdf": KDF,
            "salt": b64(salt),
            "wrap_nonce": b64(nonce),
        }
        header["wrapped_key"] = b64(
            AESGCM(_derive(passphrase, salt)).encrypt(nonce, key, canonical(header))
        )
        return header, key

    def unlock(self, passphrase):
        with self.lock():
            envelope = json.loads(self._read(self.NAME))
            header = envelope.get("header", {})
            if (
                set(header)
                != {"format", "id", "kdf", "salt", "wrap_nonce", "wrapped_key"}
                or header["format"] != "cstk-notebook-1"
                or header["kdf"] != KDF
            ):
                raise NotebookError("Unsupported notebook envelope/KDF.")
            try:
                uuid.UUID(header["id"])
            except (ValueError, TypeError):
                raise NotebookError("Invalid notebook identity.")
            aad = dict(header)
            wrapped = unb64(aad.pop("wrapped_key"), 48)
            try:
                self.key = AESGCM(
                    _derive(passphrase, unb64(header["salt"], 16))
                ).decrypt(unb64(header["wrap_nonce"], 12), wrapped, canonical(aad))
                self.header = header
                self._decode(envelope)
            except InvalidTag as error:
                self.key = None
                self.header = None
                raise NotebookError(
                    "Unlock failed: wrong passphrase or altered notebook."
                ) from error
        return self

    def _decode(self, envelope):
        if self.key is None:
            raise NotebookError("Notebook is locked.")
        if envelope.get("header") != self.header:
            raise NotebookError("Notebook key changed. Unlock again.")
        try:
            packed = AESGCM(self.key).decrypt(
                unb64(envelope["nonce"], 12),
                unb64(envelope["ciphertext"]),
                canonical(self.header),
            )
        except (InvalidTag, KeyError) as error:
            raise NotebookError(
                "Notebook authentication failed; data was altered."
            ) from error
        dec = zlib.decompressobj()
        plain = dec.decompress(packed, MAX_BYTES + 1)
        if len(plain) > MAX_BYTES or not dec.eof or dec.unused_data:
            raise NotebookError("Invalid or oversized compressed notebook.")
        state = json.loads(plain)
        verify_events(state)
        return state

    def _save(self, state):
        raw = canonical(state)
        if len(raw) > MAX_BYTES:
            raise NotebookError(
                "Notebook limit reached; archive and split the engagement."
            )
        nonce = secrets.token_bytes(12)
        envelope = {
            "header": self.header,
            "nonce": b64(nonce),
            "ciphertext": b64(
                AESGCM(self.key).encrypt(
                    nonce, zlib.compress(raw, 9), canonical(self.header)
                )
            ),
        }
        self._atomic(self.NAME, canonical(envelope))

    def _atomic(self, name, data):
        if len(data) > MAX_BYTES:
            raise NotebookError("Encrypted notebook exceeds storage limit.")
        temporary = ".pending-" + secrets.token_hex(16)
        fd = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.fd,
        )
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            os.close(fd)
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def read(self):
        with self.lock():
            return self._decode(json.loads(self._read(self.NAME)))

    def update(self, change):
        with self.lock():
            state = self._decode(json.loads(self._read(self.NAME)))
            result = change(state)
            verify_events(state)
            self._save(state)
            return result

    def rotate(self, new_passphrase):
        with self.lock():
            state = self._decode(json.loads(self._read(self.NAME)))
            header, key = self._new_header(new_passphrase, self.header["id"])
            old_header, old_key = self.header, self.key
            self.header, self.key = header, key
            try:
                event(state, "key_rotated", {})
                self._save(state)
            except Exception:
                self.header, self.key = old_header, old_key
                raise

    def close(self):
        self.key = None
        self.header = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def event(state, kind, details):
    events = state.setdefault("events", [])
    record = {
        "seq": len(events) + 1,
        "at": now(),
        "kind": kind,
        "details": details,
        "previous": events[-1]["sha256"] if events else "0" * 64,
    }
    record["sha256"] = digest(record)
    events.append(record)


def verify_events(state):
    if (
        not isinstance(state, dict)
        or state.get("schema") != 1
        or not isinstance(state.get("events"), list)
    ):
        raise NotebookError("Unsupported notebook content.")
    previous = "0" * 64
    for seq, record in enumerate(state["events"], 1):
        body = {k: v for k, v in record.items() if k != "sha256"}
        if (
            record.get("seq") != seq
            or record.get("previous") != previous
            or record.get("sha256") != digest(body)
        ):
            raise NotebookError("Notebook event chain is invalid.")
        previous = record["sha256"]
