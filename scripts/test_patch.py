#!/usr/bin/env python3
"""Standalone check for the ring_push_keepalive custom component.

Reproduces both ways the Ring push listener dies, then proves the patches
prevent them: real ECE crypto for the header bug, and the library's own error
counter for the network-drop abort. No mocks, no Home Assistant install.

The header cases are adapted from slettmayer/ha-fcm-header-fix (MIT).

Run it in a venv holding the library versions Home Assistant ships:

    python3 -m venv /tmp/rpk-venv
    /tmp/rpk-venv/bin/pip install "ring-doorbell==0.9.14" \
        "firebase-messaging==0.4.5" http-ece cryptography
    /tmp/rpk-venv/bin/python scripts/test_patch.py

Exits non-zero if any case fails.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
from base64 import urlsafe_b64encode
from pathlib import Path
from typing import Any

import http_ece
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from firebase_messaging import FcmPushClient, FcmRegisterConfig
from firebase_messaging.fcmpushclient import ErrorType
from firebase_messaging.proto.mcs_pb2 import DataMessageStanza
from ring_doorbell.listen.listenerconfig import RingEventListenerConfig

PATCH_MODULE = (
    Path(__file__).resolve().parent.parent
    / "custom_components"
    / "ring_push_keepalive"
    / "patch.py"
)

APP_ID = "test-app-id"
PAYLOAD = b'{"data": {"gcmData": "{}"}}'


def _b64(raw: bytes, *, pad: bool = True) -> str:
    """Encode as base64url, optionally stripping the trailing '=' padding."""
    encoded = urlsafe_b64encode(raw).decode("ascii")
    return encoded if pad else encoded.rstrip("=")


def _build_client(
    config: Any = None,
) -> tuple[FcmPushClient, list[Any], bytes, bytes]:
    """Return a client wired to a real keypair, plus its captured callbacks."""
    received: list[Any] = []
    receiver_key = ec.generate_private_key(ec.SECP256R1())
    auth_secret = os.urandom(16)

    credentials = {
        "gcm": {"app_id": APP_ID, "android_id": "1", "security_token": "1"},
        "keys": {
            # The library pads these two itself, so store them unpadded.
            "private": _b64(
                receiver_key.private_bytes(
                    Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
                ),
                pad=False,
            ),
            "secret": _b64(auth_secret, pad=False),
        },
    }
    client = FcmPushClient(
        lambda data, persistent_id, obj: received.append(data),
        FcmRegisterConfig("p", "a", "k", "s"),
        credentials,
        config=config,
    )
    receiver_public = receiver_key.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    )
    return client, received, receiver_public, auth_secret


def _encrypt(receiver_public: bytes, auth_secret: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt PAYLOAD as a web push sender would."""
    sender_key = ec.generate_private_key(ec.SECP256R1())
    salt = os.urandom(16)
    body = http_ece.encrypt(
        PAYLOAD,
        salt=salt,
        private_key=sender_key,
        dh=receiver_public,
        auth_secret=auth_secret,
        version="aesgcm",
    )
    sender_public = sender_key.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    )
    return body, sender_public, salt


def _stanza(body: bytes, crypto_key: str, encryption: str) -> DataMessageStanza:
    msg = DataMessageStanza()
    msg.persistent_id = "test-persistent-id"
    msg.raw_data = body
    msg.app_data.add(key="crypto-key", value=crypto_key)
    msg.app_data.add(key="encryption", value=encryption)
    msg.app_data.add(key="subtype", value=APP_ID)
    return msg


def _vapid_noise() -> str:
    """A p256ecdsa parameter of the shape Ring's VAPID signing adds."""
    return _b64(
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(Encoding.X962, PublicFormat.UncompressedPoint),
        pad=False,
    )


# A working push carries dh alone and padded; the VAPID form carries dh
# unpadded next to p256ecdsa. salt is always padded.
def shape_plain(dh: bytes, salt: bytes) -> tuple[str, str]:
    return f"dh={_b64(dh)}", f"salt={_b64(salt)}"


def shape_vapid(dh: bytes, salt: bytes) -> tuple[str, str]:
    return (
        f"dh={_b64(dh, pad=False)}; p256ecdsa={_vapid_noise()}",
        f"salt={_b64(salt)}",
    )


def shape_vapid_reordered(dh: bytes, salt: bytes) -> tuple[str, str]:
    return f"p256ecdsa={_vapid_noise()}; dh={_b64(dh)}", f"salt={_b64(salt)}"


def shape_no_dh(dh: bytes, salt: bytes) -> tuple[str, str]:
    return f"p256ecdsa={_vapid_noise()}", f"salt={_b64(salt)}"


def _run(shape: Any) -> tuple[bool, str]:
    """Feed one header shape through _handle_data_message.

    Returns (payload_delivered, exception_name_or_empty).
    """
    client, received, receiver_public, auth_secret = _build_client()
    body, dh, salt = _encrypt(receiver_public, auth_secret)
    crypto_key, encryption = shape(dh, salt)
    try:
        client._handle_data_message(_stanza(body, crypto_key, encryption))  # noqa: SLF001
    except Exception as err:  # noqa: BLE001 - the point is to see what escapes
        return bool(received), type(err).__name__
    return bool(received), ""


def _survives_burst(errors: int) -> bool:
    """Feed a burst of connection errors to a client using Ring's config.

    Returns True if the client is still willing to reset after all of them,
    i.e. it did not abort the way it did after the router reboots.
    """

    async def burst() -> bool:
        # Aborting cancels the client's tasks, which needs a running loop.
        client, *_ = _build_client(RingEventListenerConfig.default_config())
        return all(
            client._try_increment_error_count(ErrorType.CONNECTION)  # noqa: SLF001
            for _ in range(errors)
        )

    return asyncio.run(burst())


def main() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool, detail: str) -> None:
        status = "PASS" if condition else "FAIL"
        print(f"  [{status}] {label}: {detail}")
        if not condition:
            failures.append(label)

    print("Phase A - baseline: the unpatched libraries must reproduce both bugs")
    delivered, error = _run(shape_vapid)
    check(
        "VAPID header crashes unpatched",
        not delivered and error != "",
        f"delivered={delivered} raised={error or 'nothing'}",
    )
    delivered, error = _run(shape_plain)
    check(
        "single-parameter header works unpatched",
        delivered and error == "",
        f"delivered={delivered} raised={error or 'nothing'}",
    )
    check(
        "3 connection errors abort unpatched",
        not _survives_burst(3),
        "client aborts on the third error",
    )

    print("\nPhase B - patched: apply the component's patches and retest")
    spec = importlib.util.spec_from_file_location("ring_push_patch", PATCH_MODULE)
    assert spec and spec.loader
    patch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patch)
    for summary in patch.apply_patches():
        print(f"  {summary}")

    for label, shape in (
        ("VAPID header decrypts once patched", shape_vapid),
        ("single-parameter header still works", shape_plain),
        ("parameter order and padding do not matter", shape_vapid_reordered),
    ):
        delivered, error = _run(shape)
        check(
            label,
            delivered and error == "",
            f"delivered={delivered} raised={error or 'nothing'}",
        )

    delivered, error = _run(shape_no_dh)
    check(
        "undecryptable push does not escape",
        not delivered and error == "",
        f"delivered={delivered} raised={error or 'nothing'}",
    )

    config = RingEventListenerConfig.default_config()
    check(
        "listener config raised",
        config.abort_on_sequential_error_count
        == patch.ABORT_ON_SEQUENTIAL_ERROR_COUNT
        and config.connection_retry_count == patch.CONNECTION_RETRY_COUNT,
        f"abort={config.abort_on_sequential_error_count} "
        f"retries={config.connection_retry_count}",
    )
    check(
        "Ring's own config changes are kept",
        config.server_heartbeat_interval == 60
        and config.client_heartbeat_interval == 120
        and config.monitor_interval == 15,
        f"server_hb={config.server_heartbeat_interval} "
        f"client_hb={config.client_heartbeat_interval} "
        f"monitor={config.monitor_interval}",
    )
    check(
        "a reconnect burst no longer aborts",
        _survives_burst(10),
        "client survives 10 sequential connection errors",
    )
    check(
        "a persistent failure still stops eventually",
        not _survives_burst(patch.ABORT_ON_SEQUENTIAL_ERROR_COUNT),
        f"client aborts at {patch.ABORT_ON_SEQUENTIAL_ERROR_COUNT} errors",
    )

    again = patch.apply_patches()
    check(
        "patches are idempotent",
        all("already" in summary for summary in again),
        "; ".join(again),
    )

    print()
    if failures:
        print(f"FAILED ({len(failures)}): {', '.join(failures)}")
        return 1
    print("All cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
