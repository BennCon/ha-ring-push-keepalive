"""Runtime patches that keep the Ring push listener alive.

Pure Python on purpose -- no Home Assistant imports -- so that
``scripts/test_patch.py`` can exercise it without a Home Assistant install.

Home Assistant's Ring integration receives doorbell and motion events through
``ring-doorbell``'s event listener, which is built on ``firebase-messaging``'s
``FcmPushClient``. When that client shuts down it never restarts, so the
``event.*`` entities silently stop updating while everything polled keeps
working. This module removes the two ways it shuts down in practice.

1. Undecryptable pushes (``Unknown error: Incorrect padding, shutting down
   FcmPushClient``). ``Crypto-Key`` and ``Encryption`` are ``;``-separated
   parameter lists (RFC 8188 2.1, RFC 8291 4) whose order is not fixed, but
   firebase-messaging 0.4.5 slices the prefix off by position::

       crypto_key = self._app_data_by_key(msg, "crypto-key")[3:]  # strip dh=
       salt = self._app_data_by_key(msg, "encryption")[5:]  # strip salt=

   Ring signs its pushes with VAPID, so ``dh`` arrives alongside
   ``p256ecdsa`` and the slice leaves ``; p256ecdsa=...`` attached. The decode
   error escapes ``_handle_data_message`` into the catch-all in ``_listen``,
   which terminates the client. It fails before the selective ACK, so Google
   redelivers the same message on every reconnect. Upstream fixes exist as
   sdb9696/firebase-messaging#37 and #43 but are unmerged.

   The header handling here is adapted from slettmayer/ha-fcm-header-fix (MIT).

2. Network drops (``Shutting down push receiver due to 3 sequential errors of
   type ErrorType.CONNECTION`` or ``Unable to connect to MCS endpoint after 5
   tries``). A router reboot produces a burst of read errors within
   milliseconds, which trips the default abort threshold of 3, and the
   reconnect gives up after five attempts (about 2.75 minutes). Both are
   public ``FcmPushClientConfig`` settings, and Home Assistant builds the
   listener from ``RingEventListenerConfig.default_config()``, so we raise
   them there.
"""

from __future__ import annotations

import functools
import logging
from importlib.metadata import PackageNotFoundError, version

_LOGGER = logging.getLogger(__name__)

#: The library versions these patches were written against and verified on.
TESTED_VERSIONS = {"firebase-messaging": "0.4.5", "ring-doorbell": "0.9.14"}

#: Sequential errors of one type before the client gives up. The counters
#: reset on any successful read, so a reconnect burst never gets near this,
#: but a persistent login failure still stops instead of retrying forever.
ABORT_ON_SEQUENTIAL_ERROR_COUNT = 50

#: Reconnect attempts per reset. The library sleeps 3 * n**2 seconds after
#: attempt n, so 12 attempts ride out roughly 32 minutes of outage.
CONNECTION_RETRY_COUNT = 12

#: Set on the wrappers so repeated setup cannot stack them.
_MARKER = "__ring_push_keepalive__"

#: App-data header -> the parameter the library actually wants from it.
_HEADER_PARAMS = {"crypto-key": "dh", "encryption": "salt"}


def _pad(value: str) -> str:
    """Restore the base64url padding the wire format strips."""
    return value + "=" * (-len(value) % 4)


def webpush_param(header: str, name: str) -> str:
    """Return one parameter's padded base64url value from a web push header.

    Looks the parameter up by name, so neither its position nor the presence
    of other parameters (``p256ecdsa`` from VAPID signing) matters. A header
    holding a bare value with no ``name=`` label is accepted as that value.

    Raises:
        ValueError: the header has parameters but not the requested one.
    """
    segments = [segment.strip() for segment in header.split(";") if segment.strip()]

    for segment in segments:
        label, separator, value = segment.partition("=")
        # A real "name=value" has content after the '='. In a bare base64url
        # value the only '=' are trailing padding, so value.strip("=") is empty.
        if separator and value.strip("=") and label.strip() == name:
            return _pad(value.strip())

    if len(segments) == 1:
        label, separator, value = segments[0].partition("=")
        if not separator or not value.strip("="):
            return _pad(segments[0])

    msg = f"web push header carries no {name!r} parameter"
    raise ValueError(msg)


def installed_version(package: str) -> str:
    """Return an installed package's version, or 'unknown'."""
    try:
        return version(package)
    except PackageNotFoundError:
        return "unknown"


def _patch_push_client() -> str:
    """Fix header parsing and stop a bad push from killing FcmPushClient."""
    from firebase_messaging import fcmpushclient  # noqa: PLC0415

    client = fcmpushclient.FcmPushClient
    found = installed_version("firebase-messaging")

    if getattr(client._app_data_by_key, _MARKER, False):  # noqa: SLF001
        return f"firebase-messaging {found}: push client patch already applied"

    for name in ("_app_data_by_key", "_handle_data_message"):
        if not callable(getattr(client, name, None)):
            msg = (
                f"firebase-messaging {found} has no {name}(); the patch must be "
                "re-checked against the new internals"
            )
            raise RuntimeError(msg)

    original_lookup = client._app_data_by_key  # noqa: SLF001
    original_handler = client._handle_data_message  # noqa: SLF001

    @functools.wraps(original_lookup)
    def _app_data_by_key(self, p, key, do_not_raise=False):  # noqa: ANN001, ANN202
        raw = original_lookup(self, p, key, do_not_raise)
        param = _HEADER_PARAMS.get(key)
        if not param or not raw:
            return raw
        # Hand back a single-parameter header so the caller's positional
        # slice ([3:] for "dh=", [5:] for "salt=") lands on the right value.
        return f"{param}={webpush_param(raw, param)}"

    @functools.wraps(original_handler)
    def _handle_data_message(self, msg):  # noqa: ANN001, ANN202
        try:
            return original_handler(self, msg)
        except Exception:  # noqa: BLE001 - anything here would kill the listener
            # Returning normally lets the caller acknowledge the message, so
            # Google stops redelivering it. That costs this one push, but the
            # alternative is a listener that stays dead.
            _LOGGER.error(
                "Skipped an undecryptable FCM push (persistent_id=%s) and "
                "acknowledged it to keep the Ring listener alive",
                getattr(msg, "persistent_id", "?"),
                exc_info=True,
            )
            return None

    setattr(_app_data_by_key, _MARKER, True)
    setattr(_handle_data_message, _MARKER, True)
    client._app_data_by_key = _app_data_by_key  # noqa: SLF001
    client._handle_data_message = _handle_data_message  # noqa: SLF001

    return f"firebase-messaging {found}: patched web push header parsing"


def _patch_listener_config() -> str:
    """Make the Ring listener retry through network drops instead of quitting."""
    from ring_doorbell.listen.listenerconfig import (  # noqa: PLC0415
        RingEventListenerConfig,
    )

    found = installed_version("ring-doorbell")
    original = RingEventListenerConfig.default_config

    if getattr(original, _MARKER, False):
        return f"ring-doorbell {found}: listener config patch already applied"

    for name in ("abort_on_sequential_error_count", "connection_retry_count"):
        if not hasattr(RingEventListenerConfig(), name):
            msg = (
                f"ring-doorbell {found} listener config has no {name}; the patch "
                "must be re-checked against the new library"
            )
            raise RuntimeError(msg)

    @functools.wraps(original)
    def default_config() -> RingEventListenerConfig:
        config = original()
        config.abort_on_sequential_error_count = ABORT_ON_SEQUENTIAL_ERROR_COUNT
        config.connection_retry_count = CONNECTION_RETRY_COUNT
        return config

    setattr(default_config, _MARKER, True)
    RingEventListenerConfig.default_config = staticmethod(default_config)

    return (
        f"ring-doorbell {found}: listener aborts after "
        f"{ABORT_ON_SEQUENTIAL_ERROR_COUNT} sequential errors and retries "
        f"connections {CONNECTION_RETRY_COUNT} times"
    )


def apply_patches() -> list[str]:
    """Apply both patches. Returns one summary line per patch for the log.

    Idempotent: calling it again reports that the patches are already applied.

    Raises:
        RuntimeError: a library is missing or no longer looks like the version
            these patches were written for.
    """
    try:
        summaries = [_patch_push_client(), _patch_listener_config()]
    except ImportError as err:  # pragma: no cover - depends on the HA install
        msg = "ring-doorbell is not installed; is the Ring integration set up?"
        raise RuntimeError(msg) from err

    for package, tested in TESTED_VERSIONS.items():
        found = installed_version(package)
        if found != tested:
            # Patch anyway: both changes are harmless on a fixed library,
            # whereas skipping would silently restore the bug on an upgrade.
            _LOGGER.warning(
                "Patched %s %s, but these patches were verified against %s. "
                "Check whether the fix landed upstream and this component can "
                "be removed",
                package,
                found,
                tested,
            )

    return summaries
