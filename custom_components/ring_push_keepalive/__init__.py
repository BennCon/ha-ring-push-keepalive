"""Keep the Ring doorbell push listener alive.

A plain YAML-loaded component with no config: it applies the patches in
``patch.py`` once at startup, then reloads Ring if Ring won the startup race
and already built its listener without them.
"""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.start import async_at_started
from homeassistant.helpers.typing import ConfigType

from .patch import apply_patches

DOMAIN = "ring_push_keepalive"
RING_DOMAIN = "ring"

CONFIG_SCHEMA = cv.empty_config_schema(DOMAIN)

_LOGGER = logging.getLogger(__name__)

#: States in which Ring may already have built its listener config.
_EARLY_STATES = (
    ConfigEntryState.SETUP_IN_PROGRESS,
    ConfigEntryState.LOADED,
    ConfigEntryState.SETUP_RETRY,
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Patch the Ring listener, then get out of the way."""
    try:
        # Imports from site-packages, so keep it off the event loop.
        summaries = await hass.async_add_executor_job(apply_patches)
    except Exception:
        # Never block startup over this. An unpatched listener fails
        # silently, so this ERROR is the signal to alert on.
        _LOGGER.exception(
            "Could not patch the Ring push listener. Ring events may stop "
            "silently after a network drop or an undecryptable push"
        )
        return True

    for summary in summaries:
        _LOGGER.info("%s", summary)

    # The header patch replaces class methods, so it takes effect whenever it
    # lands. The config patch only reaches listeners built after it, and Ring
    # builds its listener during config entry setup, which may have run first.
    early = [
        entry.entry_id
        for entry in hass.config_entries.async_entries(RING_DOMAIN)
        if entry.state in _EARLY_STATES
    ]
    if early:

        @callback
        def _reload_ring(hass: HomeAssistant) -> None:
            _LOGGER.info(
                "Ring was set up before the listener patch; reloading it so "
                "the patched listener config takes effect"
            )
            for entry_id in early:
                hass.config_entries.async_schedule_reload(entry_id)

        async_at_started(hass, _reload_ring)

    return True
