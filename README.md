# Ring Push Keepalive

A Home Assistant custom component that stops the **Ring push listener** from
dying permanently, so `event.*_ding` and `event.*_motion` keep firing.

Home Assistant's Ring integration gets doorbell and motion events as push
notifications through [`ring-doorbell`][rd], which uses
[`firebase-messaging`][fm]. When that push client shuts down it never
restarts. Everything polled (cameras, battery, history, last activity) keeps
working, so nothing looks wrong — your doorbell automations just stop, until
you reload Ring and the cycle repeats.

## Do you have this problem?

Your Ring event entities stopped changing while `sensor.*_last_activity` keeps
updating, and your log has one of these at the moment it broke:

```text
ERROR [firebase_messaging.fcmpushclient] Unknown error: Incorrect padding, shutting down FcmPushClient.
ERROR [firebase_messaging.fcmpushclient] Shutting down push receiver due to 3 sequential errors of type ErrorType.CONNECTION
ERROR [firebase_messaging.fcmpushclient] Unable to connect to MCS endpoint after 5 tries, shutting down
```

## What it fixes

| Failure | Cause | Fix |
|---|---|---|
| `Incorrect padding` | Ring signs pushes with VAPID, so the `Crypto-Key` header carries two parameters. `firebase-messaging` 0.4.5 strips the `dh=` prefix by position and fails to decode the rest. The push is never acknowledged, so it is redelivered and kills the listener again after every reload. | Header parameters are looked up by name. Any push that still cannot be decrypted is logged and acknowledged instead of killing the listener. |
| `3 sequential errors of type CONNECTION` | A router reboot produces a burst of read errors within milliseconds, tripping the default abort threshold of 3. | Threshold raised to 50. Counters reset on every successful read, so only a persistent failure reaches it. |
| `Unable to connect ... after 5 tries` | Reconnects give up after 5 attempts, about 2¾ minutes. A router firmware update can take longer. | Retries raised to 12 (the library backs off 3·n² seconds, so about 32 minutes). |

The first is a runtime patch of a private method. The other two change
documented `FcmPushClientConfig` settings in the config Home Assistant's Ring
integration builds via `RingEventListenerConfig.default_config()`.

The header fix is adapted from [slettmayer/ha-fcm-header-fix][hfix], which
has a thorough write-up of that bug. Use this component *instead of* that one,
not alongside it (both are idempotent, but there is no reason to run two).

## Install

1. **HACS:** ⋮ → **Custom repositories** → add
   `https://github.com/BennCon/ha-ring-push-keepalive`, category
   **Integration**, then install **Ring Push Keepalive**.
   **Manual:** copy `custom_components/ring_push_keepalive/` into your
   `config/custom_components/`.
2. Add this line to `configuration.yaml` (without it the component never loads,
   and nothing will look wrong):

   ```yaml
   ring_push_keepalive:
   ```

3. Restart Home Assistant (a Ring reload is not enough: the patch has to load
   first).

## Check it is working

After the restart your log should contain, at INFO level:

```text
firebase-messaging 0.4.5: patched web push header parsing
ring-doorbell 0.9.14: listener aborts after 50 sequential errors and retries connections 12 times
```

You may also see `Ring was set up before the listener patch; reloading it`.
That is expected: if Ring finishes setting up before this component, Ring is
reloaded once after startup so its listener picks up the new settings.

A WARNING saying the patches were verified against other versions means a
library has been updated. Check whether the upstream fix has landed (see
below) and whether this component can be removed.

## Trade-offs

- **It patches library internals.** A future `firebase-messaging` release
  could change them. The component refuses to patch if the methods it wraps
  are gone, and logs an ERROR rather than blocking startup.
- **A push that cannot be decrypted is dropped.** If that push was a real
  ring, it is lost — but the listener stays up for the next one.
- **Outages longer than about 30 minutes still stop the listener.** A
  persistent failure (50 sequential errors of one type, such as revoked
  credentials) does too, deliberately, rather than retrying every few seconds
  forever.
- **Events during an outage are lost or arrive late.** Ring cannot reach Home
  Assistant while your connection is down; nothing here can change that.

## Optional: get told if it ever dies anyway

With `system_log: fire_event: true` in `configuration.yaml`, this automation
raises a notification for any listener shutdown or patch failure:

```yaml
alias: Ring push listener alert
triggers:
  - trigger: event
    event_type: system_log_event
    event_data:
      level: ERROR
conditions:
  - condition: template
    value_template: >
      {{ trigger.event.data.name == 'firebase_messaging.fcmpushclient'
         or trigger.event.data.name.startswith('custom_components.ring_push_keepalive') }}
actions:
  - action: persistent_notification.create
    data:
      title: Ring push listener
      message: "{{ trigger.event.data.message[0] }}"
```

## Remove it when upstream is fixed

The real fixes belong in `firebase-messaging`:
[#43][pr43] (select header parameters by name) and [#37][pr37] (harden
payload decoding), both unmerged at the time of writing, with no release since
0.4.5. Once Home Assistant ships a release containing them, remove the
`configuration.yaml` line and the component.

## Testing

`scripts/test_patch.py` reproduces both failures against the real libraries
(real ECE crypto, the library's own error counter), then applies the patches
and checks they are fixed:

```sh
python3 -m venv /tmp/rpk-venv
/tmp/rpk-venv/bin/pip install "ring-doorbell==0.9.14" "firebase-messaging==0.4.5" http-ece cryptography
/tmp/rpk-venv/bin/python scripts/test_patch.py
```

## License

MIT. Header handling adapted from [slettmayer/ha-fcm-header-fix][hfix]
(MIT, © 2026 Stefan Lettmayer).

[rd]: https://github.com/python-ring-doorbell/python-ring-doorbell
[fm]: https://github.com/sdb9696/firebase-messaging
[hfix]: https://github.com/slettmayer/ha-fcm-header-fix
[pr43]: https://github.com/sdb9696/firebase-messaging/pull/43
[pr37]: https://github.com/sdb9696/firebase-messaging/pull/37
