# userver-pokeme

Components for consuming [poke-me](https://push-me.io) webhooks with
[userver](https://userver.tech).

Provider knowledge lives here rather than in each service that receives events:
the signature scheme, the batch envelope and the event names are poke-me's, they
change when poke-me changes them, and a service that had learnt them would have
to be found and edited when they do.

## What it does

| | |
|---|---|
| `slugkit/pokeme/webhook.hpp` | Ed25519 signature verification, the replay window, and the batch envelope |
| `slugkit/pokeme/keys.hpp` | `WebhookKeys` — a caching component that fetches the org's public keys and keeps up with rotation |
| `slugkit/pokeme/secrets.hpp` | the management key, out of the static config and into secdist |

## The signature

poke-me signs **asymmetrically**, so a receiver holds only the public half and
there is no shared secret to leak in either direction:

```
X-PokeMe-Key-Id:    wk_019d8c00
X-PokeMe-Timestamp: 1757400000
X-PokeMe-Signature: base64url(Ed25519(timestamp + "." + body))
```

Two properties matter, because getting either wrong produces a verifier that
passes every test and accepts forgeries in production.

The **timestamp is inside the signed material**, not merely alongside it, so a
captured request cannot be replayed with a fresh one — but only if the receiver
also rejects old timestamps, which no signature can do for itself.
`VerifyWebhook` takes the window for that reason rather than leaving it to
whoever remembers.

The **key id is not decoration**: more than one key is valid during a rotation,
so a receiver that ignored it would have to try each in turn and could not tell
a wrong key from a bad signature — the difference between "rotate your keys" and
"somebody is forging requests". `Refusal` keeps those apart for the same reason.

## Wiring

```yaml
components_manager:
    components:
        pokeme-webhook-keys:
            base-url: https://push-me.io
            org-ref: acme
            secdist-key: default
            max-signature-age: 5m
            update-interval: 1h
            first-update-fail-ok: true
```

secdist, keyed by `secdist-key`:

```json
{ "pokeme": { "default": { "management_key": "mk_…" } } }
```

The management key needs `webhooks:read` and nothing more — a key that could
also publish is one a webhook receiver has no business holding.

A handler then verifies against the **raw body**, never a re-serialised one:

```cpp
const auto refusal = keys_.VerifyRequest(request, request.RequestBody());
if (refusal != slugkit::pokeme::Refusal::kOk) {
    request.SetResponseStatus(userver::server::http::HttpStatus::kUnauthorized);
    return {};
}
const auto batch = slugkit::pokeme::ParseBatch(request_json);
```

A JSON round trip does not preserve key order or whitespace, so verifying a
re-serialised body compares the signature against different bytes than were
signed.

## Two rules poke-me imposes on receivers

**Acknowledge, do not process.** The request timeout is one second and a hook
whose p95 passes 500ms is suspended. Read the batch, verify, put it somewhere
durable, return 2xx; anything else belongs after the response.

**Delivery is at-least-once.** A batch whose response is lost is sent again, so
the same event `id` may arrive more than once — deduplicate on it, never on
`delivery_id`, which is the attempt rather than the content.

## Never fatal

A deployment with no management key, or one whose key endpoint is unreachable,
starts anyway: it says so once and refuses callbacks as `kUnknownKey` until it
can fetch. Refusing to boot would take a whole service down over an endpoint
that only matters when a webhook arrives — and poke-me retries a failed delivery
for 24 hours, so an outage here costs latency rather than events.

## Building

The root `CMakeLists.txt` is a standalone harness that expects userver at
`/userver`. To vendor this into a project that has already configured userver,
add the `pokeme/` subdirectory instead:

```cmake
add_subdirectory(third-party/userver-pokeme/pokeme pokeme-client)
target_link_libraries(your-service PRIVATE slugkit-pokeme)
```

Set `USERVER_POKEME_BUILD_TESTS=ON` to build the unit tests.

## Licence

Apache-2.0.
