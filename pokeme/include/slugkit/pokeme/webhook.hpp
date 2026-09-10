#pragma once

/// @file
/// poke-me's outbound webhooks: verified, and parsed into something a caller
/// can act on without learning poke-me's wire format.
///
/// This belongs beside the client rather than in each service that receives
/// events, for the reason the client itself does: it is provider knowledge. The
/// signature scheme, the batch envelope and the event names are poke-me's, they
/// change when poke-me changes them, and a service that had learnt them would
/// have to be found and edited when they do.
///
/// ### The signature
///
/// **Asymmetric**, unlike most webhook schemes, so a consumer holds only the
/// public half and there is no shared secret to leak in either direction:
///
/// ```
/// X-PokeMe-Key-Id:    wk_019d8c00
/// X-PokeMe-Timestamp: 1757400000
/// X-PokeMe-Signature: base64url(Ed25519(timestamp + "." + body))
/// ```
///
/// Two properties are worth stating, because getting either wrong produces a
/// verifier that passes every test and accepts forgeries in production.
///
/// The **timestamp is inside the signed material**, not merely alongside it, so
/// a captured request cannot be replayed with a fresh one — but only if the
/// consumer also *rejects old timestamps*, which no signature can do for
/// itself. @ref VerifyWebhook takes the window for that reason rather than
/// leaving it to whoever remembers.
///
/// The **key id is not decoration**: more than one key is valid during a
/// rotation, so a consumer that ignored it would have to try each in turn and
/// could not tell a wrong key from a bad signature — the difference between
/// "rotate your keys" and "somebody is forging requests".
///
/// ### Acknowledge, do not process
///
/// poke-me's request timeout is **one second** and it suspends a hook whose p95
/// passes **500ms**. So a handler reads the batch, verifies, puts it somewhere
/// durable and returns 2xx; anything else belongs after the response. That is
/// the provider's rule rather than this library's, but it is the rule most
/// likely to be discovered the hard way, so it is repeated where the handler
/// author is looking.
///
/// ### At-least-once
///
/// A batch whose response is lost is sent again, so the same @ref Event::id may
/// arrive more than once. Deduplicate on it — not on @ref Batch::delivery_id,
/// which changes on every retry and is the attempt rather than the content.

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <userver/formats/json/value.hpp>

namespace slugkit::pokeme {

/// The headers poke-me signs with. Named here so a consumer never spells one
/// out — a header typo produces "unsigned", which reads like an attack.
inline constexpr std::string_view kKeyIdHeader = "X-PokeMe-Key-Id";
inline constexpr std::string_view kTimestampHeader = "X-PokeMe-Timestamp";
inline constexpr std::string_view kSignatureHeader = "X-PokeMe-Signature";

/// Why a webhook was refused.
///
/// Distinguished because they mean different things to an operator: a stale
/// timestamp is a slow network or a replay, an unknown key is a rotation we
/// have not caught up with, and a bad signature is the only one that means
/// somebody is lying. Collapsing them into one "401" is what makes a rotation
/// bug look like an attack for a day.
enum class Refusal {
    kOk,
    /// A required header was missing or unparseable.
    kMalformed,
    /// Outside the replay window.
    kStale,
    /// The key id names a key we do not hold.
    kUnknownKey,
    /// We hold the key and the signature does not verify under it.
    kBadSignature,
};

[[nodiscard]] auto ToString(Refusal refusal) -> std::string_view;

/// The bytes a signature covers: `timestamp + "." + body`.
///
/// Exposed rather than kept private so a consumer's own tests can construct a
/// signed request without reimplementing the format — the single most likely
/// place for a subtle disagreement with the sender.
[[nodiscard]] auto SigningPayload(std::int64_t timestamp, std::string_view body) -> std::string;

/// Verify @p signature_b64 over @p message with a base64url raw public key.
///
/// Accepts padded or unpadded base64url: poke-me emits unpadded, but a value
/// that has been through a config file or a copy-paste may have acquired `=`,
/// and refusing it would report a key problem that is really a transport one.
///
/// @returns false for anything wrong. Never throws — this runs on a path an
///          unauthenticated caller controls, and an exception there turns a
///          forged request into a 500 and a page.
[[nodiscard]] auto Verify(std::string_view public_key_b64, std::string_view message, std::string_view signature_b64)
    -> bool;

/// One verification, given the key the request named.
///
/// @param public_key_b64 what the key id resolved to, or **empty** when it
///        resolved to nothing — reported as @ref Refusal::kUnknownKey rather
///        than as a bad signature, which is why the lookup is the caller's and
///        not this function's.
/// @param max_age how old a timestamp may be; a timestamp *ahead* of now gets
///        the same slack, since the two clocks are not ours to align. Zero
///        disables the check, which is for tests and never for a deployment.
[[nodiscard]] auto VerifyWebhook(
    std::string_view public_key_b64,
    std::string_view timestamp_header,
    std::string_view signature_b64,
    std::string_view body,
    std::chrono::seconds max_age
) -> Refusal;

/// One event out of a batch.
///
/// The payload stays a `json::Value` rather than becoming a variant over every
/// declared type. poke-me's catalogue is a discriminated union that grows, and
/// a library that parsed each arm would have to ship a release before a
/// consumer could read a new event — while a consumer that only cares about two
/// types would carry parsers for a dozen. @ref event_type is the discriminator;
/// the consumer narrows what it recognises and ignores the rest.
struct Event {
    /// Stable across retries. **Deduplicate on this.**
    std::string id;
    /// `channel.created`, `namespace.created`, … The discriminator.
    std::string event_type;
    std::chrono::system_clock::time_point occurred_at;
    std::string organization_id;
    /// Set for events belonging to one app; empty for organisation-level
    /// events such as channels.
    std::string app_id;
    userver::formats::json::Value payload;
};

/// Events dropped before this hook could receive them — it was unreachable for
/// longer than poke-me's retention.
///
/// Nothing in this window will ever arrive. A consumer that treats a gap as
/// silence will believe nothing happened; the honest response is to reconcile
/// whatever the missing events would have told it.
struct Gap {
    std::chrono::system_clock::time_point from;
    std::chrono::system_clock::time_point to;
};

/// One request's worth.
struct Batch {
    /// This *attempt*. Changes on every retry — never deduplicate on it.
    std::string delivery_id;
    std::string organization_id;
    std::optional<Gap> gap;
    /// Oldest first.
    std::vector<Event> events;
};

/// Parse a verified batch body.
///
/// @throws userver::formats::json::Exception when the envelope is not a batch
///         at all. Call it only after @ref VerifyWebhook has passed: a body
///         nothing signed is not worth parsing, and parsing it first is how an
///         unauthenticated caller reaches your JSON reader.
[[nodiscard]] auto ParseBatch(const userver::formats::json::Value& body) -> Batch;

}  // namespace slugkit::pokeme
