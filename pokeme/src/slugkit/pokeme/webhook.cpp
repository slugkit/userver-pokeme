#include <slugkit/pokeme/webhook.hpp>

#include <charconv>
#include <cstdlib>
#include <memory>

#include <openssl/evp.h>

#include <userver/crypto/base64.hpp>
#include <userver/formats/json/value_builder.hpp>
#include <userver/utils/datetime.hpp>

namespace slugkit::pokeme {

namespace {

using EvpPkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpMdCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

/// Accepts either form. poke-me emits unpadded — a `=` in a header value is the
/// kind of thing that survives every test and then breaks on one consumer's
/// parser — but a key that has been through a config file may have acquired
/// padding, and refusing it would report a key problem that is a transport one.
auto Base64UrlDecode(std::string_view text) -> std::string {
    std::string padded{text};
    while (padded.size() % 4 != 0) {
        padded.push_back('=');
    }
    return userver::crypto::base64::Base64UrlDecode(padded);
}

}  // namespace

auto ToString(Refusal refusal) -> std::string_view {
    switch (refusal) {
        case Refusal::kOk:
            return "ok";
        case Refusal::kMalformed:
            return "malformed";
        case Refusal::kStale:
            return "stale";
        case Refusal::kUnknownKey:
            return "unknown key";
        case Refusal::kBadSignature:
            return "bad signature";
    }
    return "unknown";
}

auto SigningPayload(std::int64_t timestamp, std::string_view body) -> std::string {
    return std::to_string(timestamp) + "." + std::string{body};
}

auto Verify(std::string_view public_key_b64, std::string_view message, std::string_view signature_b64) -> bool {
    std::string public_bytes;
    std::string signature;
    try {
        public_bytes = Base64UrlDecode(public_key_b64);
        signature = Base64UrlDecode(signature_b64);
    } catch (const std::exception&) {
        return false;
    }

    EvpPkey key{
        EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519,
            nullptr,
            reinterpret_cast<const unsigned char*>(public_bytes.data()),
            public_bytes.size()
        ),
        &EVP_PKEY_free};
    if (!key) return false;

    EvpMdCtx ctx{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) <= 0) return false;

    // One-shot `EVP_DigestVerify`, not Update/Final: Ed25519 is PureEdDSA and
    // OpenSSL refuses the streaming interface for it.
    return EVP_DigestVerify(
               ctx.get(),
               reinterpret_cast<const unsigned char*>(signature.data()),
               signature.size(),
               reinterpret_cast<const unsigned char*>(message.data()),
               message.size()
           ) == 1;
}

auto VerifyWebhook(
    std::string_view public_key_b64,
    std::string_view timestamp_header,
    std::string_view signature_b64,
    std::string_view body,
    std::chrono::seconds max_age
) -> Refusal {
    if (timestamp_header.empty() || signature_b64.empty()) return Refusal::kMalformed;

    std::int64_t timestamp{};
    const auto* first = timestamp_header.data();
    const auto* last = first + timestamp_header.size();
    const auto parsed = std::from_chars(first, last, timestamp);
    if (parsed.ec != std::errc{} || parsed.ptr != last) return Refusal::kMalformed;

    // The window, before the key lookup is consulted: a stale request is
    // reported as stale even when it also names a key we have never held, which
    // is the more actionable of the two.
    if (max_age.count() > 0) {
        const auto now =
            std::chrono::duration_cast<std::chrono::seconds>(userver::utils::datetime::Now().time_since_epoch())
                .count();
        // Symmetric: a timestamp ahead of ours is the sender's clock, not an
        // attack, and the two clocks are not ours to align.
        if (std::abs(now - timestamp) > max_age.count()) return Refusal::kStale;
    }

    if (public_key_b64.empty()) return Refusal::kUnknownKey;

    if (!Verify(public_key_b64, SigningPayload(timestamp, body), signature_b64)) {
        return Refusal::kBadSignature;
    }
    return Refusal::kOk;
}

auto ParseBatch(const userver::formats::json::Value& body) -> Batch {
    Batch batch;
    batch.delivery_id = body["delivery_id"].As<std::string>("");
    batch.organization_id = body["organization_id"].As<std::string>("");

    if (body.HasMember("gap") && !body["gap"].IsNull()) {
        const auto& gap = body["gap"];
        batch.gap = Gap{
            .from = gap["from"].As<std::chrono::system_clock::time_point>(),
            .to = gap["to"].As<std::chrono::system_clock::time_point>(),
        };
    }

    const auto& events = body["events"];
    batch.events.reserve(events.GetSize());
    for (const auto& event : events) {
        batch.events.push_back(Event{
            .id = event["id"].As<std::string>(""),
            .event_type = event["event_type"].As<std::string>(""),
            .occurred_at = event["occurred_at"].As<std::chrono::system_clock::time_point>({}),
            .organization_id = event["organization_id"].As<std::string>(""),
            // Declared nullable, so absent and null are one state here — an
            // organisation-level event such as a channel belongs to no app.
            .app_id = event["app_id"].As<std::string>(""),
            .payload = event["payload"],
        });
    }
    return batch;
}

}  // namespace slugkit::pokeme
