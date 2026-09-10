#pragma once

/// @file
/// The webhook signing keys, fetched and kept fresh (poke-me WEBHOOKS.md).
///
/// A receiver needs the **public** half of whatever key signed the request in
/// front of it, and poke-me rotates: well before a key expires its successor is
/// minted and published, both verify for an overlap, and only then does signing
/// move to the newer one. So the answer to "which key" is a *set* that changes
/// on its own schedule, and a consumer that pinned one from a config file would
/// work until the first rotation and then reject everything.
///
/// Hence a cache rather than a setting. `GET /api/v1/orgs/{org}/webhook-keys`
/// is a JWKS in all but name; this pulls it on an interval and answers by key
/// id. The same shape `userver-paddle` uses for Paddle's notification secrets —
/// the mechanism a webhook receiver needs is the same whoever is signing, even
/// where the crypto is not.
///
/// ### Never fatal
///
/// A deployment whose key endpoint is unreachable — or which has no management
/// key at all — starts, says so once, and refuses webhooks with
/// @ref Refusal::kUnknownKey until it can fetch. Refusing to boot would take a
/// whole service down over an endpoint that only matters when a webhook
/// arrives, and poke-me retries a failed delivery for 24 hours: an outage here
/// costs latency, not events.

#include <chrono>
#include <string>
#include <string_view>
#include <unordered_map>

#include <userver/cache/caching_component_base.hpp>
#include <userver/clients/http/client.hpp>
#include <userver/server/http/http_request.hpp>
#include <userver/yaml_config/schema.hpp>

#include <slugkit/pokeme/webhook.hpp>

namespace slugkit::pokeme {

/// key id → base64url raw public key.
using KeySet = std::unordered_map<std::string, std::string>;

class WebhookKeys final : public userver::components::CachingComponentBase<KeySet> {
public:
    using BaseType = userver::components::CachingComponentBase<KeySet>;

    static constexpr std::string_view kName = "pokeme-webhook-keys";

    WebhookKeys(const userver::components::ComponentConfig& config, const userver::components::ComponentContext& context);
    ~WebhookKeys() override;

    static auto GetStaticConfigSchema() -> userver::yaml_config::Schema;

    /// Whether a management key resolved. False leaves the cache empty and
    /// every verification answering @ref Refusal::kUnknownKey.
    [[nodiscard]] auto Configured() const -> bool { return !management_key_.empty(); }

    /// The public key @p key_id names, or empty when we hold none.
    ///
    /// Empty is what @ref VerifyWebhook reads as an unknown key, so the two
    /// compose without the caller branching.
    [[nodiscard]] auto Find(std::string_view key_id) const -> std::string;

    /// Verify a whole request: headers, window, signature.
    ///
    /// The body is passed rather than read from @p request because a handler
    /// deriving from `HttpHandlerJsonBase` has already consumed it, and
    /// verifying a *re-serialised* body would compare a signature against
    /// different bytes — key order and whitespace are not preserved by a JSON
    /// round trip. Pass `request.RequestBody()`, always.
    [[nodiscard]] auto VerifyRequest(const userver::server::http::HttpRequest& request, std::string_view body) const
        -> Refusal;

private:
    auto Update(
        userver::cache::UpdateType type,
        const std::chrono::system_clock::time_point& last_update,
        const std::chrono::system_clock::time_point& now,
        userver::cache::UpdateStatisticsScope& stats_scope
    ) -> void override;

    userver::clients::http::Client& http_;
    std::string base_url_;
    std::string org_ref_;
    std::string management_key_;
    std::chrono::milliseconds timeout_;
    std::chrono::seconds max_age_;
};

}  // namespace slugkit::pokeme
