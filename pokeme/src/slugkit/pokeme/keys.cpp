#include <slugkit/pokeme/keys.hpp>

#include <fmt/format.h>

#include <userver/clients/http/component.hpp>
#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/formats/json/serialize.hpp>
#include <userver/logging/log.hpp>
#include <userver/storages/secdist/component.hpp>
#include <userver/tracing/span.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <slugkit/pokeme/secrets.hpp>

namespace slugkit::pokeme {

namespace {

auto Trim(std::string url) -> std::string {
    while (!url.empty() && url.back() == '/') url.pop_back();
    return url;
}

}  // namespace

WebhookKeys::WebhookKeys(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context
)
    : BaseType{config, context}
    , http_{context.FindComponent<userver::components::HttpClient>().GetHttpClient()}
    , base_url_{Trim(config["base-url"].As<std::string>(""))}
    , org_ref_{config["org-ref"].As<std::string>("")}
    , timeout_{config["timeout"].As<std::chrono::milliseconds>(std::chrono::seconds{10})}
    , max_age_{config["max-signature-age"].As<std::chrono::seconds>(std::chrono::minutes{5})} {
    if (const auto key = config["secdist-key"].As<std::string>(""); !key.empty()) {
        const auto& secrets = context.FindComponent<userver::components::Secdist>().Get().Get<Secrets>();
        if (const auto* credentials = secrets.Find(key)) {
            management_key_ = credentials->management_key;
            // secdist wins over the static config for these two: they travel
            // with the credential, and moving an account should be one change.
            if (credentials->base_url) base_url_ = Trim(*credentials->base_url);
            if (credentials->org_ref) org_ref_ = *credentials->org_ref;
        } else {
            LOG_ERROR() << "pokeme: secdist has no pokeme." << key
                        << " — webhook signatures cannot be verified and every callback will be refused.";
        }
    }

    if (!Configured() || base_url_.empty() || org_ref_.empty()) {
        // Inert, never fatal. The keys matter only when a webhook arrives, and
        // poke-me retries a failed delivery for 24 hours — so an outage here
        // costs latency rather than events, while refusing to boot would take
        // the whole service down over it.
        LOG_ERROR() << "pokeme: webhook key cache is inert (no management key, base-url or org-ref). "
                       "Callbacks will be refused as unsigned until it is configured.";
    }

    StartPeriodicUpdates();
}

WebhookKeys::~WebhookKeys() { StopPeriodicUpdates(); }

auto WebhookKeys::Find(std::string_view key_id) const -> std::string {
    if (key_id.empty()) return {};
    const auto snapshot = Get();
    if (!snapshot) return {};
    const auto found = snapshot->find(std::string{key_id});
    return found == snapshot->end() ? std::string{} : found->second;
}

auto WebhookKeys::VerifyRequest(const userver::server::http::HttpRequest& request, std::string_view body) const
    -> Refusal {
    const auto& key_id = request.GetHeader(std::string{kKeyIdHeader});
    const auto& timestamp = request.GetHeader(std::string{kTimestampHeader});
    const auto& signature = request.GetHeader(std::string{kSignatureHeader});

    if (key_id.empty()) return Refusal::kMalformed;

    return VerifyWebhook(Find(key_id), timestamp, signature, body, max_age_);
}

auto WebhookKeys::Update(
    userver::cache::UpdateType,
    const std::chrono::system_clock::time_point&,
    const std::chrono::system_clock::time_point&,
    userver::cache::UpdateStatisticsScope& stats_scope
) -> void {
    if (!Configured() || base_url_.empty() || org_ref_.empty()) {
        // A configured-away cache is not a failing one. Finishing with nothing
        // keeps the component healthy and every verification answering
        // "unknown key", which is the honest state.
        stats_scope.FinishNoChanges();
        return;
    }

    userver::tracing::Span span{"pokeme-webhook-keys"};

    auto response = http_.CreateRequest()
                        .get(fmt::format("{}/api/v1/orgs/{}/webhook-keys", base_url_, org_ref_))
                        .headers({{"X-Management-Key", management_key_}})
                        .timeout(timeout_)
                        .perform();
    response->raise_for_status();

    const auto document = userver::formats::json::FromString(response->body());

    auto keys = std::make_unique<KeySet>();
    for (const auto& key : document["keys"]) {
        // Ed25519 only. An algorithm we cannot verify is skipped rather than
        // stored: holding it would let a future signature be refused as a *bad
        // signature* — somebody lying — when it is really a scheme we have not
        // learnt yet.
        const auto algorithm = key["algorithm"].As<std::string>("Ed25519");
        if (algorithm != "Ed25519") {
            LOG_WARNING() << "pokeme: ignoring webhook key with unsupported algorithm '" << algorithm << "'";
            continue;
        }
        auto id = key["key_id"].As<std::string>("");
        auto public_key = key["public_key"].As<std::string>("");
        if (id.empty() || public_key.empty()) continue;
        keys->insert_or_assign(std::move(id), std::move(public_key));
    }

    // Every key that can still verify something, which is why the whole set is
    // replaced rather than merged: poke-me omits expired keys, and merging
    // would keep one alive here after it stopped being valid there.
    const auto size = keys->size();
    stats_scope.IncreaseDocumentsReadCount(size);
    Set(std::move(keys));
    stats_scope.Finish(size);
}

auto WebhookKeys::GetStaticConfigSchema() -> userver::yaml_config::Schema {
    return userver::yaml_config::MergeSchemas<BaseType>(R"(
type: object
description: poke-me webhook signing keys, fetched and rotated
additionalProperties: false
properties:
    base-url:
        type: string
        description: poke-me's origin, e.g. https://push-me.io. Overridden by secdist when that carries one.
    org-ref:
        type: string
        description: the organisation whose keys these are — uuid or slug. Overridden by secdist.
    secdist-key:
        type: string
        description: key under `pokeme` in the secdist document holding the management key
    timeout:
        type: string
        description: timeout for one key fetch
        defaultDescription: 10s
    max-signature-age:
        type: string
        description: >-
            How old a signed callback may be. The timestamp is inside the signed
            material, so this is what actually stops a replay — a signature that
            was once valid stays valid for ever without it.
        defaultDescription: 5m
)");
}

}  // namespace slugkit::pokeme
