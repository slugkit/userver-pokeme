#include <slugkit/pokeme/metrics.hpp>

#include <userver/utils/statistics/labels.hpp>

namespace slugkit::pokeme {

namespace {

constexpr std::array kOrder{
    Refusal::kOk, Refusal::kMalformed, Refusal::kStale, Refusal::kUnknownKey, Refusal::kBadSignature,
};

auto Index(Refusal refusal) noexcept -> std::size_t {
    switch (refusal) {
        case Refusal::kOk:
            return 0;
        case Refusal::kMalformed:
            return 1;
        case Refusal::kStale:
            return 2;
        case Refusal::kUnknownKey:
            return 3;
        case Refusal::kBadSignature:
            return 4;
    }
    // An outcome added to the enum and not here is still a refusal; counting
    // it as malformed keeps it visible rather than dropping it.
    return 1;
}

}  // namespace

auto MetricLabel(Refusal refusal) -> std::string_view {
    switch (refusal) {
        case Refusal::kOk:
            return "ok";
        case Refusal::kMalformed:
            return "malformed";
        case Refusal::kStale:
            return "stale";
        case Refusal::kUnknownKey:
            return "unknown_key";
        case Refusal::kBadSignature:
            return "bad_signature";
    }
    return "malformed";
}

void WebhookMetrics::Account(Refusal refusal) noexcept { ++verifications_[Index(refusal)]; }

void DumpMetric(userver::utils::statistics::Writer& writer, const WebhookMetrics& metrics) {
    // Every outcome, zeros included: a series that appears only on the first
    // forgery cannot be alerted on by rate, because it has no history to
    // compare against.
    for (const auto refusal : kOrder) {
        writer["verifications"].ValueWithLabels(
            metrics.verifications_[Index(refusal)],
            userver::utils::statistics::LabelView{"outcome", MetricLabel(refusal)}
        );
    }
    writer["keys"] = metrics.keys_.load();
    writer["configured"] = metrics.configured_.load();
}

void ResetMetric(WebhookMetrics& metrics) {
    // The counters only. `keys` and `configured` are the state of the cache,
    // not something that accumulated, and zeroing them would report an empty
    // cache that is not.
    for (auto& counter : metrics.verifications_) ResetMetric(counter);
}

}  // namespace slugkit::pokeme
