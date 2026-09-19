#pragma once

/// @file
/// What the webhook side reports about itself.
///
/// One question matters more than the rest, and it is the one @ref Refusal was
/// split to answer: *is somebody forging requests, or have we fallen behind a
/// rotation?* A log line per refusal answers it for one request; a counter per
/// outcome answers it for the last hour, which is what an alert needs. So the
/// verifications are counted by outcome — never collapsed into "refused" —
/// with the same five names @ref Refusal draws.
///
/// ```
/// <prefix>.verifications  {outcome: ok|malformed|stale|unknown_key|bad_signature}  rate
/// <prefix>.keys                                                                      gauge
/// <prefix>.configured                                                                gauge, 0|1
/// ```
///
/// `keys` at zero while `configured` is one is the state worth an alert: the
/// cache has a credential and still holds nothing, so every callback is being
/// refused as `unknown_key`. How the fetches themselves are going is already
/// reported by userver's own `cache` metrics under the component's name.

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <userver/utils/statistics/rate_counter.hpp>
#include <userver/utils/statistics/writer.hpp>

#include <slugkit/pokeme/webhook.hpp>

namespace slugkit::pokeme {

/// The label an outcome is reported under. Not @ref ToString, which is prose
/// for a log line — `unknown key` — while a label value wants to be a token.
[[nodiscard]] auto MetricLabel(Refusal refusal) -> std::string_view;

class WebhookMetrics final {
public:
    /// One verification, whatever it concluded.
    void Account(Refusal refusal) noexcept;

    /// How many keys the cache holds now.
    void SetKeys(std::size_t count) noexcept { keys_.store(static_cast<std::int64_t>(count)); }
    void SetConfigured(bool configured) noexcept { configured_.store(configured ? 1 : 0); }

    friend void DumpMetric(userver::utils::statistics::Writer& writer, const WebhookMetrics& metrics);
    friend void ResetMetric(WebhookMetrics& metrics);

private:
    static constexpr std::size_t kOutcomes = 5;

    std::array<userver::utils::statistics::RateCounter, kOutcomes> verifications_{};
    std::atomic<std::int64_t> keys_{0};
    std::atomic<std::int64_t> configured_{0};
};

}  // namespace slugkit::pokeme
