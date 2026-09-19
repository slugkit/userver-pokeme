/// What the webhook side reports, read back the way a scrape reads it.

#include <userver/utest/utest.hpp>
#include <userver/utils/statistics/storage.hpp>
#include <userver/utils/statistics/testing.hpp>

#include <slugkit/pokeme/metrics.hpp>

namespace {

using slugkit::pokeme::Refusal;
using slugkit::pokeme::WebhookMetrics;
using userver::utils::statistics::Rate;
using userver::utils::statistics::Snapshot;
using userver::utils::statistics::Storage;

auto Read(const WebhookMetrics& metrics) -> Snapshot {
    Storage storage;
    auto holder = storage.RegisterWriter("pokeme.webhook", [&metrics](auto& writer) { writer = metrics; });
    return Snapshot{storage, "pokeme.webhook"};
}

}  // namespace

UTEST(PokeMeMetrics, CountsEachOutcomeUnderItsOwnLabel) {
    WebhookMetrics metrics;
    metrics.Account(Refusal::kOk);
    metrics.Account(Refusal::kOk);
    metrics.Account(Refusal::kUnknownKey);
    metrics.Account(Refusal::kBadSignature);

    const auto snapshot = Read(metrics);
    EXPECT_EQ(snapshot.SingleMetric("verifications", {{"outcome", "ok"}}).AsRate(), Rate{2});
    // A rotation we have not caught up with and a forgery are different pages;
    // they must never share a series.
    EXPECT_EQ(snapshot.SingleMetric("verifications", {{"outcome", "unknown_key"}}).AsRate(), Rate{1});
    EXPECT_EQ(snapshot.SingleMetric("verifications", {{"outcome", "bad_signature"}}).AsRate(), Rate{1});
}

UTEST(PokeMeMetrics, EveryOutcomeIsPresentBeforeItHappens) {
    // A series born at the first forgery has no history for a rate alert to
    // compare against.
    const WebhookMetrics metrics;
    const auto snapshot = Read(metrics);
    for (const auto* outcome : {"ok", "malformed", "stale", "unknown_key", "bad_signature"}) {
        EXPECT_EQ(snapshot.SingleMetric("verifications", {{"outcome", outcome}}).AsRate(), Rate{0}) << outcome;
    }
}

UTEST(PokeMeMetrics, ReportsTheKeysHeldAndWhetherConfigured) {
    WebhookMetrics metrics;
    const auto before = Read(metrics);
    EXPECT_EQ(before.SingleMetric("keys").AsInt(), 0);
    EXPECT_EQ(before.SingleMetric("configured").AsInt(), 0);

    metrics.SetConfigured(true);
    metrics.SetKeys(2);
    const auto after = Read(metrics);
    EXPECT_EQ(after.SingleMetric("keys").AsInt(), 2);
    EXPECT_EQ(after.SingleMetric("configured").AsInt(), 1);
}

UTEST(PokeMeMetrics, ResetClearsTheCountersNotTheState) {
    WebhookMetrics metrics;
    metrics.SetConfigured(true);
    metrics.SetKeys(1);
    metrics.Account(Refusal::kStale);

    ResetMetric(metrics);

    const auto snapshot = Read(metrics);
    EXPECT_EQ(snapshot.SingleMetric("verifications", {{"outcome", "stale"}}).AsRate(), Rate{0});
    EXPECT_EQ(snapshot.SingleMetric("keys").AsInt(), 1);
    EXPECT_EQ(snapshot.SingleMetric("configured").AsInt(), 1);
}
