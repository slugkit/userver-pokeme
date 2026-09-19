/// Reading poke-me's signing-key list.
///
/// The shape these fixtures carry is copied from poke-me's own handler
/// (`list_webhook_keys.cpp`), not written from memory — the first release of
/// this library read a `keys` field poke-me has never sent, and its integration
/// tests passed because the mock had been written to agree with the code.

#include <userver/formats/json/serialize.hpp>
#include <userver/utest/utest.hpp>

#include <slugkit/pokeme/keys.hpp>

namespace {

using slugkit::pokeme::ParseKeySet;

auto Json(const char* text) { return userver::formats::json::FromString(text); }

}  // namespace

TEST(PokeMeKeys, ReadsTheListPokeMeActuallySends) {
    const auto keys = ParseKeySet(Json(R"({"items": [
        {"key_id": "wk_new", "public_key": "PUBNEW", "algorithm": "Ed25519",
         "not_before": "2026-09-13T00:00:00+00:00", "expires_at": "2026-12-13T00:00:00+00:00", "retired": false},
        {"key_id": "wk_old", "public_key": "PUBOLD", "algorithm": "Ed25519",
         "not_before": "2026-06-13T00:00:00+00:00", "expires_at": "2026-09-20T00:00:00+00:00", "retired": true}
    ]})"));

    ASSERT_EQ(keys.size(), 2u);
    EXPECT_EQ(keys.at("wk_new"), "PUBNEW");
    // Retired means it stopped signing, not verifying: a batch signed just
    // before the rotation must still be accepted.
    EXPECT_EQ(keys.at("wk_old"), "PUBOLD");
}

TEST(PokeMeKeys, AnAnswerWithoutItemsIsNotAnEmptySet) {
    // The regression. An answer we cannot read must fail the update — which
    // keeps the previous keys — rather than replace them with nothing and
    // refuse every callback.
    EXPECT_ANY_THROW((void)ParseKeySet(Json(R"({"keys": [{"key_id": "wk_1", "public_key": "PUB"}]})")));
    EXPECT_ANY_THROW((void)ParseKeySet(Json(R"({})")));
}

TEST(PokeMeKeys, AnEmptyListIsAnEmptySet) {
    // Distinct from the above: poke-me holding no unexpired key is a real
    // state, and answering it is not a failure.
    EXPECT_TRUE(ParseKeySet(Json(R"({"items": []})")).empty());
}

TEST(PokeMeKeys, AnAlgorithmWeCannotVerifyIsSkipped) {
    const auto keys = ParseKeySet(Json(R"({"items": [
        {"key_id": "wk_ec", "public_key": "PUBEC", "algorithm": "ES256"},
        {"key_id": "wk_ed", "public_key": "PUBED", "algorithm": "Ed25519"}
    ]})"));
    EXPECT_EQ(keys.size(), 1u);
    EXPECT_TRUE(keys.contains("wk_ed"));
}

TEST(PokeMeKeys, AnEntryWithoutAnIdOrAKeyIsSkipped) {
    const auto keys = ParseKeySet(Json(R"({"items": [
        {"public_key": "PUB", "algorithm": "Ed25519"},
        {"key_id": "wk_nokey", "algorithm": "Ed25519"},
        {"key_id": "wk_ok", "public_key": "PUBOK", "algorithm": "Ed25519"}
    ]})"));
    EXPECT_EQ(keys.size(), 1u);
    EXPECT_EQ(keys.at("wk_ok"), "PUBOK");
}
