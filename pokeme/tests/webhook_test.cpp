/// Verifying poke-me's webhook signatures.
///
/// The tests worth having here are the negative ones. A verifier that accepts
/// every genuine request and *also* accepts a forged one passes any test that
/// only signs correctly — so each case below breaks exactly one thing and
/// asserts the refusal, and `ASigningKeypairVerifiesItsOwnSignature` is the
/// control that stops the rest passing vacuously because nothing verifies.

#include <memory>
#include <string>

#include <openssl/evp.h>

#include <userver/utest/utest.hpp>
#include <userver/utils/datetime.hpp>
#include <userver/utils/mock_now.hpp>

#include <slugkit/pokeme/webhook.hpp>

namespace {

using slugkit::pokeme::Refusal;

using EvpPkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpMdCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

auto Base64UrlUnpadded(const std::string& bytes) -> std::string {
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    std::size_t i = 0;
    while (i + 2 < bytes.size()) {
        const auto n = (static_cast<unsigned char>(bytes[i]) << 16) |
                       (static_cast<unsigned char>(bytes[i + 1]) << 8) | static_cast<unsigned char>(bytes[i + 2]);
        out += kAlphabet[(n >> 18) & 63];
        out += kAlphabet[(n >> 12) & 63];
        out += kAlphabet[(n >> 6) & 63];
        out += kAlphabet[n & 63];
        i += 3;
    }
    if (i + 1 == bytes.size()) {
        const auto n = static_cast<unsigned char>(bytes[i]) << 16;
        out += kAlphabet[(n >> 18) & 63];
        out += kAlphabet[(n >> 12) & 63];
    } else if (i + 2 == bytes.size()) {
        const auto n =
            (static_cast<unsigned char>(bytes[i]) << 16) | (static_cast<unsigned char>(bytes[i + 1]) << 8);
        out += kAlphabet[(n >> 18) & 63];
        out += kAlphabet[(n >> 12) & 63];
        out += kAlphabet[(n >> 6) & 63];
    }
    return out;
}

/// A keypair, in the shapes the wire uses: the public half base64url, the
/// private half kept as an EVP_PKEY to sign with.
struct Keypair {
    EvpPkey key{nullptr, &EVP_PKEY_free};
    std::string public_key_b64;
};

auto Generate() -> Keypair {
    EVP_PKEY* raw = nullptr;
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx{
        EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), &EVP_PKEY_CTX_free};
    EXPECT_TRUE(ctx);
    EXPECT_GT(EVP_PKEY_keygen_init(ctx.get()), 0);
    EXPECT_GT(EVP_PKEY_keygen(ctx.get(), &raw), 0);

    Keypair pair;
    pair.key = EvpPkey{raw, &EVP_PKEY_free};

    std::size_t size = 0;
    EXPECT_GT(EVP_PKEY_get_raw_public_key(pair.key.get(), nullptr, &size), 0);
    std::string bytes(size, '\0');
    EXPECT_GT(EVP_PKEY_get_raw_public_key(pair.key.get(), reinterpret_cast<unsigned char*>(bytes.data()), &size), 0);
    pair.public_key_b64 = Base64UrlUnpadded(bytes);
    return pair;
}

auto Sign(const Keypair& pair, const std::string& message) -> std::string {
    EvpMdCtx ctx{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
    EXPECT_GT(EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pair.key.get()), 0);

    std::size_t size = 0;
    EXPECT_GT(
        EVP_DigestSign(
            ctx.get(), nullptr, &size, reinterpret_cast<const unsigned char*>(message.data()), message.size()
        ),
        0
    );
    std::string signature(size, '\0');
    EXPECT_GT(
        EVP_DigestSign(
            ctx.get(),
            reinterpret_cast<unsigned char*>(signature.data()),
            &size,
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size()
        ),
        0
    );
    signature.resize(size);
    return Base64UrlUnpadded(signature);
}

constexpr std::int64_t kNow = 1757400000;
constexpr auto kWindow = std::chrono::minutes{5};
const std::string kBody = R"({"delivery_id":"d","organization_id":"o","events":[]})";

auto Freeze() {
    userver::utils::datetime::MockNowSet(std::chrono::system_clock::time_point{std::chrono::seconds{kNow}});
}

}  // namespace

UTEST(PokeMeWebhook, ASigningKeypairVerifiesItsOwnSignature) {
    // The control. Every refusal below would also be produced by a verifier
    // that refused everything, so this is what makes them mean something.
    Freeze();
    const auto pair = Generate();
    const auto signature = Sign(pair, slugkit::pokeme::SigningPayload(kNow, kBody));

    EXPECT_EQ(
        slugkit::pokeme::VerifyWebhook(pair.public_key_b64, std::to_string(kNow), signature, kBody, kWindow),
        Refusal::kOk
    );
}

UTEST(PokeMeWebhook, ABodyChangedAfterSigningIsRefused) {
    Freeze();
    const auto pair = Generate();
    const auto signature = Sign(pair, slugkit::pokeme::SigningPayload(kNow, kBody));

    EXPECT_EQ(
        slugkit::pokeme::VerifyWebhook(
            pair.public_key_b64, std::to_string(kNow), signature, kBody + " ", kWindow
        ),
        Refusal::kBadSignature
    );
}

UTEST(PokeMeWebhook, AnotherKeysSignatureIsRefused) {
    Freeze();
    const auto ours = Generate();
    const auto theirs = Generate();
    const auto signature = Sign(theirs, slugkit::pokeme::SigningPayload(kNow, kBody));

    EXPECT_EQ(
        slugkit::pokeme::VerifyWebhook(ours.public_key_b64, std::to_string(kNow), signature, kBody, kWindow),
        Refusal::kBadSignature
    );
}

UTEST(PokeMeWebhook, TheTimestampIsInsideTheSignedMaterial) {
    // The property that makes replay protection possible at all. A captured
    // request re-presented with a fresh timestamp must not verify — if the
    // timestamp were merely alongside the signature, this would pass.
    Freeze();
    const auto pair = Generate();
    const auto signature = Sign(pair, slugkit::pokeme::SigningPayload(kNow, kBody));

    EXPECT_EQ(
        slugkit::pokeme::VerifyWebhook(pair.public_key_b64, std::to_string(kNow + 1), signature, kBody, kWindow),
        Refusal::kBadSignature
    );
}

UTEST(PokeMeWebhook, AnOldTimestampIsStaleEvenWithAGoodSignature) {
    // And this is why the window exists: the signature above is genuine. A
    // verifier without a window accepts a captured request for ever.
    Freeze();
    const auto pair = Generate();
    const auto old = kNow - 3600;
    const auto signature = Sign(pair, slugkit::pokeme::SigningPayload(old, kBody));

    EXPECT_EQ(
        slugkit::pokeme::VerifyWebhook(pair.public_key_b64, std::to_string(old), signature, kBody, kWindow),
        Refusal::kStale
    );
}

UTEST(PokeMeWebhook, AClockAheadOfOursIsAllowedTheSameSlack) {
    // The sender's clock is not ours to align, and refusing a request from a
    // machine a few seconds fast would be an outage nobody could diagnose.
    Freeze();
    const auto pair = Generate();
    const auto ahead = kNow + 60;
    const auto signature = Sign(pair, slugkit::pokeme::SigningPayload(ahead, kBody));

    EXPECT_EQ(
        slugkit::pokeme::VerifyWebhook(pair.public_key_b64, std::to_string(ahead), signature, kBody, kWindow),
        Refusal::kOk
    );
}

UTEST(PokeMeWebhook, AKeyWeDoNotHoldIsNotABadSignature) {
    // The distinction the key id exists for: a rotation we have not caught up
    // with must not read as somebody forging requests.
    Freeze();
    const auto pair = Generate();
    const auto signature = Sign(pair, slugkit::pokeme::SigningPayload(kNow, kBody));

    EXPECT_EQ(
        slugkit::pokeme::VerifyWebhook("", std::to_string(kNow), signature, kBody, kWindow), Refusal::kUnknownKey
    );
}

UTEST(PokeMeWebhook, MissingOrMalformedHeadersAreMalformed) {
    Freeze();
    const auto pair = Generate();
    const auto signature = Sign(pair, slugkit::pokeme::SigningPayload(kNow, kBody));

    EXPECT_EQ(slugkit::pokeme::VerifyWebhook(pair.public_key_b64, "", signature, kBody, kWindow), Refusal::kMalformed);
    EXPECT_EQ(
        slugkit::pokeme::VerifyWebhook(pair.public_key_b64, std::to_string(kNow), "", kBody, kWindow),
        Refusal::kMalformed
    );
    // Not a number, and not *partly* a number: "1757400000x" must not parse as
    // the timestamp with the tail ignored.
    EXPECT_EQ(
        slugkit::pokeme::VerifyWebhook(pair.public_key_b64, "1757400000x", signature, kBody, kWindow),
        Refusal::kMalformed
    );
}

UTEST(PokeMeWebhook, AMalformedKeyOrSignatureIsRefusedRatherThanThrowing) {
    // This runs on a path an unauthenticated caller controls. An exception here
    // is a way to turn a forged request into a 500 and a page.
    Freeze();
    EXPECT_EQ(
        slugkit::pokeme::VerifyWebhook("not-a-key", std::to_string(kNow), "not-a-signature", kBody, kWindow),
        Refusal::kBadSignature
    );
}

UTEST(PokeMeWebhook, APaddedPublicKeyIsAccepted) {
    // We emit unpadded, but a key that has been through a config file may have
    // acquired `=`. Refusing it would report a key problem that is a transport
    // one.
    Freeze();
    const auto pair = Generate();
    const auto signature = Sign(pair, slugkit::pokeme::SigningPayload(kNow, kBody));

    auto padded = pair.public_key_b64;
    while (padded.size() % 4 != 0) padded.push_back('=');

    EXPECT_EQ(
        slugkit::pokeme::VerifyWebhook(padded, std::to_string(kNow), signature, kBody, kWindow), Refusal::kOk
    );
}
