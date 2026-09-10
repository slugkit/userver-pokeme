#pragma once

/// @file
/// poke-me credentials out of the static config and into secdist.
///
/// A management key is a credential, and a credential in a static config is a
/// credential in a file: userver renders config through templates onto disk, so
/// a deployment that fills it from an environment variable still writes it out.
/// secdist exists for exactly this — read once at startup, from a document that
/// never becomes part of the rendered config.
///
/// The expected document, keyed by the component's `secdist-key`:
///
/// ```json
/// {
///   "pokeme": {
///     "default": {
///       "management_key": "mk_…",
///       "base_url": "https://push-me.io",
///       "org_ref":  "acme"
///     }
///   }
/// }
/// ```
///
/// Only `management_key` is a secret; the other two are here because they
/// travel with it. An organisation ref and a base URL change when the account
/// does, and moving the whole set together is what makes swapping accounts a
/// secret change rather than a redeploy. Either may be omitted and taken from
/// the static config instead.
///
/// Keyed by name so a process talking to two organisations configures two
/// components against two blocks rather than needing a second mechanism.

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include <userver/formats/json/value.hpp>

namespace slugkit::pokeme {

/// One block of the secdist document.
struct Credentials {
    /// Reads the org's webhook signing keys. Needs the `webhooks:read` scope
    /// and nothing more — a key that could also publish would be a key a
    /// webhook receiver had no business holding.
    std::string management_key;
    std::optional<std::string> base_url;
    std::optional<std::string> org_ref;
};

class Secrets final {
public:
    Secrets() = default;
    explicit Secrets(const userver::formats::json::Value& doc);

    /// @returns the block under @p key, or nullptr when the document has none.
    ///
    /// Absence is not an error here. Every component in a process shares one
    /// secdist document, and the component decides what a missing block means,
    /// because only it knows whether it was told to expect one.
    [[nodiscard]] auto Find(std::string_view key) const -> const Credentials*;

private:
    std::unordered_map<std::string, Credentials> blocks_;
};

}  // namespace slugkit::pokeme
