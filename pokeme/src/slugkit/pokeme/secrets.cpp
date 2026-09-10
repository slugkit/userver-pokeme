#include <slugkit/pokeme/secrets.hpp>

namespace slugkit::pokeme {

Secrets::Secrets(const userver::formats::json::Value& doc) {
    const auto& root = doc["pokeme"];
    if (!root.IsObject()) return;

    for (auto it = root.begin(); it != root.end(); ++it) {
        const auto& block = *it;
        if (!block.IsObject()) continue;

        Credentials credentials;
        credentials.management_key = block["management_key"].As<std::string>("");
        if (block.HasMember("base_url")) {
            credentials.base_url = block["base_url"].As<std::string>("");
        }
        if (block.HasMember("org_ref")) {
            credentials.org_ref = block["org_ref"].As<std::string>("");
        }
        blocks_.emplace(it.GetName(), std::move(credentials));
    }
}

auto Secrets::Find(std::string_view key) const -> const Credentials* {
    const auto found = blocks_.find(std::string{key});
    return found == blocks_.end() ? nullptr : &found->second;
}

}  // namespace slugkit::pokeme
