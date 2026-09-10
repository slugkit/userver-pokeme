#pragma once

/// @file
/// Forward declarations, so a header that only mentions these types need not
/// pull in userver's cache or HTTP client.

namespace slugkit::pokeme {

struct Credentials;
class Secrets;

struct Event;
struct Gap;
struct Batch;
enum class Refusal;

class WebhookKeys;

}  // namespace slugkit::pokeme
