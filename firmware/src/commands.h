// Authenticated command handling (see docs/protocol.md).
//
// Payload: {"ts": <unix ms>, "cmd": "PING|QUARANTINE|RELEASE", "mac": "<64 hex>"}
// MAC:     HMAC-SHA256(key, "v1|cmd|<device_id>|<ts>|<cmd>")
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace idps {

enum class Command : uint8_t { kNone, kPing, kQuarantine, kRelease };

enum class Verdict : uint8_t {
  kAccepted,
  kTooLong,
  kMalformed,
  kUnknownCommand,
  kNoKey,       // node has no valid key or failed its crypto self-test
  kBadMac,
  kReplay,      // ts <= last accepted ts
  kNoTime,      // time not synced and IDPS_REQUIRE_TIME_SYNC=1
  kStale,       // ts too far from local time
};

const char* verdictName(Verdict v);

struct CommandContext {
  const char* deviceId;
  const uint8_t* key;     // kKeyLen bytes
  bool keyUsable;         // valid key AND crypto self-test passed
  uint64_t lastAcceptedTs;
  bool timeSynced;
  uint64_t nowUnixMs;
};

// Validates a command payload. On kAccepted, *cmd and *ts are set.
Verdict verifyCommand(const uint8_t* payload, size_t len, const CommandContext& ctx, Command* cmd, uint64_t* ts);

// Fixed-window limiter: at most `perSecond` messages are parsed per second,
// so a flood cannot monopolise the CPU with JSON parsing and HMACs.
class RateLimiter {
 public:
  explicit RateLimiter(uint16_t perSecond) : perSecond_(perSecond) {}
  bool admit(uint32_t nowMs);

 private:
  uint16_t perSecond_;
  uint16_t count_ = 0;
  uint32_t windowStartMs_ = 0;
};

}  // namespace idps
