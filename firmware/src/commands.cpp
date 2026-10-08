#include "commands.h"

#include <ArduinoJson.h>
#include <stdio.h>
#include <string.h>

#include "hmac_auth.h"
#include "idps_config.h"
#include "util.h"

namespace idps {

const char* verdictName(Verdict v) {
  switch (v) {
    case Verdict::kAccepted: return "accepted";
    case Verdict::kTooLong: return "too_long";
    case Verdict::kMalformed: return "malformed";
    case Verdict::kUnknownCommand: return "unknown_command";
    case Verdict::kNoKey: return "no_key";
    case Verdict::kBadMac: return "bad_mac";
    case Verdict::kReplay: return "replay";
    case Verdict::kNoTime: return "no_time_sync";
    case Verdict::kStale: return "stale";
  }
  return "?";
}

static Command parseCommandName(const char* name) {
  if (strcmp(name, "PING") == 0) return Command::kPing;
  if (strcmp(name, "QUARANTINE") == 0) return Command::kQuarantine;
  if (strcmp(name, "RELEASE") == 0) return Command::kRelease;
  return Command::kNone;
}

Verdict verifyCommand(const uint8_t* payload, size_t len, const CommandContext& ctx, Command* cmd, uint64_t* ts) {
  if (len > IDPS_MAX_CMD_PAYLOAD) return Verdict::kTooLong;

  JsonDocument doc;
  if (deserializeJson(doc, payload, len, DeserializationOption::NestingLimit(1))) return Verdict::kMalformed;
  JsonVariantConst tsV = doc["ts"];
  JsonVariantConst cmdV = doc["cmd"];
  JsonVariantConst macV = doc["mac"];
  if (!tsV.is<uint64_t>() || !cmdV.is<const char*>() || !macV.is<const char*>()) return Verdict::kMalformed;

  const uint64_t cmdTs = tsV.as<uint64_t>();
  const char* cmdName = cmdV.as<const char*>();
  const char* macHex = macV.as<const char*>();
  const Command parsed = parseCommandName(cmdName);
  if (parsed == Command::kNone) return Verdict::kUnknownCommand;
  if (!ctx.keyUsable) return Verdict::kNoKey;

  char tsStr[21];
  formatU64(cmdTs, tsStr);
  char canonical[96];
  const int n = snprintf(canonical, sizeof(canonical), "v%d|cmd|%s|%s|%s",
                         IDPS_PROTOCOL_VERSION, ctx.deviceId, tsStr, cmdName);
  if (n <= 0 || static_cast<size_t>(n) >= sizeof(canonical)) return Verdict::kMalformed;

  uint8_t mac[kMacLen];
  if (!hmacSha256(ctx.key, kKeyLen, reinterpret_cast<const uint8_t*>(canonical), static_cast<size_t>(n), mac)) {
    return Verdict::kNoKey;
  }
  if (!macEqualsHex(mac, macHex, strlen(macHex))) return Verdict::kBadMac;

  // Freshness checks only after authentication, so forged traffic is
  // always reported as bad_mac.
  if (cmdTs <= ctx.lastAcceptedTs) return Verdict::kReplay;
  if (ctx.timeSynced) {
    const uint64_t skewMs = static_cast<uint64_t>(IDPS_CMD_MAX_SKEW_S) * 1000ULL;
    const uint64_t diff = cmdTs > ctx.nowUnixMs ? cmdTs - ctx.nowUnixMs : ctx.nowUnixMs - cmdTs;
    if (diff > skewMs) return Verdict::kStale;
  } else if (IDPS_REQUIRE_TIME_SYNC) {
    return Verdict::kNoTime;
  }

  *cmd = parsed;
  *ts = cmdTs;
  return Verdict::kAccepted;
}

bool RateLimiter::admit(uint32_t nowMs) {
  if (elapsed(nowMs, windowStartMs_, 1000)) {
    windowStartMs_ = nowMs;
    count_ = 0;
  }
  if (count_ >= perSecond_) return false;
  ++count_;
  return true;
}

}  // namespace idps
