// Host harness: runs the firmware's real command-verification and telemetry
// code on a PC so tests/test_firmware_host.py can drive it with payloads made
// by the Python backend.
//
//   host_harness kat
//   host_harness command <device> <keyhex> <last_ts> <time_synced 0|1> <now_ms>   (payload on stdin)
//   host_harness telemetry <device> <keyhex> <boot> <seq> <up> <rx> <af> <heap> <rssi> <wr> <mr> <q> <lastcmd>
//   host_harness ratelimit
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commands.h"
#include "hmac_auth.h"
#include "telemetry.h"
#include "util.h"

static uint64_t u64(const char* s) { return strtoull(s, nullptr, 10); }

int main(int argc, char** argv) {
  if (argc < 2) return 2;
  const char* mode = argv[1];

  if (strcmp(mode, "kat") == 0) {
    puts(idps::selfTest() ? "PASS" : "FAIL");
    return 0;
  }

  if (strcmp(mode, "ratelimit") == 0) {
    idps::RateLimiter limiter(5);
    const uint32_t times[] = {1000, 1000, 1000, 1000, 1000, 1000, 1999, 2000, 2000};
    for (uint32_t t : times) putchar(limiter.admit(t) ? '1' : '0');
    putchar('\n');
    return 0;
  }

  if (argc < 4) return 2;
  uint8_t key[idps::kKeyLen];
  if (!idps::fromHex(argv[3], key, sizeof(key))) {
    puts("BAD_KEY");
    return 1;
  }

  if (strcmp(mode, "command") == 0 && argc == 7) {
    static uint8_t payload[4096];
    const size_t len = fread(payload, 1, sizeof(payload), stdin);
    idps::CommandContext ctx{argv[2], key, true, u64(argv[4]), argv[5][0] == '1', u64(argv[6])};
    idps::Command cmd = idps::Command::kNone;
    uint64_t ts = 0;
    const idps::Verdict v = idps::verifyCommand(payload, len, ctx, &cmd, &ts);
    char tsStr[21];
    idps::formatU64(ts, tsStr);
    printf("%s %d %s\n", idps::verdictName(v), static_cast<int>(cmd), tsStr);
    return 0;
  }

  if (strcmp(mode, "telemetry") == 0 && argc == 15) {
    idps::TelemetryFields f{};
    f.bootId = static_cast<uint32_t>(u64(argv[4]));
    f.seq = static_cast<uint32_t>(u64(argv[5]));
    f.uptimeS = static_cast<uint32_t>(u64(argv[6]));
    f.rxMsgs = static_cast<uint32_t>(u64(argv[7]));
    f.authFail = static_cast<uint32_t>(u64(argv[8]));
    f.freeHeap = static_cast<uint32_t>(u64(argv[9]));
    f.rssi = static_cast<int32_t>(atol(argv[10]));
    f.wifiReconnects = static_cast<uint32_t>(u64(argv[11]));
    f.mqttReconnects = static_cast<uint32_t>(u64(argv[12]));
    f.quarantined = argv[13][0] == '1';
    f.lastCmdTs = u64(argv[14]);
    char json[512];
    if (idps::buildTelemetryJson(argv[2], key, f, json, sizeof(json)) < 0) {
      puts("ERROR");
      return 1;
    }
    puts(json);
    return 0;
  }
  return 2;
}
