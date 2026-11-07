// ESP32 PTP L2 Follower v1
// Copyright Rob Latour, 2026
// License: MIT
// Website: https://github.com/roblatour/ESP32PTPL2Follower
//

#pragma once

#include <cstddef>
#include <cstdint>

namespace follower
{
    inline constexpr std::size_t ptp_auth_tlv_size = 26;
    inline constexpr std::size_t ptp_auth_icv_size = 16;

    enum class AuthResult : uint8_t
    {
        unauthenticated,
        valid,
        authentication_required,
        disabled,
        malformed,
        unavailable,
        unknown_key,
        invalid_mac,
    };

    // Only these two results permit protocol processing. Authentication does not
    // validate timing semantics, identity, replay, or packet delay; callers do so
    // before mutating selection, health, or clocks. Mixed PTP accepts unsigned peers.
    constexpr bool auth_accepted(AuthResult result)
    {
        return result == AuthResult::unauthenticated || result == AuthResult::valid;
    }

    // Call once during startup, before publishing worker tasks, never in the RX
    // callback/clock lock. Idempotent; faults are sticky until reboot. Returns false
    // for required missing keys, malformed configured keys, crypto failures or an
    // invalid policy. Optional empty/absent rings warn once and permit unsigned-only
    // operation. Disabled valid policies are also ready.
    // No keys are logged/exported/persisted. After initialization, calls are safe
    // concurrently on distinct caller-owned buffers; there is no runtime rekey API.
    bool auth_initialize();
    // Policy readiness permits protocol processing, not necessarily cryptography.
    bool ptp_auth_ready();
    // True only after a complete valid key ring has been imported successfully.
    bool ptp_auth_available();

    // PTP buffers start at the PTP header (not Ethernet), and length MUST equal
    // messageLength: caller strips validated Ethernet padding. Only the supported
    // Sync/Delay_Req/Follow_Up/Delay_Resp/Announce bodies and a single final TLV are
    // accepted. Disabled/keyless modes reject signed traffic, never ignore its TLV.
    // Fatal initialization faults reject even unsigned traffic. Verify all ring keys
    // independently of the active transmit ID.
    AuthResult ptp_auth_verify(const uint8_t *message, std::size_t length);
    // Match the selected master's verified security association. Unsigned v2.0 is
    // allowed only when not required; signed v2.1 requires enabled/ready crypto.
    // In mixed mode this permits an unsigned server to parse our Delay_Req.
    // On failure length is unchanged; discard buffer (contents may change).
    bool ptp_auth_append(uint8_t *message, std::size_t capacity, std::size_t &length, bool authenticate);

    // Static non-secret diagnostic text. No logging occurs in verification paths;
    // caller should rate-limit diagnostics under malformed/unauthenticated traffic.
    const char *auth_result_name(AuthResult result);
}
