#include "auth.h"
#include "ESP32PTPL2FollowerSettings.h"
#include "auth_vectors.h"
#include "follower_core.h"
#include "esp_log.h"
#include "psa/crypto.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <string>

namespace
{
using namespace follower;
using Packet = std::array<uint8_t, 128>;
unsigned checks = 0;

void check(bool success, const char *expression, int line)
{
    ++checks;
    if (!success)
    {
        std::fprintf(stderr, "FAIL line %d: %s\n", line, expression);
        std::exit(1);
    }
}

#define CHECK(expression) check((expression), #expression, __LINE__)

void write_id(uint8_t *output, uint32_t id)
{
    for (unsigned i = 0; i < 4; ++i)
        output[i] = static_cast<uint8_t>(id >> (24 - 8 * i));
}

void test_results()
{
    const char *names[] = {"unauthenticated", "valid", "authentication_required", "disabled",
                           "malformed", "unavailable", "unknown_key", "invalid_mac"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
    {
        const auto result = static_cast<AuthResult>(i);
        CHECK(std::strcmp(auth_result_name(result), names[i]) == 0);
        CHECK(auth_accepted(result) == (i < 2));
    }
    CHECK(std::strcmp(auth_result_name(static_cast<AuthResult>(255)), "unknown") == 0);
    CHECK(!auth_accepted(static_cast<AuthResult>(255)));
}

void test_ptp(bool ready, bool available)
{
    CHECK(ptp_auth_verify(nullptr, 44) == AuthResult::malformed);
    auto packet = vectors::ptp_unsigned;
    const auto unsigned_result = !ready ? AuthResult::unavailable :
        settings::ptp_auth_required ? AuthResult::authentication_required : AuthResult::unauthenticated;
    CHECK(ptp_auth_verify(packet.data(), 44) == unsigned_result);
    auto length = std::size_t{44};
    CHECK(ptp_auth_append(packet.data(), packet.size(), length, settings::ptp_auth_enabled) ==
          (ready && (!settings::ptp_auth_enabled || available)));
    CHECK(length == (available ? 70u : 44u));
    if (!ready)
    {
        CHECK(ptp_auth_verify(vectors::ptp_signed_active.data(), 70) == AuthResult::unavailable);
        return;
    }
    if (!settings::ptp_auth_enabled)
    {
        CHECK(packet == vectors::ptp_unsigned);
        CHECK(ptp_auth_verify(vectors::ptp_signed_active.data(), 70) == AuthResult::disabled);
    }
    else if (!available)
    {
        CHECK(packet == vectors::ptp_unsigned);
        CHECK(ptp_auth_verify(vectors::ptp_signed_active.data(), 70) == AuthResult::unavailable);
        CHECK(ptp_auth_verify(vectors::ptp_signed_other.data(), 70) == AuthResult::unavailable);
        auto corrupt = vectors::ptp_signed_active;
        corrupt[69] ^= 1;
        CHECK(!auth_accepted(ptp_auth_verify(corrupt.data(), 70)));
    }
    else
    {
        CHECK(packet == vectors::ptp_signed_active);
        CHECK(ptp_auth_verify(vectors::ptp_signed_active.data(), 70) == AuthResult::valid);
        CHECK(ptp_auth_verify(vectors::ptp_signed_other.data(), 70) == AuthResult::valid);
        for (std::size_t i = 0; i < 70; ++i)
        {
            for (unsigned bit = 0; bit < 8; ++bit)
            {
                auto corrupt = vectors::ptp_signed_active;
                corrupt[i] ^= static_cast<uint8_t>(1u << bit);
                CHECK(!auth_accepted(ptp_auth_verify(corrupt.data(), 70)));
            }
        }
        auto corrupt = vectors::ptp_signed_active;
        write_id(corrupt.data() + 50, 0);
        CHECK(ptp_auth_verify(corrupt.data(), 70) == AuthResult::unknown_key);
        corrupt = vectors::ptp_signed_active;
        corrupt[69] ^= 1;
        CHECK(ptp_auth_verify(corrupt.data(), 70) == AuthResult::invalid_mac);
        for (const auto offset : {44u, 45u, 46u, 47u, 48u, 49u})
        {
            corrupt = vectors::ptp_signed_active;
            corrupt[offset] ^= 1;
            CHECK(ptp_auth_verify(corrupt.data(), 70) == AuthResult::malformed);
        }
        for (const auto *failure : {"mac", "hash_update", "hash_finish"})
        {
            host_psa_set_failure(failure);
            CHECK(ptp_auth_verify(vectors::ptp_signed_active.data(), 70) == AuthResult::unavailable);
            auto output = vectors::ptp_unsigned;
            length = 44;
            CHECK(!ptp_auth_append(output.data(), output.size(), length, true));
            CHECK(length == 44);
            host_psa_set_failure(nullptr);
        }
        packet = vectors::ptp_unsigned;
        length = 44;
        CHECK(!ptp_auth_append(packet.data(), 69, length, true));
        CHECK(length == 44);
        CHECK(packet == vectors::ptp_unsigned);
    }
    for (std::size_t size = 0; size <= 128; ++size)
    {
        if (size == 70)
            continue;
        CHECK(ptp_auth_verify(vectors::ptp_signed_active.data(), size) == AuthResult::malformed);
        if (size != 44)
        {
            auto resized = vectors::ptp_signed_active;
            resized[2] = 0;
            resized[3] = static_cast<uint8_t>(size);
            CHECK(ptp_auth_verify(resized.data(), size) == AuthResult::malformed);
        }
    }
    for (const auto type : {0u, 1u, 8u, 9u, 11u})
    {
        const std::size_t body = type == 9 ? 54 : type == 11 ? 64 : 44;
        Packet output{};
        output[0] = static_cast<uint8_t>(type);
        output[1] = available ? 0x12 : 0x02;
        output[3] = static_cast<uint8_t>(body);
        length = body;
        CHECK(ptp_auth_append(output.data(), output.size(), length, available));
        CHECK(length == body + (available ? 26u : 0u));
        CHECK(ptp_auth_verify(output.data(), length) ==
              (available ? AuthResult::valid : AuthResult::unauthenticated));
    }
    for (unsigned type = 0; type < 16; ++type)
    {
        if (type == 0 || type == 1 || type == 8 || type == 9 || type == 11)
            continue;
        packet = vectors::ptp_unsigned;
        packet[0] = static_cast<uint8_t>(type);
        CHECK(ptp_auth_verify(packet.data(), 44) == AuthResult::malformed);
        length = 44;
        CHECK(!ptp_auth_append(packet.data(), packet.size(), length, settings::ptp_auth_enabled));
        CHECK(length == 44);
    }
    packet = vectors::ptp_unsigned;
    packet[1] = settings::ptp_auth_enabled ? 0x02 : 0x12;
    length = 44;
    CHECK(!ptp_auth_append(packet.data(), packet.size(), length, settings::ptp_auth_enabled));
    CHECK(length == 44);
    packet = vectors::ptp_unsigned;
    length = 44;
    CHECK(!ptp_auth_append(packet.data(), 43, length, settings::ptp_auth_enabled));
    CHECK(length == 44);
    CHECK(!ptp_auth_append(nullptr, 128, length, settings::ptp_auth_enabled));
    CHECK(length == 44);
    packet[0] |= 0x10;
    CHECK(ptp_auth_verify(packet.data(), 44) == AuthResult::malformed);
    CHECK(!ptp_auth_append(packet.data(), packet.size(), length, settings::ptp_auth_enabled));
}

void test_discovery(bool ready, bool available, bool signed_server)
{
    const auto &frames = signed_server ? vectors::signed_server : vectors::unsigned_server;
    const bool accepted = ready && (signed_server ? available : !settings::ptp_auth_required);
    RestrictedFollowerSelection selection;
    ExchangeMatcher matcher;
    const Identity local{{0x82, 0xf1, 0xb2, 0xff, 0xfe, 0xd2, 0xca, 0x9a, 0, 1}};
    Pair pair;
    for (std::size_t i = 0; i < frames.size(); ++i)
    {
        follower::Packet parsed;
        CHECK(parse_ptp(frames[i].data(), frames[i].size(), {}, parsed) == Error::ok);
        const auto result = ptp_auth_verify(frames[i].data() + 14, parsed.message_length);
        CHECK(auth_accepted(result) == accepted);
        if (!auth_accepted(result)) continue;
        const Security security{true, result == AuthResult::valid, parsed.spp, parsed.key_id};
        if (i < 2)
        {
            CHECK(selection.announce(parsed, security, static_cast<int64_t>(i + 1)) == Error::ok);
            CHECK((selection.selected() != nullptr) == (i == 1));
            if (i == 1) matcher.select(parsed.source, local, 0, 7);
        }
        else if (i == 2)
            CHECK(matcher.sync(parsed, security, {100, 3000}, true, 7, 3) == Error::ok);
        else if (i == 3)
        {
            CHECK(matcher.follow_up(parsed, security, 7, 4) == Error::ok);
            CHECK(matcher.take_pair(4, pair) == Error::ok);
            CHECK(matcher.begin_delay(9, {100, 100003000}, true, pair, 7, 5) == Error::ok);
        }
        else
        {
            Exchange exchange;
            CHECK(matcher.delay_response(parsed, security, 7, 6, exchange) == Error::ok);
            Measurement measured;
            CHECK(calculate_e2e(exchange, 6, measured) == Error::ok);
            CHECK(measured.offset_ns() == 1000 && measured.delay_ns() == 1000);
        }
    }
    CHECK((selection.selected() != nullptr) == accepted);
    if (accepted)
    {
        std::array<uint8_t, 128> request{};
        request[0] = 1;
        request[1] = signed_server ? 0x12 : 2;
        request[3] = 44;
        request[32] = signed_server ? 0 : 1;
        std::size_t length = 44;
        CHECK(ptp_auth_append(request.data(), request.size(), length, selection.selected()->security.authenticated));
        CHECK(length == (signed_server ? 70u : 44u));
        CHECK(ptp_auth_verify(request.data(), length) ==
              (signed_server ? AuthResult::valid : AuthResult::unauthenticated));
    }
    if (ready)
    {
        auto unsigned_request = vectors::ptp_unsigned;
        unsigned_request[1] = 2;
        std::size_t length = 44;
        CHECK(ptp_auth_append(unsigned_request.data(), unsigned_request.size(), length, false) ==
              !settings::ptp_auth_required);
        auto signed_request = vectors::ptp_unsigned;
        signed_request[1] = 0x12;
        length = 44;
        CHECK(ptp_auth_append(signed_request.data(), signed_request.size(), length, true) ==
              available);
        CHECK(length == (available ? 70u : 44u));
    }
    if (signed_server)
    {
        auto corrupt = frames[0];
        corrupt[14 + 89] ^= 1;
        follower::Packet parsed;
        CHECK(parse_ptp(corrupt.data(), corrupt.size(), {}, parsed) == Error::ok);
        CHECK(!auth_accepted(ptp_auth_verify(corrupt.data() + 14, parsed.message_length)));
    }
}
}

int main(int argc, char **argv)
{
    CHECK(follower::settings::ptp_auth_enabled == bool(EXPECT_PTP_ENABLED));
    CHECK(follower::settings::ptp_auth_required == bool(EXPECT_PTP_REQUIRED));
    const bool ptp_ready = argc > 2 ? std::atoi(argv[2]) != 0 : EXPECT_PTP_READY;
    const std::size_t key_count = argc > 3 ? std::strtoul(argv[3], nullptr, 10) : EXPECT_PTP_KEYS;
    const bool available = key_count != 0;
    const bool keyless_optional = settings::ptp_auth_enabled && !settings::ptp_auth_required &&
                                  ptp_ready && !available;
    CHECK(!follower::ptp_auth_ready());
    CHECK(!follower::ptp_auth_available());
    CHECK(follower::ptp_auth_verify(vectors::ptp_unsigned.data(), 44) == follower::AuthResult::unavailable);
    host_psa_set_failure(argc > 1 ? argv[1] : nullptr);
    CHECK(follower::auth_initialize() == ptp_ready);
    CHECK(follower::ptp_auth_ready() == ptp_ready);
    CHECK(follower::ptp_auth_available() == available);
    CHECK(host_psa_key_count() == key_count);
    host_psa_set_failure(nullptr);
    CHECK(follower::auth_initialize() == ptp_ready);
    CHECK(follower::ptp_auth_ready() == ptp_ready);
    CHECK(follower::ptp_auth_available() == available);
    CHECK(host_psa_key_count() == key_count);
    const auto startup_logs = host_log_count;
    CHECK(startup_logs == static_cast<unsigned>(!ptp_ready || keyless_optional));
    CHECK(host_warning_count == static_cast<unsigned>(keyless_optional));
    if (keyless_optional)
    {
        CHECK(host_last_error[0] == '\0');
        CHECK(std::strstr(host_last_warning, "No PTP keys are provisioned") != nullptr);
        CHECK(std::strstr(host_last_warning, "unsigned-only operation") != nullptr);
        CHECK(std::strstr(host_last_warning, "signed packets rejected") != nullptr);
        CHECK(std::strstr(host_last_warning, "main\\ESP32PTPL2FollowerSettingsSecrets.h") != nullptr);
    }
    if (!ptp_ready)
    {
        CHECK(host_last_error[0] != '\0');
        if constexpr (!settings::ptp_auth_enabled && settings::ptp_auth_required)
            CHECK(std::strstr(host_last_error, "AUTH_REQUIRED=1 requires AUTH_ENABLED=1") != nullptr);
        else if constexpr (std::size(settings::ptp_symmetric_keys) == 0)
        {
            CHECK(std::strstr(host_last_error, "PTP key ring is empty") != nullptr);
            CHECK(std::strstr(host_last_error, "main\\ESP32PTPL2FollowerSettingsSecrets.h") != nullptr);
            CHECK(std::strstr(host_last_error, "active key ID=") != nullptr);
        }
        else if (argc > 1)
        {
            CHECK(std::strstr(host_last_error, "PSA") != nullptr);
            CHECK(std::strstr(host_last_error, std::strcmp(argv[1], "init") == 0
                ? "crypto initialization failed" : "key import failed") != nullptr);
            CHECK(std::strstr(host_last_error, "status=") != nullptr);
        }
        else
            CHECK(std::strstr(host_last_error, "PTP authentication configuration fault:") != nullptr);
    }
    for (const auto &key : settings::ptp_symmetric_keys)
    {
        const std::string material(key.key_value, 32);
        if (material.find('\0') == std::string::npos)
        {
            CHECK(std::strstr(host_last_error, material.c_str()) == nullptr);
            CHECK(std::strstr(host_last_warning, material.c_str()) == nullptr);
        }
    }
    test_results();
    test_ptp(ptp_ready, available);
    test_discovery(ptp_ready, available, false);
    test_discovery(ptp_ready, available, true);
    CHECK(host_log_count == startup_logs);
    CHECK(follower::ptp_auth_available() == available);
    CHECK(host_psa_key_count() == key_count);
    std::printf("PASS %u checks (PTP ready %d, auth available %d, keys %zu)\n",
                checks, ptp_ready, available, key_count);
    return 0;
}
