// ESP32 PTP L2 Follower v1
// Copyright Rob Latour, 2026
// License: MIT
// Website: https://github.com/roblatour/ESP32PTPL2Follower
//

#include "auth.h"
#include "ESP32PTPL2FollowerSettings.h"

#include <cinttypes>
#include <iterator>
#include <limits>

#include "esp_log.h"
#include "psa/crypto.h"

namespace follower
{
    namespace
    {
        constexpr auto mac_algorithm = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), ptp_auth_icv_size);
        constexpr std::size_t key_size = 32;
        constexpr const char *tag = "auth";

        struct PtpHandle
        {
            uint32_t id{};
            psa_key_id_t handle{};
        };

        PtpHandle ptp_keys[settings::ptp_max_keys]{};
        std::size_t ptp_key_count = 0;
        bool initialized = false;
        bool ptp_ready = false;
        bool ptp_available = false;

        uint16_t read_u16(const uint8_t *data)
        {
            return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
        }

        uint32_t read_u32(const uint8_t *data)
        {
            return (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
                   (static_cast<uint32_t>(data[2]) << 8) | data[3];
        }

        void write_u32(uint8_t *data, uint32_t value)
        {
            for (std::size_t i = 0; i < 4; ++i)
                data[i] = static_cast<uint8_t>(value >> (24 - 8 * i));
        }

        std::size_t ptp_body_size(uint8_t type)
        {
            switch (type & 0x0f)
            {
            case 0:
            case 1:
            case 8:
                return 44;
            case 9:
                return 54;
            case 11:
                return 64;
            default:
                return 0;
            }
        }

        bool ptp_header_valid(const uint8_t *message, std::size_t length)
        {
            return message != nullptr && length >= 34 && read_u16(message + 2) == length &&
                   (message[0] & 0xf0) == 0 && (message[1] == 0x02 || message[1] == 0x12);
        }

        template <typename Ring>
        const char *ring_error(const Ring &ring, std::size_t maximum, uint32_t maximum_id, uint32_t active_id)
        {
            const auto ring_size = std::size(ring);
            if (ring_size == 0)
                return "PTP key ring is empty";
            if (ring_size > maximum)
                return "PTP key ring exceeds the supported key count";
            bool active_found = false;
            for (std::size_t i = 0; i < ring_size; ++i)
            {
                const auto &key = ring[i];
                if (key.key_id == 0 || key.key_id > maximum_id)
                    return "PTP key ID is out of range";
                if (key.key_value[key_size] != '\0')
                    return "PTP key is not NUL-terminated after 32 characters";
                for (std::size_t j = 0; j < key_size; ++j)
                {
                    const char c = key.key_value[j];
                    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')))
                        return "PTP key must contain exactly 32 ASCII alphanumeric characters";
                }
                for (std::size_t j = 0; j < i; ++j)
                    if (ring[j].key_id == key.key_id)
                        return "PTP key IDs are duplicated";
                active_found = active_found || key.key_id == active_id;
            }
            return active_found ? nullptr : "PTP active transmit key ID is missing from the key ring";
        }

        const PtpHandle *find_ptp_key(uint32_t id)
        {
            for (std::size_t i = 0; i < ptp_key_count; ++i)
                if (ptp_keys[i].id == id)
                    return &ptp_keys[i];
            return nullptr;
        }

        void release_ptp_keys()
        {
            for (std::size_t i = 0; i < ptp_key_count; ++i)
            {
                psa_destroy_key(ptp_keys[i].handle);
                ptp_keys[i] = {};
            }
            ptp_key_count = 0;
        }

        bool import_ptp_keys()
        {
            for (const auto &source : settings::ptp_symmetric_keys)
            {
                psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
                psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
                psa_set_key_bits(&attributes, key_size * 8);
                psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
                psa_set_key_algorithm(&attributes, mac_algorithm);
                // Volatile lifetime is the default: no key IDs or material enter NVS.
                psa_key_id_t handle = 0;
                const auto status = psa_import_key(&attributes,
                                                   reinterpret_cast<const uint8_t *>(source.key_value), key_size, &handle);
                psa_reset_key_attributes(&attributes);
                if (status != PSA_SUCCESS)
                {
                    ESP_LOGE(tag, "PTP HMAC key import failed: key ID=%" PRIu32 " PSA status=%ld; authentication unavailable",
                             source.key_id, static_cast<long>(status));
                    release_ptp_keys();
                    return false;
                }
                ptp_keys[ptp_key_count++] = {source.key_id, handle};
            }
            return true;
        }

    }

    bool auth_initialize()
    {
        if (initialized)
            return ptp_ready;
        initialized = true;
        if constexpr (!settings::ptp_auth_enabled)
        {
            ptp_ready = !settings::ptp_auth_required;
            if (!ptp_ready)
                ESP_LOGE(tag, "PTP authentication configuration fault: AUTH_REQUIRED=1 requires AUTH_ENABLED=1; no unsigned downgrade");
            return ptp_ready;
        }
        else
        {
            if constexpr (!settings::ptp_auth_required && std::size(settings::ptp_symmetric_keys) == 0)
            {
                ESP_LOGW(tag, "No PTP keys are provisioned; optional authentication permits unsigned-only operation; signed packets rejected; provision matching server keys in main\\ESP32PTPL2FollowerSettingsSecrets.h to accept signed time");
                ptp_ready = true;
                return true;
            }
            else
            {
                const char *error = ring_error(settings::ptp_symmetric_keys, settings::ptp_max_keys,
                                               std::numeric_limits<uint32_t>::max(), settings::ptp_active_key_id);
                if (error)
                {
                    ESP_LOGE(tag, "PTP authentication configuration fault: %s; provision 1..4 matching server keys (32 ASCII alphanumeric characters each) in main\\ESP32PTPL2FollowerSettingsSecrets.h; active key ID=%" PRIu32,
                             error, settings::ptp_active_key_id);
                    return false;
                }
                const auto status = psa_crypto_init();
                if (status != PSA_SUCCESS)
                {
                    ESP_LOGE(tag, "PTP PSA crypto initialization failed: status=%ld; authentication unavailable", static_cast<long>(status));
                    return false;
                }
                ptp_available = import_ptp_keys();
                ptp_ready = ptp_available;
                return ptp_ready;
            }
        }
    }

    bool ptp_auth_ready()
    {
        return ptp_ready;
    }

    bool ptp_auth_available()
    {
        return ptp_available;
    }

    AuthResult ptp_auth_verify(const uint8_t *message, std::size_t length)
    {
        if (!ptp_header_valid(message, length))
            return AuthResult::malformed;
        const auto body = ptp_body_size(message[0]);
        if (body == 0 || (length != body && length != body + ptp_auth_tlv_size))
            return AuthResult::malformed;
        if (!ptp_ready)
            return AuthResult::unavailable;
        if (length == body)
            return settings::ptp_auth_required ? AuthResult::authentication_required : AuthResult::unauthenticated;
        if (!settings::ptp_auth_enabled)
            return AuthResult::disabled;
        const auto *tlv = message + body;
        if (message[1] != 0x12 || read_u16(tlv) != 0x8009 ||
            read_u16(tlv + 2) != ptp_auth_tlv_size - 4 || tlv[4] != settings::ptp_auth_spp || tlv[5] != 0)
            return AuthResult::malformed;
        if (!ptp_available)
            return AuthResult::unavailable;
        const auto *key = find_ptp_key(read_u32(tlv + 6));
        if (key == nullptr)
            return AuthResult::unknown_key;
        const auto status = psa_mac_verify(key->handle, mac_algorithm, message, length - ptp_auth_icv_size,
                                           tlv + 10, ptp_auth_icv_size);
        if (status == PSA_SUCCESS)
            return AuthResult::valid;
        return status == PSA_ERROR_INVALID_SIGNATURE ? AuthResult::invalid_mac : AuthResult::unavailable;
    }

    bool ptp_auth_append(uint8_t *message, std::size_t capacity, std::size_t &length, bool authenticate)
    {
        if (!ptp_ready || length > capacity || !ptp_header_valid(message, length) ||
            ptp_body_size(message[0]) != length || message[1] != (authenticate ? 0x12 : 0x02))
            return false;
        if (!authenticate)
            return !settings::ptp_auth_required;
        if (!ptp_available)
            return false;
        if (capacity - length < ptp_auth_tlv_size)
            return false;
        const auto *key = find_ptp_key(settings::ptp_active_key_id);
        if (key == nullptr)
            return false;
        const auto total = length + ptp_auth_tlv_size;
        auto *tlv = message + length;
        tlv[0] = 0x80;
        tlv[1] = 0x09;
        tlv[2] = 0;
        tlv[3] = ptp_auth_tlv_size - 4;
        tlv[4] = settings::ptp_auth_spp;
        tlv[5] = 0;
        write_u32(tlv + 6, key->id);
        message[2] = static_cast<uint8_t>(total >> 8);
        message[3] = static_cast<uint8_t>(total);
        std::size_t mac_length = 0;
        const auto status = psa_mac_compute(key->handle, mac_algorithm, message, total - ptp_auth_icv_size,
                                            tlv + 10, ptp_auth_icv_size, &mac_length);
        if (status != PSA_SUCCESS || mac_length != ptp_auth_icv_size)
            return false;
        length = total;
        return true;
    }

    const char *auth_result_name(AuthResult result)
    {
        switch (result)
        {
        case AuthResult::unauthenticated:
            return "unauthenticated";
        case AuthResult::valid:
            return "valid";
        case AuthResult::authentication_required:
            return "authentication_required";
        case AuthResult::disabled:
            return "disabled";
        case AuthResult::malformed:
            return "malformed";
        case AuthResult::unavailable:
            return "unavailable";
        case AuthResult::unknown_key:
            return "unknown_key";
        case AuthResult::invalid_mac:
            return "invalid_mac";
        }
        return "unknown";
    }
}
