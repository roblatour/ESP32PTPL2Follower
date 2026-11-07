#pragma once

#include <cstddef>
#include <cstdint>

using psa_status_t = int32_t;
using psa_key_id_t = uint32_t;
using psa_algorithm_t = uint32_t;
using psa_key_usage_t = uint32_t;
using psa_key_type_t = uint16_t;

inline constexpr psa_status_t PSA_SUCCESS = 0;
inline constexpr psa_status_t PSA_ERROR_GENERIC_ERROR = -132;
inline constexpr psa_status_t PSA_ERROR_NOT_SUPPORTED = -134;
inline constexpr psa_status_t PSA_ERROR_INVALID_ARGUMENT = -135;
inline constexpr psa_status_t PSA_ERROR_BAD_STATE = -137;
inline constexpr psa_status_t PSA_ERROR_BUFFER_TOO_SMALL = -138;
inline constexpr psa_status_t PSA_ERROR_INVALID_SIGNATURE = -149;
inline constexpr psa_algorithm_t PSA_ALG_SHA_256 = 0x02000009;
inline constexpr psa_key_type_t PSA_KEY_TYPE_HMAC = 0x1100;
inline constexpr psa_key_usage_t PSA_KEY_USAGE_SIGN_MESSAGE = 0x0400;
inline constexpr psa_key_usage_t PSA_KEY_USAGE_VERIFY_MESSAGE = 0x0800;

constexpr psa_algorithm_t PSA_ALG_HMAC(psa_algorithm_t hash)
{
    return 0x03800000 | (hash & 0xff);
}
constexpr psa_algorithm_t PSA_ALG_TRUNCATED_MAC(psa_algorithm_t algorithm, std::size_t size)
{
    return (algorithm & ~0x003f0000u) | (static_cast<uint32_t>(size) << 16);
}

struct psa_key_attributes_t
{
    psa_key_type_t type{};
    std::size_t bits{};
    psa_key_usage_t usage{};
    psa_algorithm_t algorithm{};
};
struct psa_hash_operation_t
{
    void *algorithm{};
    void *hash{};
};
#define PSA_KEY_ATTRIBUTES_INIT {}
#define PSA_HASH_OPERATION_INIT {}

void psa_set_key_type(psa_key_attributes_t *, psa_key_type_t);
void psa_set_key_bits(psa_key_attributes_t *, std::size_t);
void psa_set_key_usage_flags(psa_key_attributes_t *, psa_key_usage_t);
void psa_set_key_algorithm(psa_key_attributes_t *, psa_algorithm_t);
void psa_reset_key_attributes(psa_key_attributes_t *);
psa_status_t psa_crypto_init();
psa_status_t psa_import_key(const psa_key_attributes_t *, const uint8_t *, std::size_t, psa_key_id_t *);
psa_status_t psa_destroy_key(psa_key_id_t);
psa_status_t psa_mac_compute(psa_key_id_t, psa_algorithm_t, const uint8_t *, std::size_t,
                             uint8_t *, std::size_t, std::size_t *);
psa_status_t psa_mac_verify(psa_key_id_t, psa_algorithm_t, const uint8_t *, std::size_t,
                            const uint8_t *, std::size_t);
psa_status_t psa_hash_setup(psa_hash_operation_t *, psa_algorithm_t);
psa_status_t psa_hash_update(psa_hash_operation_t *, const uint8_t *, std::size_t);
psa_status_t psa_hash_finish(psa_hash_operation_t *, uint8_t *, std::size_t, std::size_t *);
psa_status_t psa_hash_abort(psa_hash_operation_t *);

void host_psa_set_failure(const char *);
std::size_t host_psa_key_count();
