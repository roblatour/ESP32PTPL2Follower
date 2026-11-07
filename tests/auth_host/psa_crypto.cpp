#include "psa/crypto.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <cstring>
#include <limits>
#include <map>
#include <string>

namespace
{
struct Key
{
    psa_key_attributes_t attributes;
    std::array<uint8_t, 32> bytes;
};
std::map<psa_key_id_t, Key> keys;
psa_key_id_t next_key = 1;
std::string failure;
unsigned imports = 0;
bool initialized = false;
constexpr auto supported_mac = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 16);

bool fails(const char *name)
{
    return failure == name;
}

psa_status_t open_hash(psa_hash_operation_t *operation, const uint8_t *key, std::size_t size)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    key ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0) < 0)
        return PSA_ERROR_NOT_SUPPORTED;
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0, const_cast<PUCHAR>(key),
                         static_cast<ULONG>(size), 0) < 0)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return PSA_ERROR_GENERIC_ERROR;
    }
    operation->algorithm = algorithm;
    operation->hash = hash;
    return PSA_SUCCESS;
}
}

void host_psa_set_failure(const char *name) { failure = name ? name : ""; }
std::size_t host_psa_key_count() { return keys.size(); }
void psa_set_key_type(psa_key_attributes_t *a, psa_key_type_t v) { a->type = v; }
void psa_set_key_bits(psa_key_attributes_t *a, std::size_t v) { a->bits = v; }
void psa_set_key_usage_flags(psa_key_attributes_t *a, psa_key_usage_t v) { a->usage = v; }
void psa_set_key_algorithm(psa_key_attributes_t *a, psa_algorithm_t v) { a->algorithm = v; }
void psa_reset_key_attributes(psa_key_attributes_t *a) { *a = {}; }

psa_status_t psa_crypto_init()
{
    if (fails("init"))
        return PSA_ERROR_GENERIC_ERROR;
    psa_hash_operation_t operation{};
    const auto status = open_hash(&operation, nullptr, 0);
    psa_hash_abort(&operation);
    initialized = status == PSA_SUCCESS;
    return status;
}

psa_status_t psa_import_key(const psa_key_attributes_t *attributes, const uint8_t *data,
                             std::size_t size, psa_key_id_t *id)
{
    if (!initialized)
        return PSA_ERROR_BAD_STATE;
    if (fails("import") || (fails("import_second") && ++imports == 2))
        return PSA_ERROR_GENERIC_ERROR;
    if (!attributes || !data || !id || size != 32 || attributes->bits != 256 ||
        attributes->type != PSA_KEY_TYPE_HMAC || attributes->algorithm != supported_mac)
        return PSA_ERROR_INVALID_ARGUMENT;
    Key key{*attributes, {}};
    std::memcpy(key.bytes.data(), data, size);
    *id = next_key++;
    keys.emplace(*id, key);
    return PSA_SUCCESS;
}

psa_status_t psa_destroy_key(psa_key_id_t id)
{
    const auto entry = keys.find(id);
    if (entry == keys.end())
        return PSA_ERROR_INVALID_ARGUMENT;
    SecureZeroMemory(entry->second.bytes.data(), entry->second.bytes.size());
    keys.erase(entry);
    return PSA_SUCCESS;
}

psa_status_t psa_mac_compute(psa_key_id_t id, psa_algorithm_t algorithm, const uint8_t *data,
                             std::size_t size, uint8_t *output, std::size_t capacity, std::size_t *length)
{
    if (fails("mac"))
        return PSA_ERROR_GENERIC_ERROR;
    const auto key = keys.find(id);
    if (key == keys.end() || algorithm != supported_mac || !data || !output || !length ||
        !(key->second.attributes.usage & PSA_KEY_USAGE_SIGN_MESSAGE))
        return PSA_ERROR_INVALID_ARGUMENT;
    if (capacity < 16)
        return PSA_ERROR_BUFFER_TOO_SMALL;
    psa_hash_operation_t operation{};
    auto status = open_hash(&operation, key->second.bytes.data(), key->second.bytes.size());
    if (status == PSA_SUCCESS)
        status = psa_hash_update(&operation, data, size);
    uint8_t digest[32]{};
    std::size_t digest_size = 0;
    if (status == PSA_SUCCESS)
        status = psa_hash_finish(&operation, digest, sizeof(digest), &digest_size);
    psa_hash_abort(&operation);
    if (status == PSA_SUCCESS)
    {
        std::memcpy(output, digest, 16);
        *length = 16;
    }
    return status;
}

psa_status_t psa_mac_verify(psa_key_id_t id, psa_algorithm_t algorithm, const uint8_t *data,
                            std::size_t size, const uint8_t *mac, std::size_t mac_size)
{
    if (!mac || mac_size != 16)
        return PSA_ERROR_INVALID_SIGNATURE;
    const auto key = keys.find(id);
    if (key == keys.end() || !(key->second.attributes.usage & PSA_KEY_USAGE_VERIFY_MESSAGE))
        return PSA_ERROR_INVALID_ARGUMENT;
    uint8_t expected[16]{};
    std::size_t length = 0;
    const auto status = psa_mac_compute(id, algorithm, data, size, expected, sizeof(expected), &length);
    if (status != PSA_SUCCESS)
        return status;
    uint8_t difference = 0;
    for (std::size_t i = 0; i < mac_size; ++i)
        difference = static_cast<uint8_t>(difference | (mac[i] ^ expected[i]));
    return difference == 0 ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE;
}

psa_status_t psa_hash_setup(psa_hash_operation_t *operation, psa_algorithm_t algorithm)
{
    if (!initialized || !operation || operation->hash)
        return PSA_ERROR_BAD_STATE;
    if (fails("hash_setup"))
        return PSA_ERROR_GENERIC_ERROR;
    if (algorithm != PSA_ALG_SHA_256)
        return PSA_ERROR_NOT_SUPPORTED;
    return open_hash(operation, nullptr, 0);
}

psa_status_t psa_hash_update(psa_hash_operation_t *operation, const uint8_t *data, std::size_t size)
{
    if (fails("hash_update"))
        return PSA_ERROR_GENERIC_ERROR;
    if (!operation || !operation->hash || !data || size > std::numeric_limits<ULONG>::max())
        return PSA_ERROR_INVALID_ARGUMENT;
    return BCryptHashData(static_cast<BCRYPT_HASH_HANDLE>(operation->hash),
                          const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0) >= 0 ?
        PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_hash_finish(psa_hash_operation_t *operation, uint8_t *output,
                             std::size_t capacity, std::size_t *length)
{
    if (fails("hash_finish"))
        return PSA_ERROR_GENERIC_ERROR;
    if (!operation || !operation->hash || !output || !length)
        return PSA_ERROR_BAD_STATE;
    if (capacity < 32)
        return PSA_ERROR_BUFFER_TOO_SMALL;
    const auto result = BCryptFinishHash(static_cast<BCRYPT_HASH_HANDLE>(operation->hash), output, 32, 0);
    psa_hash_abort(operation);
    if (result < 0)
        return PSA_ERROR_GENERIC_ERROR;
    *length = 32;
    return PSA_SUCCESS;
}

psa_status_t psa_hash_abort(psa_hash_operation_t *operation)
{
    if (!operation)
        return PSA_ERROR_INVALID_ARGUMENT;
    if (operation->hash)
        BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(operation->hash));
    if (operation->algorithm)
        BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(operation->algorithm), 0);
    *operation = {};
    return PSA_SUCCESS;
}
