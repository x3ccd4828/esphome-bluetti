#include "esphome/core/defines.h"

#ifndef USE_RP2
#include "bluetti_crypto.h"
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"

#include <cstring>
#include <mbedtls/aes.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha256.h>

namespace esphome::bluetti::crypto {
namespace {
constexpr const char *TAG = "bluetti_encryption";

template <typename T, void (*Init)(T *), void (*Free)(T *)> class Context {
  public:
    Context() { Init(&value_); }
    ~Context() { Free(&value_); }
    Context(const Context &) = delete;
    Context &operator=(const Context &) = delete;
    operator T *() { return &value_; }

  private:
    T value_;
};
using Group =
    Context<mbedtls_ecp_group, mbedtls_ecp_group_init, mbedtls_ecp_group_free>;
using Point =
    Context<mbedtls_ecp_point, mbedtls_ecp_point_init, mbedtls_ecp_point_free>;
using Integer = Context<mbedtls_mpi, mbedtls_mpi_init, mbedtls_mpi_free>;
using Aes = Context<mbedtls_aes_context, mbedtls_aes_init, mbedtls_aes_free>;

bool ok(int result, const char *operation) {
    if (result != 0)
        ESP_LOGE(TAG, "%s failed (ret=%d)", operation, result);
    return result == 0;
}
int random(void *, unsigned char *output, size_t len) {
    return esphome::random_bytes(output, len) ? 0
                                              : MBEDTLS_ERR_ECP_RANDOM_FAILED;
}
bool curve(mbedtls_ecp_group *group) {
    return ok(mbedtls_ecp_group_load(group, MBEDTLS_ECP_DP_SECP256R1),
              "P-256 curve");
}
} // namespace

bool md5(const uint8_t *data, size_t len, uint8_t output[16]) {
    return ok(mbedtls_md5(data, len, output), "MD5");
}
bool sha256(const uint8_t *data, size_t len, uint8_t output[32]) {
    return ok(mbedtls_sha256(data, len, output, 0), "SHA-256");
}
bool cbc(bool encrypt, const uint8_t *data, size_t len, const uint8_t *key,
         unsigned key_bits, const uint8_t iv[16], uint8_t *output) {
    Aes context;
    uint8_t iv_copy[16];
    std::memcpy(iv_copy, iv, sizeof(iv_copy));
    int result = encrypt ? mbedtls_aes_setkey_enc(context, key, key_bits)
                         : mbedtls_aes_setkey_dec(context, key, key_bits);
    return ok(result, "AES key") &&
           ok(mbedtls_aes_crypt_cbc(
                  context, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
                  len, iv_copy, data, output),
              "AES-CBC");
}
bool generate_keypair(uint8_t private_key[32], uint8_t public_key[64]) {
    Group group;
    Point point;
    Integer scalar;
    uint8_t encoded[65];
    size_t size = sizeof(encoded);
    if (!curve(group) ||
        !ok(mbedtls_ecp_gen_keypair(group, scalar, point, random, nullptr),
            "Key generation") ||
        !ok(mbedtls_mpi_write_binary(scalar, private_key, 32),
            "Private key export") ||
        !ok(mbedtls_ecp_point_write_binary(group, point,
                                           MBEDTLS_ECP_PF_UNCOMPRESSED, &size,
                                           encoded, sizeof(encoded)),
            "Public key export"))
        return false;
    std::memcpy(public_key, encoded + 1, 64);
    return true;
}
bool verify(const uint8_t public_key[65], const uint8_t hash[32],
            const uint8_t signature[64]) {
    Group group;
    Point point;
    Integer r, s;
    return curve(group) &&
           ok(mbedtls_ecp_point_read_binary(group, point, public_key, 65),
              "K2 public key") &&
           ok(mbedtls_mpi_read_binary(r, signature, 32), "Signature r") &&
           ok(mbedtls_mpi_read_binary(s, signature + 32, 32), "Signature s") &&
           ok(mbedtls_ecdsa_verify(group, hash, 32, point, r, s),
              "Peer signature");
}
bool sign(const uint8_t private_key[32], const uint8_t hash[32],
          uint8_t signature[64]) {
    Group group;
    Integer scalar, r, s;
    return curve(group) &&
           ok(mbedtls_mpi_read_binary(scalar, private_key, 32),
              "L1 private key") &&
           ok(mbedtls_ecdsa_sign(group, r, s, scalar, hash, 32, random,
                                 nullptr),
              "Local signature") &&
           ok(mbedtls_mpi_write_binary(r, signature, 32),
              "Signature r export") &&
           ok(mbedtls_mpi_write_binary(s, signature + 32, 32),
              "Signature s export");
}
bool shared_secret(const uint8_t private_key[32], const uint8_t public_key[64],
                   uint8_t secret[32]) {
    Group group;
    Point point;
    Integer scalar, shared;
    uint8_t encoded[65] = {4};
    std::memcpy(encoded + 1, public_key, 64);
    return curve(group) &&
           ok(mbedtls_ecp_point_read_binary(group, point, encoded,
                                            sizeof(encoded)),
              "Public key") &&
           ok(mbedtls_mpi_read_binary(scalar, private_key, 32),
              "Private key") &&
           ok(mbedtls_ecdh_compute_shared(group, shared, point, scalar, random,
                                          nullptr),
              "ECDH") &&
           ok(mbedtls_mpi_write_binary(shared, secret, 32),
              "Shared secret export");
}
} // namespace esphome::bluetti::crypto
#endif
