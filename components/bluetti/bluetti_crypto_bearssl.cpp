#include "esphome/core/defines.h"

#ifdef USE_RP2
#include "bluetti_crypto.h"
#include "esphome/core/helpers.h"

#include <bearssl/bearssl.h>
#include <cstring>

namespace esphome::bluetti::crypto {

bool md5(const uint8_t *data, size_t len, uint8_t output[16]) {
    br_md5_context context;
    br_md5_init(&context);
    br_md5_update(&context, data, len);
    br_md5_out(&context, output);
    return true;
}
bool sha256(const uint8_t *data, size_t len, uint8_t output[32]) {
    br_sha256_context context;
    br_sha256_init(&context);
    br_sha256_update(&context, data, len);
    br_sha256_out(&context, output);
    return true;
}
bool cbc(bool encrypt, const uint8_t *data, size_t len, const uint8_t *key,
         unsigned key_bits, const uint8_t iv[16], uint8_t *output) {
    if (len % 16 != 0 || (key_bits != 128 && key_bits != 256))
        return false;
    uint8_t iv_copy[16];
    std::memcpy(iv_copy, iv, sizeof(iv_copy));
    std::memmove(output, data, len);
    if (encrypt) {
        br_aes_ct_cbcenc_keys context;
        br_aes_ct_cbcenc_init(&context, key, key_bits / 8);
        br_aes_ct_cbcenc_run(&context, iv_copy, output, len);
    } else {
        br_aes_ct_cbcdec_keys context;
        br_aes_ct_cbcdec_init(&context, key, key_bits / 8);
        br_aes_ct_cbcdec_run(&context, iv_copy, output, len);
    }
    return true;
}
bool generate_keypair(uint8_t private_key[32], uint8_t public_key[64]) {
    uint8_t seed[32], encoded[65];
    if (!esphome::random_bytes(seed, sizeof(seed)))
        return false;
    br_hmac_drbg_context rng;
    br_hmac_drbg_init(&rng, &br_sha256_vtable, seed, sizeof(seed));
    br_ec_private_key key;
    if (br_ec_keygen(&rng.vtable, &br_ec_p256_m15, &key, private_key,
                     BR_EC_secp256r1) != 32 ||
        br_ec_compute_pub(&br_ec_p256_m15, nullptr, encoded, &key) !=
            sizeof(encoded))
        return false;
    std::memcpy(public_key, encoded + 1, 64);
    return true;
}
bool verify(const uint8_t public_key[65], const uint8_t hash[32],
            const uint8_t signature[64]) {
    br_ec_public_key key{BR_EC_secp256r1, const_cast<uint8_t *>(public_key),
                         65};
    return br_ecdsa_i15_vrfy_raw(&br_ec_p256_m15, hash, 32, &key, signature,
                                 64) == 1;
}
bool sign(const uint8_t private_key[32], const uint8_t hash[32],
          uint8_t signature[64]) {
    br_ec_private_key key{BR_EC_secp256r1, const_cast<uint8_t *>(private_key),
                          32};
    return br_ecdsa_i15_sign_raw(&br_ec_p256_m15, &br_sha256_vtable, hash, &key,
                                 signature) == 64;
}
bool shared_secret(const uint8_t private_key[32], const uint8_t public_key[64],
                   uint8_t secret[32]) {
    uint8_t encoded[65] = {4};
    std::memcpy(encoded + 1, public_key, 64);
    // BearSSL validates the peer point while multiplying. Bluetti uses the
    // resulting point's big-endian X coordinate directly as its AES-256 key.
    if (br_ec_p256_m15.mul(encoded, sizeof(encoded), private_key, 32,
                           BR_EC_secp256r1) != 1)
        return false;
    std::memcpy(secret, encoded + 1, 32);
    return true;
}
} // namespace esphome::bluetti::crypto
#endif
