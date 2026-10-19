#pragma once

#include <cstddef>
#include <cstdint>

namespace esphome::bluetti::crypto {

bool md5(const uint8_t *data, size_t len, uint8_t output[16]);
bool sha256(const uint8_t *data, size_t len, uint8_t output[32]);
bool cbc(bool encrypt, const uint8_t *data, size_t len, const uint8_t *key,
         unsigned key_bits, const uint8_t iv[16], uint8_t *output);
bool generate_keypair(uint8_t private_key[32], uint8_t public_key[64]);
bool verify(const uint8_t public_key[65], const uint8_t hash[32],
            const uint8_t signature[64]);
bool sign(const uint8_t private_key[32], const uint8_t hash[32],
          uint8_t signature[64]);
bool shared_secret(const uint8_t private_key[32], const uint8_t public_key[64],
                   uint8_t secret[32]);

} // namespace esphome::bluetti::crypto
