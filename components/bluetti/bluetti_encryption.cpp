#include "bluetti_encryption.h"

#include "esphome/core/log.h"

#include <cstring>
#include <esp_random.h>
#include <mbedtls/aes.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha256.h>

namespace esphome::bluetti {
namespace {

constexpr const char *TAG = "bluetti_encryption";
constexpr size_t AES_BLOCK_SIZE = 16;
constexpr size_t PUBKEY_LEN = 64;
constexpr size_t PEER_PAYLOAD_SIZE = 128;
constexpr uint8_t LOCAL_AES_KEY[16] = {0x45, 0x9F, 0xC5, 0x35, 0x80, 0x89,
                                       0x41, 0xF1, 0x70, 0x91, 0xE0, 0x99,
                                       0x3E, 0xE3, 0xE9, 0x3D};
constexpr uint8_t PRIVATE_KEY_L1[32] = {
    0x4F, 0x19, 0xA1, 0x6E, 0x3E, 0x87, 0xBD, 0xD9, 0xBD, 0x24, 0xD3,
    0xE5, 0x49, 0x5B, 0x88, 0x04, 0x15, 0x11, 0x94, 0x3C, 0xBC, 0x8B,
    0x96, 0x9A, 0xDE, 0x96, 0x41, 0xD0, 0xF5, 0x6A, 0xF3, 0x37};
// The original K2 trust anchor in SEC1 form, without its DER wrapper.
constexpr uint8_t PUBLIC_KEY_K2[65] = {
    0x04, 0xA7, 0x3A, 0xBF, 0x5D, 0x22, 0x32, 0xC8, 0xC1, 0xC7, 0x2E,
    0x68, 0x30, 0x43, 0x43, 0xC2, 0x72, 0x49, 0x5E, 0x3A, 0x8F, 0xD6,
    0xF3, 0x0E, 0xA9, 0x6D, 0xE2, 0xF4, 0xB3, 0xCE, 0x60, 0xB2, 0x51,
    0xEE, 0x21, 0xAC, 0x66, 0x7C, 0xF8, 0xA7, 0x1E, 0x18, 0xB4, 0x6B,
    0x66, 0x4E, 0xAE, 0xFF, 0xE3, 0xC4, 0x89, 0xF2, 0x4F, 0x69, 0x5B,
    0x64, 0x11, 0xDB, 0x7E, 0x22, 0xCC, 0xC8, 0x5A, 0x85, 0x94};

// Scope-bound cleanup covers every early error return.
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

bool crypto_ok(int result, const char *operation) {
    if (result != 0)
        ESP_LOGE(TAG, "%s failed (ret=%d)", operation, result);
    return result == 0;
}

int random_bytes(void *, unsigned char *output, size_t len) {
    esp_fill_random(output, len);
    return 0;
}

bool load_curve(mbedtls_ecp_group *group) {
    return crypto_ok(mbedtls_ecp_group_load(group, MBEDTLS_ECP_DP_SECP256R1),
                     "P-256 curve");
}

bool read_public_key(mbedtls_ecp_group *group, mbedtls_ecp_point *point,
                     const uint8_t *raw_key) {
    uint8_t encoded[65];
    encoded[0] = 0x04;
    std::memcpy(encoded + 1, raw_key, PUBKEY_LEN);
    return crypto_ok(
        mbedtls_ecp_point_read_binary(group, point, encoded, sizeof(encoded)),
        "Public key");
}

bool hash_public_key(const uint8_t *key, const uint8_t *iv, uint8_t *hash) {
    uint8_t message[80];
    std::memcpy(message, key, PUBKEY_LEN);
    std::memcpy(message + PUBKEY_LEN, iv, AES_BLOCK_SIZE);
    return crypto_ok(mbedtls_sha256(message, sizeof(message), hash, 0),
                     "SHA-256");
}

bool verify_peer_signature(mbedtls_ecp_group *group, const uint8_t *key,
                           const uint8_t *signature, const uint8_t *iv) {
    Point trusted_key;
    Integer r, s;
    uint8_t hash[32];
    return crypto_ok(mbedtls_ecp_point_read_binary(group, trusted_key,
                                                   PUBLIC_KEY_K2,
                                                   sizeof(PUBLIC_KEY_K2)),
                     "K2 public key") &&
           hash_public_key(key, iv, hash) &&
           crypto_ok(mbedtls_mpi_read_binary(r, signature, 32),
                     "Signature r") &&
           crypto_ok(mbedtls_mpi_read_binary(s, signature + 32, 32),
                     "Signature s") &&
           crypto_ok(mbedtls_ecdsa_verify(group, hash, sizeof(hash),
                                          trusted_key, r, s),
                     "Peer signature");
}

size_t finish_kex_packet(uint8_t type, size_t payload_len, uint8_t *packet) {
    packet[0] = packet[1] = 0x2A;
    packet[2] = type;
    packet[3] = static_cast<uint8_t>(payload_len);
    uint16_t checksum = 0;
    for (size_t i = 2; i < payload_len + 4; ++i)
        checksum += packet[i];
    packet[payload_len + 4] = static_cast<uint8_t>(checksum >> 8);
    packet[payload_len + 5] = static_cast<uint8_t>(checksum);
    return payload_len + 6;
}

bool crypt_cbc(int mode, const uint8_t *data, size_t len, const uint8_t *key,
               unsigned key_bits, const uint8_t *iv, uint8_t *output) {
    Aes context;
    uint8_t iv_copy[AES_BLOCK_SIZE];
    std::memcpy(iv_copy, iv, sizeof(iv_copy));
    int result = mode == MBEDTLS_AES_ENCRYPT
                     ? mbedtls_aes_setkey_enc(context, key, key_bits)
                     : mbedtls_aes_setkey_dec(context, key, key_bits);
    return crypto_ok(result, "AES key") &&
           crypto_ok(
               mbedtls_aes_crypt_cbc(context, mode, len, iv_copy, data, output),
               "AES-CBC");
}

bool encrypt_frame(const uint8_t *data, size_t len, const uint8_t *key,
                   unsigned key_bits, const uint8_t *iv, const uint8_t *iv_seed,
                   uint8_t *output, size_t *output_len) {
    const size_t header_len = iv_seed == nullptr ? 2 : 6;
    if (data == nullptr || output == nullptr || output_len == nullptr ||
        len == 0 || len > UINT16_MAX || *output_len < header_len)
        return false;
    const size_t padded_len =
        (len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
    if (padded_len > *output_len - header_len)
        return false;

    // Move first to support aliased input/output without a temporary packet.
    std::memmove(output + header_len, data, len);
    std::memset(output + header_len + len, 0, padded_len - len);
    if (!crypt_cbc(MBEDTLS_AES_ENCRYPT, output + header_len, padded_len, key,
                   key_bits, iv, output + header_len))
        return false;
    output[0] = static_cast<uint8_t>(len >> 8);
    output[1] = static_cast<uint8_t>(len);
    if (iv_seed != nullptr)
        std::memcpy(output + 2, iv_seed, 4);
    *output_len = header_len + padded_len;
    return true;
}

} // namespace

void BluettiEncryption::reset() {
    unsecure_aes_key_.fill(0);
    unsecure_aes_iv_.fill(0);
    secure_aes_key_.fill(0);
    peer_pubkey_.fill(0);
    my_privkey_.fill(0);
    my_pubkey_.fill(0);
    unsecure_key_set_ = secure_aes_key_set_ = peer_pubkey_set_ =
        my_keypair_set_ = false;
}

bool BluettiEncryption::precompute_ephemeral_keypair() {
    if (my_keypair_set_)
        return true;
    Group group;
    Point public_key;
    Integer private_key;
    uint8_t encoded[65];
    size_t encoded_len = sizeof(encoded);
    if (!load_curve(group) ||
        !crypto_ok(mbedtls_ecp_gen_keypair(group, private_key, public_key,
                                           random_bytes, nullptr),
                   "Key generation") ||
        !crypto_ok(mbedtls_mpi_write_binary(private_key, my_privkey_.data(),
                                            my_privkey_.size()),
                   "Private key export") ||
        !crypto_ok(mbedtls_ecp_point_write_binary(
                       group, public_key, MBEDTLS_ECP_PF_UNCOMPRESSED,
                       &encoded_len, encoded, sizeof(encoded)),
                   "Public key export"))
        return false;
    std::memcpy(my_pubkey_.data(), encoded + 1, PUBKEY_LEN);
    my_keypair_set_ = true;
    return true;
}

bool BluettiEncryption::handle_challenge(const uint8_t *data, size_t len,
                                         uint8_t *response,
                                         size_t *response_len) {
    if (data == nullptr || len != 4 || response == nullptr ||
        response_len == nullptr || *response_len < 10)
        return false;
    uint8_t reversed[4] = {data[3], data[2], data[1], data[0]};
    if (!crypto_ok(
            mbedtls_md5(reversed, sizeof(reversed), unsecure_aes_iv_.data()),
            "MD5"))
        return false;
    for (size_t i = 0; i < sizeof(LOCAL_AES_KEY); ++i)
        unsecure_aes_key_[i] = unsecure_aes_iv_[i] ^ LOCAL_AES_KEY[i];
    unsecure_key_set_ = true;
    std::memcpy(response + 4, unsecure_aes_iv_.data() + 8, 4);
    *response_len = finish_kex_packet(0x02, 4, response);
    return true;
}

bool BluettiEncryption::handle_peer_pubkey(const uint8_t *data, size_t len,
                                           uint8_t *response,
                                           size_t *response_len) {
    if (!unsecure_key_set_ || data == nullptr || len != PEER_PAYLOAD_SIZE ||
        response == nullptr || response_len == nullptr ||
        *response_len < PEER_PAYLOAD_SIZE + 6)
        return false;
    Group group;
    Integer private_key, r, s;
    uint8_t hash[32];
    if (!load_curve(group) ||
        !verify_peer_signature(group, data, data + PUBKEY_LEN,
                               unsecure_aes_iv_.data()) ||
        !precompute_ephemeral_keypair() ||
        !hash_public_key(my_pubkey_.data(), unsecure_aes_iv_.data(), hash) ||
        !crypto_ok(mbedtls_mpi_read_binary(private_key, PRIVATE_KEY_L1,
                                           sizeof(PRIVATE_KEY_L1)),
                   "L1 private key") ||
        !crypto_ok(mbedtls_ecdsa_sign(group, r, s, private_key, hash,
                                      sizeof(hash), random_bytes, nullptr),
                   "Local signature"))
        return false;
    // Save before writing the response: its input may be inside that buffer.
    std::memcpy(peer_pubkey_.data(), data, PUBKEY_LEN);
    std::memcpy(response + 4, my_pubkey_.data(), PUBKEY_LEN);
    if (!crypto_ok(mbedtls_mpi_write_binary(r, response + 4 + PUBKEY_LEN, 32),
                   "Signature r export") ||
        !crypto_ok(
            mbedtls_mpi_write_binary(s, response + 4 + PUBKEY_LEN + 32, 32),
            "Signature s export"))
        return false;
    *response_len = finish_kex_packet(0x05, PEER_PAYLOAD_SIZE, response);
    peer_pubkey_set_ = true;
    return true;
}

bool BluettiEncryption::derive_secure_key() {
    if (!my_keypair_set_ || !peer_pubkey_set_)
        return false;
    Group group;
    Point peer_key;
    Integer private_key, shared_secret;
    if (!load_curve(group) ||
        !read_public_key(group, peer_key, peer_pubkey_.data()) ||
        !crypto_ok(mbedtls_mpi_read_binary(private_key, my_privkey_.data(),
                                           my_privkey_.size()),
                   "Private key") ||
        !crypto_ok(mbedtls_ecdh_compute_shared(group, shared_secret, peer_key,
                                               private_key, random_bytes,
                                               nullptr),
                   "ECDH") ||
        !crypto_ok(mbedtls_mpi_write_binary(shared_secret,
                                            secure_aes_key_.data(),
                                            secure_aes_key_.size()),
                   "Shared secret export"))
        return false;
    secure_aes_key_set_ = true;
    return true;
}

bool BluettiEncryption::handle_pubkey_accepted(const uint8_t *data,
                                               size_t len) {
    return data != nullptr && len == 1 && data[0] == 0 && derive_secure_key();
}

bool BluettiEncryption::encrypt_unsecure_kex(const uint8_t *data, size_t len,
                                             uint8_t *output,
                                             size_t *output_len) {
    return unsecure_key_set_ &&
           encrypt_frame(data, len, unsecure_aes_key_.data(), 128,
                         unsecure_aes_iv_.data(), nullptr, output, output_len);
}

bool BluettiEncryption::encrypt_modbus_command(const uint8_t *data, size_t len,
                                               uint8_t *output,
                                               size_t *output_len) {
    if (!is_ready_for_commands())
        return false;
    uint8_t iv_seed[4], iv[AES_BLOCK_SIZE];
    esp_fill_random(iv_seed, sizeof(iv_seed));
    return crypto_ok(mbedtls_md5(iv_seed, sizeof(iv_seed), iv), "MD5") &&
           encrypt_frame(data, len, secure_aes_key_.data(), 256, iv, iv_seed,
                         output, output_len);
}

bool BluettiEncryption::decrypt_response(const uint8_t *data, size_t len,
                                         uint8_t *output, size_t *output_len) {
    const bool secure = is_ready_for_commands();
    const size_t header_len = secure ? 6 : 2;
    if ((!secure && !unsecure_key_set_) || data == nullptr ||
        output == nullptr || output_len == nullptr || len <= header_len)
        return false;
    const size_t plaintext_len = static_cast<size_t>(data[0]) << 8 | data[1];
    const size_t encrypted_len = len - header_len;
    if (encrypted_len % AES_BLOCK_SIZE != 0 || encrypted_len > *output_len ||
        plaintext_len > encrypted_len)
        return false;
    uint8_t iv[AES_BLOCK_SIZE];
    if (secure) {
        if (!crypto_ok(mbedtls_md5(data + 2, 4, iv), "MD5"))
            return false;
    } else {
        std::memcpy(iv, unsecure_aes_iv_.data(), sizeof(iv));
    }
    std::memmove(output, data + header_len, encrypted_len);
    if (!crypt_cbc(MBEDTLS_AES_DECRYPT, output, encrypted_len,
                   secure ? secure_aes_key_.data() : unsecure_aes_key_.data(),
                   secure ? 256 : 128, iv, output))
        return false;
    *output_len = plaintext_len;
    return true;
}

} // namespace esphome::bluetti
