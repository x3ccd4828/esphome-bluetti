#include "bluetti_encryption.h"

#include "esphome/core/log.h"

#include <cstring>
#include <esp_random.h>
#include <mbedtls/aes.h>
#include <mbedtls/md5.h>

namespace esphome {
namespace bluetti_rust {

static const char *const TAG = "bluetti_encryption";

// ============================================================================
// BluettiMessage Implementation
// ============================================================================

BluettiMessage::BluettiMessage(const uint8_t *buffer, size_t len)
    : buffer_(buffer), len_(len), data_len_(0), body_len_(0) {
    if (len < KEX_DATA_OFFSET + CHECKSUM_SIZE) {
        return;
    }

    // Calculate lengths without checksum
    body_len_ = len_ - CHECKSUM_SIZE;
    if (body_len_ > KEX_DATA_OFFSET) {
        data_len_ = body_len_ - KEX_DATA_OFFSET;
    }
}

bool BluettiMessage::is_pre_key_exchange() const {
    return len_ >= 2 && buffer_[0] == KEX_MAGIC[0] &&
           buffer_[1] == KEX_MAGIC[1];
}

MessageType BluettiMessage::message_type() const {
    if (len_ <= KEX_TYPE_OFFSET) {
        return static_cast<MessageType>(0);
    }
    return static_cast<MessageType>(buffer_[KEX_TYPE_OFFSET]);
}

const uint8_t *BluettiMessage::data() const {
    if (len_ < KEX_DATA_OFFSET + CHECKSUM_SIZE) {
        return nullptr;
    }
    return buffer_ + KEX_DATA_OFFSET;
}

const uint8_t *BluettiMessage::body() const {
    if (len_ < KEX_BODY_OFFSET + CHECKSUM_SIZE) {
        return nullptr;
    }
    return buffer_ + KEX_BODY_OFFSET;
}

bool BluettiMessage::verify_checksum() const {
    if (len_ < KEX_DATA_OFFSET + CHECKSUM_SIZE) {
        return false;
    }

    // Calculate checksum of body (without the checksum itself)
    uint16_t computed = BluettiEncryption::hexsum(body(), body_len_);

    // Read stored checksum (last 2 bytes, big-endian)
    uint16_t stored = (static_cast<uint16_t>(buffer_[len_ - 2]) << 8) |
                      static_cast<uint16_t>(buffer_[len_ - 1]);

    return computed == stored;
}

// ============================================================================
// Static Utility Functions
// ============================================================================

void BluettiEncryption::md5_hash_16(const uint8_t *input, size_t len,
                                    uint8_t *output) {
    mbedtls_md5_context ctx;
    mbedtls_md5_init(&ctx);
    mbedtls_md5_starts(&ctx);
    mbedtls_md5_update(&ctx, input, len);

    uint8_t full_hash[16];
    mbedtls_md5_finish(&ctx, full_hash);
    mbedtls_md5_free(&ctx);

    // Copy first 16 bytes (MD5 produces 16 bytes anyway)
    std::memcpy(output, full_hash, 16);
}

void BluettiEncryption::xor_16(const uint8_t *a, const uint8_t *b,
                               uint8_t *output) {
    for (size_t i = 0; i < 16; ++i) {
        output[i] = a[i] ^ b[i];
    }
}

void BluettiEncryption::zero_pad(const uint8_t *data, size_t len,
                                 uint8_t *output, size_t *out_len) {
    std::memcpy(output, data, len);

    size_t padding = (AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    for (size_t i = 0; i < padding; ++i) {
        output[len + i] = 0;
    }

    *out_len = len + padding;
}

uint16_t BluettiEncryption::hexsum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum += data[i];
    }
    return static_cast<uint16_t>(sum & 0xFFFF);
}

// ============================================================================
// BluettiEncryption Implementation
// ============================================================================

BluettiEncryption::BluettiEncryption() { reset(); }

void BluettiEncryption::reset() {
    unsecure_aes_key_.fill(0);
    unsecure_aes_iv_.fill(0);
    secure_aes_key_.fill(0);
    peer_pubkey_.fill(0);
    my_privkey_.fill(0);
    my_pubkey_.fill(0);

    unsecure_key_set_ = false;
    unsecure_iv_set_ = false;
    secure_aes_key_set_ = false;
    peer_pubkey_set_ = false;
    my_keypair_set_ = false;
}

bool BluettiEncryption::handle_challenge(const uint8_t *data, size_t len,
                                         uint8_t *response,
                                         size_t *response_len) {
    if (len != CHALLENGE_LEN) {
        ESP_LOGE(TAG, "Invalid challenge length: %u",
                 static_cast<unsigned>(len));
        return false;
    }

    // Reverse the 4-byte seed
    uint8_t reversed[CHALLENGE_LEN];
    for (size_t i = 0; i < CHALLENGE_LEN; ++i) {
        reversed[i] = data[CHALLENGE_LEN - 1 - i];
    }

    // Derive unsecure IV = MD5(reversed_seed)
    md5_hash_16(reversed, CHALLENGE_LEN, unsecure_aes_iv_.data());
    unsecure_iv_set_ = true;

    // Derive unsecure key = IV XOR LOCAL_AES_KEY
    xor_16(unsecure_aes_iv_.data(), LOCAL_AES_KEY.data(),
           unsecure_aes_key_.data());
    unsecure_key_set_ = true;

    ESP_LOGI(TAG, "Challenge handled, unsecure keys derived");

    // Build response: MAGIC + TYPE(0x02) + LEN(4) + IV[8..12] + CHECKSUM
    if (*response_len < 8) {
        return false;
    }

    response[0] = KEX_MAGIC[0];
    response[1] = KEX_MAGIC[1];
    response[2] = CHALLENGE_RESPONSE_TYPE;
    response[3] = CHALLENGE_LEN;
    std::memcpy(response + 4,
                unsecure_aes_iv_.data() + CHALLENGE_IV_RESPONSE_START,
                CHALLENGE_LEN);

    // Calculate checksum of body (bytes 2-7)
    uint16_t checksum = hexsum(response + 2, 6);
    response[6] = (checksum >> 8) & 0xFF;
    response[7] = checksum & 0xFF;

    *response_len = 8;
    return true;
}

bool BluettiEncryption::aes_encrypt(const uint8_t *data, size_t len,
                                    const uint8_t *key, size_t key_len,
                                    const uint8_t *iv, uint8_t *output,
                                    size_t *output_len) {
    if (key_len != 16 && key_len != 32) {
        ESP_LOGE(TAG, "Invalid key length: %u", static_cast<unsigned>(key_len));
        return false;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret;
    if (key_len == 16) {
        ret = mbedtls_aes_setkey_enc(&ctx, key, 128);
    } else {
        ret = mbedtls_aes_setkey_enc(&ctx, key, 256);
    }

    if (ret != 0) {
        mbedtls_aes_free(&ctx);
        return false;
    }

    // Prepare IV copy (mbedtls modifies it)
    uint8_t iv_copy[16];
    std::memcpy(iv_copy, iv, 16);

    // Zero-pad the input
    uint8_t padded[512];
    size_t padded_len;
    zero_pad(data, len, padded, &padded_len);

    // Encrypt
    ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, padded_len, iv_copy,
                                padded, output);
    mbedtls_aes_free(&ctx);

    if (ret != 0) {
        return false;
    }

    *output_len = padded_len;
    return true;
}

bool BluettiEncryption::aes_decrypt(const uint8_t *data, size_t len,
                                    const uint8_t *key, size_t key_len,
                                    const uint8_t *iv, uint8_t *output,
                                    size_t *output_len) {
    if (key_len != 16 && key_len != 32) {
        ESP_LOGE(TAG, "Invalid key length: %u", static_cast<unsigned>(key_len));
        return false;
    }

    if (len % AES_BLOCK_SIZE != 0) {
        ESP_LOGE(TAG, "Data length not aligned to AES block size");
        return false;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret;
    if (key_len == 16) {
        ret = mbedtls_aes_setkey_dec(&ctx, key, 128);
    } else {
        ret = mbedtls_aes_setkey_dec(&ctx, key, 256);
    }

    if (ret != 0) {
        mbedtls_aes_free(&ctx);
        return false;
    }

    // Prepare IV copy
    uint8_t iv_copy[16];
    std::memcpy(iv_copy, iv, 16);

    // Decrypt
    ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv_copy, data,
                                output);
    mbedtls_aes_free(&ctx);

    if (ret != 0) {
        return false;
    }

    *output_len = len;
    return true;
}

// ============================================================================
// Phase 3: ECDH/ECDSA Implementation
// ============================================================================

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>

bool BluettiEncryption::verify_peer_signature(const uint8_t *pubkey,
                                              const uint8_t *signature) {
    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa);

    // Load the P-256 curve
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load P-256 curve");
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Extract K2 public key bytes (last 64 bytes of the ASN.1 encoded key)
    uint8_t k2_pubkey_raw[64];
    memcpy(k2_pubkey_raw, PUBLIC_KEY_K2_BYTES.data() + 27, 64);

    // Read the K2 public key
    mbedtls_ecp_point k2_pubkey;
    mbedtls_ecp_point_init(&k2_pubkey);
    ret = mbedtls_ecp_point_read_binary(&grp, &k2_pubkey, k2_pubkey_raw, 64);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to read K2 public key");
        mbedtls_ecp_point_free(&k2_pubkey);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Verify that K2 public key is on the curve
    ret = mbedtls_ecp_check_pubkey(&grp, &k2_pubkey);
    if (ret != 0) {
        ESP_LOGE(TAG, "K2 public key not on curve");
        mbedtls_ecp_point_free(&k2_pubkey);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Create the data that was signed: peer_pubkey + unsecure_iv
    uint8_t signed_data[80]; // 64 bytes pubkey + 16 bytes IV
    memcpy(signed_data, pubkey, 64);
    memcpy(signed_data + 64, unsecure_aes_iv_.data(), 16);

    // Hash the signed data with SHA256
    uint8_t hash[32];
    mbedtls_sha256(signed_data, sizeof(signed_data), hash, 0);

    // Read the signature (64 bytes: r and s components)
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    ret = mbedtls_mpi_read_binary(&r, signature, 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to read signature r component");
        mbedtls_mpi_free(&s);
        mbedtls_mpi_free(&r);
        mbedtls_ecp_point_free(&k2_pubkey);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    ret = mbedtls_mpi_read_binary(&s, signature + 32, 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to read signature s component");
        mbedtls_mpi_free(&s);
        mbedtls_mpi_free(&r);
        mbedtls_ecp_point_free(&k2_pubkey);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Verify the ECDSA signature
    ret = mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &k2_pubkey, &r, &s);

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&k2_pubkey);
    mbedtls_ecp_group_free(&grp);

    if (ret != 0) {
        ESP_LOGE(TAG, "ECDSA signature verification failed");
        return false;
    }

    ESP_LOGI(TAG, "Peer signature verified successfully");
    return true;
}

bool BluettiEncryption::generate_ephemeral_keypair() {
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load P-256 curve for key generation");
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "bluetti_ecdh";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to seed RNG");
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Generate ephemeral keypair
    mbedtls_ecp_point pubkey;
    mbedtls_mpi privkey;
    mbedtls_ecp_point_init(&pubkey);
    mbedtls_mpi_init(&privkey);

    ret = mbedtls_ecp_gen_keypair(&grp, &privkey, &pubkey,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);

    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to generate ephemeral keypair");
        mbedtls_mpi_free(&privkey);
        mbedtls_ecp_point_free(&pubkey);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Export private key
    ret = mbedtls_mpi_write_binary(&privkey, my_privkey_.data(), 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to export private key");
        mbedtls_mpi_free(&privkey);
        mbedtls_ecp_point_free(&pubkey);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Export public key (compressed format without 0x04 prefix, just X and Y
    // coordinates)
    uint8_t pubkey_full[65];
    size_t pubkey_len = sizeof(pubkey_full);
    ret = mbedtls_ecp_point_write_binary(
        &grp, &pubkey, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubkey_len, pubkey_full,
        sizeof(pubkey_full));
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to export public key");
        mbedtls_mpi_free(&privkey);
        mbedtls_ecp_point_free(&pubkey);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Copy without the 0x04 prefix
    memcpy(my_pubkey_.data(), pubkey_full + 1, 64);
    my_keypair_set_ = true;

    mbedtls_mpi_free(&privkey);
    mbedtls_ecp_point_free(&pubkey);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ecp_group_free(&grp);

    ESP_LOGI(TAG, "Ephemeral keypair generated");
    return true;
}

bool BluettiEncryption::derive_secure_key() {
    if (!my_keypair_set_ || !peer_pubkey_set_) {
        ESP_LOGE(TAG,
                 "Cannot derive secure key: missing keypair or peer pubkey");
        return false;
    }

    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load P-256 curve for ECDH");
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Load our private key
    mbedtls_mpi privkey;
    mbedtls_mpi_init(&privkey);
    ret = mbedtls_mpi_read_binary(&privkey, my_privkey_.data(), 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to read private key");
        mbedtls_mpi_free(&privkey);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Load peer public key
    mbedtls_ecp_point peer_pubkey;
    mbedtls_ecp_point_init(&peer_pubkey);
    uint8_t peer_pubkey_full[65];
    peer_pubkey_full[0] = 0x04; // Uncompressed point prefix
    memcpy(peer_pubkey_full + 1, peer_pubkey_.data(), 64);

    ret =
        mbedtls_ecp_point_read_binary(&grp, &peer_pubkey, peer_pubkey_full, 65);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to read peer public key");
        mbedtls_ecp_point_free(&peer_pubkey);
        mbedtls_mpi_free(&privkey);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Perform ECDH: shared_secret = privkey * peer_pubkey
    mbedtls_ecp_point shared_secret;
    mbedtls_ecp_point_init(&shared_secret);
    ret = mbedtls_ecp_mul(&grp, &shared_secret, &privkey, &peer_pubkey, nullptr,
                          nullptr);
    if (ret != 0) {
        ESP_LOGE(TAG, "ECDH multiplication failed");
        mbedtls_ecp_point_free(&shared_secret);
        mbedtls_ecp_point_free(&peer_pubkey);
        mbedtls_mpi_free(&privkey);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Export shared secret point to binary (65 bytes: 0x04 + X + Y)
    uint8_t shared_point[65];
    size_t shared_len = sizeof(shared_point);
    ret = mbedtls_ecp_point_write_binary(
        &grp, &shared_secret, MBEDTLS_ECP_PF_UNCOMPRESSED, &shared_len,
        shared_point, sizeof(shared_point));
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to export shared secret point");
        mbedtls_ecp_point_free(&shared_secret);
        mbedtls_ecp_point_free(&peer_pubkey);
        mbedtls_mpi_free(&privkey);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Extract X coordinate (bytes 1-32 after the 0x04 prefix)
    memcpy(secure_aes_key_.data(), shared_point + 1, 32);
    secure_aes_key_set_ = true;

    mbedtls_ecp_point_free(&shared_secret);
    mbedtls_ecp_point_free(&peer_pubkey);
    mbedtls_mpi_free(&privkey);
    mbedtls_ecp_group_free(&grp);

    ESP_LOGI(TAG, "Secure AES key derived via ECDH");
    return true;
}

bool BluettiEncryption::handle_peer_pubkey(const uint8_t *data, size_t len,
                                           uint8_t *response,
                                           size_t *response_len) {
    if (len != PEER_PUBKEY_PAYLOAD_LEN) {
        ESP_LOGE(TAG, "Invalid peer pubkey payload length: %u", len);
        return false;
    }

    const uint8_t *pubkey = data;
    const uint8_t *signature = data + PUBKEY_LEN;

    // Verify peer signature
    if (!verify_peer_signature(pubkey, signature)) {
        return false;
    }

    // Store peer public key
    memcpy(peer_pubkey_.data(), pubkey, PUBKEY_LEN);
    peer_pubkey_set_ = true;

    ESP_LOGI(TAG, "Peer public key stored");

    // Generate our ephemeral keypair
    if (!generate_ephemeral_keypair()) {
        return false;
    }

    // Sign our public key with L1 private key
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load curve for signing");
        return false;
    }

    // Load L1 private key
    mbedtls_mpi l1_privkey;
    mbedtls_mpi_init(&l1_privkey);
    ret = mbedtls_mpi_read_binary(&l1_privkey, PRIVATE_KEY_L1.data(), 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to read L1 private key");
        mbedtls_mpi_free(&l1_privkey);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Compute L1 public key
    mbedtls_ecp_point l1_pubkey;
    mbedtls_ecp_point_init(&l1_pubkey);
    ret = mbedtls_ecp_mul(&grp, &l1_pubkey, &l1_privkey, &grp.G, nullptr,
                          nullptr);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to compute L1 public key");
        mbedtls_ecp_point_free(&l1_pubkey);
        mbedtls_mpi_free(&l1_privkey);
        mbedtls_ecp_group_free(&grp);
        return false;
    }

    // Create data to sign: my_pubkey + unsecure_iv
    uint8_t data_to_sign[80];
    memcpy(data_to_sign, my_pubkey_.data(), 64);
    memcpy(data_to_sign + 64, unsecure_aes_iv_.data(), 16);

    // Hash the data
    uint8_t hash[32];
    mbedtls_sha256(data_to_sign, sizeof(data_to_sign), hash, 0);

    // Sign with ECDSA
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "bluetti_sign";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)pers, strlen(pers));

    ret = mbedtls_ecdsa_sign(&grp, &r, &s, &l1_privkey, hash, sizeof(hash),
                             mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ecp_point_free(&l1_pubkey);
    mbedtls_mpi_free(&l1_privkey);
    mbedtls_ecp_group_free(&grp);

    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to sign with L1 key");
        mbedtls_mpi_free(&s);
        mbedtls_mpi_free(&r);
        return false;
    }

    // Build the response payload: my_pubkey + signature
    uint8_t payload[128]; // 64 bytes pubkey + 64 bytes signature
    memcpy(payload, my_pubkey_.data(), 64);
    mbedtls_mpi_write_binary(&r, payload + 64, 32);
    mbedtls_mpi_write_binary(&s, payload + 96, 32);

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);

    // Build KEX packet
    if (*response_len < 4 + sizeof(payload) + 2) {
        ESP_LOGE(TAG, "Response buffer too small");
        return false;
    }

    response[0] = KEX_MAGIC[0];
    response[1] = KEX_MAGIC[1];
    response[2] = LOCAL_PUBKEY_TYPE;
    response[3] = sizeof(payload);
    memcpy(response + 4, payload, sizeof(payload));

    // Calculate and append checksum
    uint16_t checksum = hexsum(response + 2, 4 + sizeof(payload));
    response[4 + sizeof(payload)] = (checksum >> 8) & 0xFF;
    response[4 + sizeof(payload) + 1] = checksum & 0xFF;

    *response_len = 4 + sizeof(payload) + 2;

    ESP_LOGI(TAG, "Local public key response built");
    return true;
}

bool BluettiEncryption::handle_pubkey_accepted(const uint8_t *data,
                                               size_t len) {
    if (len != 1 || data[0] != 0) {
        ESP_LOGE(TAG, "Invalid pubkey accepted response");
        return false;
    }

    // Derive secure key via ECDH
    if (!derive_secure_key()) {
        return false;
    }

    ESP_LOGI(TAG, "Encryption handshake complete - secure key established");
    return true;
}

bool BluettiEncryption::encrypt_modbus_command(const uint8_t *data, size_t len,
                                               uint8_t *output,
                                               size_t *output_len) {
    if (!secure_aes_key_set_) {
        ESP_LOGE(TAG, "Cannot encrypt: secure key not established");
        return false;
    }

    // Generate random IV seed
    uint8_t iv_seed[4];
    esp_fill_random(iv_seed, 4);

    // Derive IV from seed
    uint8_t iv[16];
    md5_hash_16(iv_seed, 4, iv);

    // Encrypt the data
    uint8_t encrypted[512];
    size_t encrypted_len;
    if (!aes_encrypt(data, len, secure_aes_key_.data(), 32, iv, encrypted,
                     &encrypted_len)) {
        return false;
    }

    // Build output: length_prefix(2) + iv_seed(4) + encrypted_data
    if (*output_len < 2 + 4 + encrypted_len) {
        ESP_LOGE(TAG, "Output buffer too small for encrypted command");
        return false;
    }

    output[0] = (len >> 8) & 0xFF;
    output[1] = len & 0xFF;
    memcpy(output + 2, iv_seed, 4);
    memcpy(output + 6, encrypted, encrypted_len);

    *output_len = 2 + 4 + encrypted_len;
    return true;
}

bool BluettiEncryption::decrypt_response(const uint8_t *data, size_t len,
                                         uint8_t *output, size_t *output_len) {
    if (len < 6) {
        ESP_LOGE(TAG, "Response too short to decrypt");
        return false;
    }

    // Parse length prefix
    uint16_t data_len = (static_cast<uint16_t>(data[0]) << 8) | data[1];

    uint8_t *decrypted;
    size_t decrypted_len;

    if (secure_aes_key_set_) {
        // Use secure key
        uint8_t iv[16];
        md5_hash_16(data + 2, 4, iv);

        decrypted = output;
        decrypted_len = *output_len;

        if (!aes_decrypt(data + 6, len - 6, secure_aes_key_.data(), 32, iv,
                         decrypted, &decrypted_len)) {
            return false;
        }
    } else if (unsecure_key_set_ && unsecure_iv_set_) {
        // Use unsecure key (during handshake)
        decrypted = output;
        decrypted_len = *output_len;

        if (!aes_decrypt(data + 2, len - 2, unsecure_aes_key_.data(), 16,
                         unsecure_aes_iv_.data(), decrypted, &decrypted_len)) {
            return false;
        }
    } else {
        ESP_LOGE(TAG, "Cannot decrypt: no keys available");
        return false;
    }

    // Verify decrypted length matches expected
    if (decrypted_len < data_len) {
        ESP_LOGW(TAG, "Decrypted data shorter than expected");
    }

    *output_len = decrypted_len;
    return true;
}

} // namespace bluetti_rust
} // namespace esphome
