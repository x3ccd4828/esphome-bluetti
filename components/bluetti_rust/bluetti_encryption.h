#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace esphome {
namespace bluetti_rust {

// Constants from Rust implementation
constexpr uint8_t KEX_MAGIC[2] = {0x2A, 0x2A};
constexpr size_t AES_BLOCK_SIZE = 16;
constexpr size_t CHECKSUM_SIZE = 2;
constexpr size_t KEX_TYPE_OFFSET = 2;
constexpr size_t KEX_BODY_OFFSET = 2;
constexpr size_t KEX_DATA_OFFSET = 4;
constexpr size_t CHALLENGE_LEN = 4;
constexpr size_t PUBKEY_LEN = 64;
constexpr size_t SIGNATURE_LEN = 64;
constexpr size_t PEER_PUBKEY_PAYLOAD_LEN = PUBKEY_LEN + SIGNATURE_LEN;
constexpr size_t SEC1_UNCOMPRESSED_PUBKEY_LEN = PUBKEY_LEN + 1;
constexpr uint8_t SEC1_UNCOMPRESSED_TAG = 0x04;
constexpr uint8_t CHALLENGE_RESPONSE_TYPE = 0x02;
constexpr uint8_t LOCAL_PUBKEY_TYPE = 0x05;
constexpr size_t CHALLENGE_IV_RESPONSE_START = 8;
constexpr size_t CHALLENGE_IV_RESPONSE_END = 12;
constexpr std::array<uint8_t, 4> IV_SEED = {0x12, 0x34, 0x56, 0x78};

// Hardcoded keys from Rust
constexpr std::array<uint8_t, 16> LOCAL_AES_KEY = {
    0x45, 0x9F, 0xC5, 0x35, 0x80, 0x89, 0x41, 0xF1,
    0x70, 0x91, 0xE0, 0x99, 0x3E, 0xE3, 0xE9, 0x3D};

constexpr std::array<uint8_t, 32> PRIVATE_KEY_L1 = {
    0x4F, 0x19, 0xA1, 0x6E, 0x3E, 0x87, 0xBD, 0xD9, 0xBD, 0x24, 0xD3,
    0xE5, 0x49, 0x5B, 0x88, 0x04, 0x15, 0x11, 0x94, 0x3C, 0xBC, 0x8B,
    0x96, 0x9A, 0xDE, 0x96, 0x41, 0xD0, 0xF5, 0x6A, 0xF3, 0x37};

// K2 public key (SECP256R1/X9.62 uncompressed format)
constexpr std::array<uint8_t, 91> PUBLIC_KEY_K2_BYTES = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
    0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xA7, 0x3A, 0xBF, 0x5D, 0x22, 0x32, 0xC8, 0xC1, 0xC7,
    0x2E, 0x68, 0x30, 0x43, 0x43, 0xC2, 0x72, 0x49, 0x5E, 0x3A, 0x8F, 0xD6,
    0xF3, 0x0E, 0xA9, 0x6D, 0xE2, 0xF4, 0xB3, 0xCE, 0x60, 0xB2, 0x51, 0xEE,
    0x21, 0xAC, 0x66, 0x7C, 0xF8, 0xA7, 0x1E, 0x18, 0xB4, 0x6B, 0x66, 0x4E,
    0xAE, 0xFF, 0xE3, 0xC4, 0x89, 0xF2, 0x4F, 0x69, 0x5B, 0x64, 0x11, 0xDB,
    0x7E, 0x22, 0xCC, 0xC8, 0x5A, 0x85, 0x94};

// Message types
enum class MessageType : uint8_t {
    Challenge = 1,
    ChallengeAccepted = 3,
    PeerPubkey = 4,
    PubkeyAccepted = 6,
};

// Message parser class
class BluettiMessage {
  public:
    explicit BluettiMessage(const uint8_t *buffer, size_t len);

    bool is_pre_key_exchange() const;
    MessageType message_type() const;
    const uint8_t *data() const;
    const uint8_t *body() const;
    bool verify_checksum() const;
    size_t data_len() const { return data_len_; }
    size_t body_len() const { return body_len_; }

  private:
    const uint8_t *buffer_;
    size_t len_;
    size_t data_len_;
    size_t body_len_;
};

// Main encryption class
class BluettiEncryption {
  public:
    BluettiEncryption();

    // State checks
    bool is_ready_for_commands() const {
        return secure_aes_key_set_ && peer_pubkey_set_;
    }
    void reset();

    // Key exchange handlers
    bool precompute_ephemeral_keypair();
    bool handle_challenge(const uint8_t *data, size_t len, uint8_t *response,
                          size_t *response_len);
    bool handle_peer_pubkey(const uint8_t *data, size_t len, uint8_t *response,
                            size_t *response_len);
    bool handle_pubkey_accepted(const uint8_t *data, size_t len);

    // Encryption/Decryption
    bool encrypt_unsecure_kex(const uint8_t *data, size_t len, uint8_t *output,
                              size_t *output_len);
    bool encrypt_modbus_command(const uint8_t *data, size_t len,
                                uint8_t *output, size_t *output_len);
    bool decrypt_response(const uint8_t *data, size_t len, uint8_t *output,
                          size_t *output_len);

    // Utility
    static void md5_hash_16(const uint8_t *input, size_t len, uint8_t *output);
    static void xor_16(const uint8_t *a, const uint8_t *b, uint8_t *output);
    static void zero_pad(const uint8_t *data, size_t len, uint8_t *output,
                         size_t *out_len);
    static uint16_t hexsum(const uint8_t *data, size_t len);

  private:
    // State
    std::array<uint8_t, 16> unsecure_aes_key_;
    std::array<uint8_t, 16> unsecure_aes_iv_;
    std::array<uint8_t, 32> secure_aes_key_;
    std::array<uint8_t, 64>
        peer_pubkey_; // Raw 64-byte pubkey (without 0x04 prefix)
    std::array<uint8_t, 32> my_privkey_; // Ephemeral private key
    std::array<uint8_t, 64> my_pubkey_;  // Ephemeral public key

    bool unsecure_key_set_ = false;
    bool unsecure_iv_set_ = false;
    bool secure_aes_key_set_ = false;
    bool peer_pubkey_set_ = false;
    bool my_keypair_set_ = false;

    // Helpers
    bool verify_peer_signature(const uint8_t *pubkey, const uint8_t *signature);
    bool generate_ephemeral_keypair();
    bool derive_secure_key();

    // AES operations
    bool aes_encrypt(const uint8_t *data, size_t len, const uint8_t *key,
                     size_t key_len, const uint8_t *iv, uint8_t *output,
                     size_t *output_len);
    bool aes_decrypt(const uint8_t *data, size_t len, const uint8_t *key,
                     size_t key_len, const uint8_t *iv, uint8_t *output,
                     size_t *output_len);
};

} // namespace bluetti_rust
} // namespace esphome
