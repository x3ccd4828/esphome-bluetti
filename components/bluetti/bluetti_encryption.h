#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace esphome::bluetti {

class BluettiEncryption {
  public:
    // A 134-byte public-key packet padded to 144 bytes, plus its length prefix.
    static constexpr size_t PUBKEY_RESPONSE_SIZE = 146;

    bool is_ready_for_commands() const { return secure_aes_key_set_; }
    void reset();
    bool precompute_ephemeral_keypair();
    bool handle_challenge(const uint8_t *data, size_t len, uint8_t *response,
                          size_t *response_len);
    bool handle_peer_pubkey(const uint8_t *data, size_t len, uint8_t *response,
                            size_t *response_len);
    bool handle_pubkey_accepted(const uint8_t *data, size_t len);
    bool encrypt_unsecure_kex(const uint8_t *data, size_t len, uint8_t *output,
                              size_t *output_len);
    bool encrypt_modbus_command(const uint8_t *data, size_t len,
                                uint8_t *output, size_t *output_len);
    bool decrypt_response(const uint8_t *data, size_t len, uint8_t *output,
                          size_t *output_len);

  private:
    std::array<uint8_t, 16> unsecure_aes_key_{};
    std::array<uint8_t, 16> unsecure_aes_iv_{};
    std::array<uint8_t, 32> secure_aes_key_{};
    std::array<uint8_t, 64> peer_pubkey_{};
    std::array<uint8_t, 32> my_privkey_{};
    std::array<uint8_t, 64> my_pubkey_{};
    bool unsecure_key_set_{false};
    bool secure_aes_key_set_{false};
    bool peer_pubkey_set_{false};
    bool my_keypair_set_{false};

    bool derive_secure_key();
};

} // namespace esphome::bluetti
