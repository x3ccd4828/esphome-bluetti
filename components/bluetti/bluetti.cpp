#include "bluetti.h"

#include "esphome/core/log.h"

#include "esphome/core/hal.h"
#include <cstring>

namespace esphome::bluetti {
namespace {

constexpr const char *TAG = "bluetti";
bool is_kex(const uint8_t *data, size_t len) {
    return len >= 2 && data[0] == 0x2A && data[1] == 0x2A;
}
uint16_t read_be16(const uint8_t *data) {
    return static_cast<uint16_t>(data[0]) << 8 | data[1];
}

} // namespace

void Bluetti::setup() {
    ESP_LOGI(TAG, "Setting up Bluetti encryption");
#if defined(USE_RP2) && defined(USE_OTA_STATE_LISTENER)
    ota::get_global_ota_callback()->add_global_state_listener(this);
#endif
    this->reset_connection();
    this->set_interval("bluetti_poll", POLL_INTERVAL_MS,
                       [this]() { this->poll_next_register(); });
}

void Bluetti::dump_config() {
    ESP_LOGCONFIG(TAG, "Bluetti Encryption:");
    ESP_LOGCONFIG(TAG, "  Ready: %s", this->is_ready() ? "YES" : "NO");
}

void Bluetti::reset_connection() {
    notify_handle_ = write_handle_ = 0;
    poll_index_ = cached_pubkey_response_len_ = 0;
    this->reset_pending_read();
    ac_output_ = {};
    dc_output_ = {};
    battery_soc_ = dc_output_power_w_ = ac_output_power_w_ = dc_input_power_w_ =
        ac_input_power_w_ = ac_input_voltage_v_ = NAN;
    time_remaining_min_ = -1;
    crypto_ctx_.reset();
    if (!crypto_ctx_.precompute_ephemeral_keypair())
        ESP_LOGW(TAG, "Failed to precompute ephemeral keypair");
}

void Bluetti::process_notification(const uint8_t *data, size_t len) {
    if (data == nullptr || len < 2)
        return;
    if (is_kex(data, len)) {
        this->handle_kex_message(data, len, false);
        return;
    }
    size_t decrypted_len = sizeof(tx_buffer_);
    if (!crypto_ctx_.decrypt_response(data, len, tx_buffer_, &decrypted_len)) {
        ESP_LOGVV(TAG, "Ignoring encrypted notification (%u bytes)",
                  static_cast<unsigned>(len));
        return;
    }
    if (this->is_ready())
        this->handle_decrypted_response(tx_buffer_, decrypted_len);
    else if (is_kex(tx_buffer_, decrypted_len))
        this->handle_kex_message(tx_buffer_, decrypted_len, true);
}

void Bluetti::handle_kex_message(const uint8_t *data, size_t len,
                                 bool encrypted) {
    if (len < 6 || len < static_cast<size_t>(data[3]) + 6) {
        ESP_LOGW(TAG, "Malformed key exchange packet (%u bytes)",
                 static_cast<unsigned>(len));
        return;
    }
    const uint8_t type = data[2];
    const size_t payload_len = data[3];
    const uint8_t *payload = data + 4;
    size_t response_len = sizeof(tx_buffer_);
    bool success = false;
    switch (type) {
    case 0x01: // Challenge is sent in plaintext.
        if (encrypted)
            return;
        cached_pubkey_response_len_ = 0;
        success = crypto_ctx_.handle_challenge(payload, payload_len, tx_buffer_,
                                               &response_len);
        if (success)
            this->ble_write(tx_buffer_, response_len);
        break;
    case 0x03: // Challenge accepted.
        return;
    case 0x04: // Peer public key. Retry with exactly the same response.
        if (cached_pubkey_response_len_ != 0) {
            this->ble_write(cached_pubkey_response_,
                            cached_pubkey_response_len_);
            return;
        }
        success = crypto_ctx_.handle_peer_pubkey(payload, payload_len,
                                                 tx_buffer_, &response_len);
        if (success) {
            size_t cached_len = sizeof(cached_pubkey_response_);
            if (encrypted) {
                success = crypto_ctx_.encrypt_unsecure_kex(
                    tx_buffer_, response_len, cached_pubkey_response_,
                    &cached_len);
            } else {
                std::memcpy(cached_pubkey_response_, tx_buffer_, response_len);
                cached_len = response_len;
            }
            if (success) {
                cached_pubkey_response_len_ = cached_len;
                this->ble_write(cached_pubkey_response_, cached_len);
            }
        }
        break;
    case 0x06: // Public key accepted.
        success = crypto_ctx_.handle_pubkey_accepted(payload, payload_len);
        if (success) {
            cached_pubkey_response_len_ = 0;
            this->reset_pending_read();
            ESP_LOGI(TAG, "Encryption handshake complete");
        }
        break;
    default:
        ESP_LOGVV(TAG, "Unhandled key exchange type: 0x%02X", type);
        return;
    }
    if (!success)
        ESP_LOGW(TAG, "Key exchange failed (type=0x%02X)", type);
}

bool Bluetti::send_modbus_command(uint8_t function, uint16_t reg,
                                  uint16_t value) {
    if (!this->is_ready())
        return false;
    uint8_t command[8] = {0x01,
                          function,
                          static_cast<uint8_t>(reg >> 8),
                          static_cast<uint8_t>(reg),
                          static_cast<uint8_t>(value >> 8),
                          static_cast<uint8_t>(value),
                          0,
                          0};
    const uint16_t crc = modbus_crc16(command, 6);
    command[6] = static_cast<uint8_t>(crc);
    command[7] = static_cast<uint8_t>(crc >> 8);
    size_t len = sizeof(tx_buffer_);
    if (!crypto_ctx_.encrypt_modbus_command(command, sizeof(command),
                                            tx_buffer_, &len)) {
        ESP_LOGW(TAG, "Failed to encrypt MODBUS command");
        return false;
    }
    return this->ble_write(tx_buffer_, len);
}

bool Bluetti::set_ac_output(bool enabled) {
    return this->set_output(ac_output_, enabled, REG_CTRL_AC_OUTPUT, "AC");
}

bool Bluetti::set_dc_output(bool enabled) {
    return this->set_output(dc_output_, enabled, REG_CTRL_DC_OUTPUT, "DC");
}

bool Bluetti::set_output(OutputState &state, bool enabled, uint16_t reg,
                         const char *name) {
    if (!this->is_ready()) {
        ESP_LOGW(TAG, "Cannot toggle %s output before handshake is complete",
                 name);
        return false;
    }
    const uint32_t now = millis();
    if (state.last_toggle_ms != 0 &&
        now - state.last_toggle_ms < TOGGLE_DEBOUNCE_MS)
        return false;
    if (state.known && state.enabled == enabled && !state.pending)
        return true;
    if (pending_register_ != 0) {
        state.pending = true;
        state.pending_value = enabled;
        state.last_toggle_ms = now;
        ESP_LOGI(TAG, "Queued %s output toggle: %s", name,
                 enabled ? "ON" : "OFF");
        return true;
    }
    if (!this->write_output(state, enabled, reg, name))
        return false;
    state.last_toggle_ms = now;
    state.pending_value = enabled;
    return true;
}

bool Bluetti::write_output(OutputState &state, bool enabled, uint16_t reg,
                           const char *name) {
    if (!this->send_modbus_command(0x06, reg, enabled ? 1 : 0))
        return false;
    state.pending = false;
    ESP_LOGI(TAG, "%s output toggle requested: %s", name,
             enabled ? "ON" : "OFF");
    return true;
}

void Bluetti::poll_next_register() {
    if (write_handle_ == 0 || !this->is_connected() || !this->is_ready())
        return;
    const uint32_t now = millis();
    if (pending_register_ != 0) {
        if (now - pending_since_ms_ >= 3000) {
            ESP_LOGW(TAG, "MODBUS poll timeout on register %u; retrying",
                     pending_register_);
            this->reset_pending_read();
        }
        return;
    }
    if (ac_output_.pending) {
        this->write_output(ac_output_, ac_output_.pending_value,
                           REG_CTRL_AC_OUTPUT, "AC");
        return;
    }
    if (dc_output_.pending) {
        this->write_output(dc_output_, dc_output_.pending_value,
                           REG_CTRL_DC_OUTPUT, "DC");
        return;
    }
    const uint16_t reg = POLL_REGISTERS[poll_index_];
    if (this->send_modbus_command(0x03, reg, 1)) {
        pending_register_ = reg;
        pending_since_ms_ = now;
    }
}

void Bluetti::reset_pending_read() {
    // Queued writes belong to the connection, not to a single telemetry read.
    pending_register_ = 0;
    pending_since_ms_ = 0;
}

void Bluetti::handle_decrypted_response(const uint8_t *data, size_t len) {
    if (data == nullptr || len < 5 || data[0] != 0x01)
        return;
    const uint16_t crc = static_cast<uint16_t>(data[len - 2]) |
                         static_cast<uint16_t>(data[len - 1]) << 8;
    if (modbus_crc16(data, len - 2) != crc) {
        ESP_LOGW(TAG, "MODBUS CRC mismatch (register %u)", pending_register_);
        return;
    }
    if (data[1] == 0x06 && len >= 8) {
        this->apply_register_value(read_be16(data + 2), read_be16(data + 4));
        return;
    }
    if (data[1] == 0x83) {
        ESP_LOGW(TAG, "MODBUS exception for register %u (code=0x%02X)",
                 pending_register_, data[2]);
    } else {
        if (pending_register_ == 0 || data[1] != 0x03 || len < 7)
            return;
        if (data[2] < 2 || len < static_cast<size_t>(data[2]) + 5) {
            ESP_LOGW(TAG, "Malformed MODBUS response");
            return;
        }
        this->apply_register_value(pending_register_, read_be16(data + 3));
    }
    this->reset_pending_read();
    poll_index_ = (poll_index_ + 1) % POLL_REGISTER_COUNT;
}

void Bluetti::apply_register_value(uint16_t reg, uint16_t value) {
    switch (reg) {
    case REG_BATTERY_SOC:
        battery_soc_ = value;
        break;
    case REG_TIME_REMAINING:
        time_remaining_min_ = value;
        break;
    case REG_DC_OUTPUT_POWER:
        dc_output_power_w_ = value;
        break;
    case REG_AC_OUTPUT_POWER:
        ac_output_power_w_ = value;
        break;
    case REG_DC_INPUT_POWER:
        dc_input_power_w_ = value;
        break;
    case REG_AC_INPUT_POWER:
        ac_input_power_w_ = value;
        break;
    case REG_AC_INPUT_VOLTAGE:
        ac_input_voltage_v_ = value / 10.0f;
        break;
    case REG_CTRL_AC_OUTPUT:
        ac_output_.enabled = value != 0;
        ac_output_.known = true;
        break;
    case REG_CTRL_DC_OUTPUT:
        dc_output_.enabled = value != 0;
        dc_output_.known = true;
        break;
    default:
        break;
    }
}

uint16_t Bluetti::modbus_crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (uint8_t bit = 0; bit < 8; ++bit)
            crc = static_cast<uint16_t>((crc >> 1) ^ ((crc & 1) ? 0xA001 : 0));
    }
    return crc;
}

} // namespace esphome::bluetti
