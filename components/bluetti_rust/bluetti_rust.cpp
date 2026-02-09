#include "bluetti_rust.h"

#include "esphome/core/log.h"

#include <cstring>
#include <esp_random.h>
#include <esp_timer.h>

namespace esphome {
namespace bluetti_rust {

static const char *const TAG = "bluetti_rust";

BluettiRust::~BluettiRust() {
    if (this->rust_ctx_ != nullptr) {
        bluetti_free(this->rust_ctx_);
        this->rust_ctx_ = nullptr;
    }
}

void BluettiRust::setup() {
    ESP_LOGI(TAG, "Setting up Bluetti Rust wrapper");

    this->rust_ctx_ = bluetti_init();
    if (this->rust_ctx_ == nullptr) {
        ESP_LOGE(TAG, "bluetti_init failed");
        return;
    }

    const int32_t rc = bluetti_set_random_callback(
        this->rust_ctx_, &BluettiRust::random_callback, this);
    if (rc != BLUETTI_FFI_OK) {
        ESP_LOGE(TAG, "bluetti_set_random_callback failed: %d", rc);
    }

    this->mark_metrics_unavailable();
    this->reset_poll_state();

    this->set_interval("bluetti_poll", POLL_INTERVAL_MS,
                       [this]() { this->poll_next_register(); });
}

void BluettiRust::dump_config() {
    ESP_LOGCONFIG(TAG, "Bluetti Rust:");
    ESP_LOGCONFIG(TAG, "  Context: %s",
                  this->rust_ctx_ != nullptr ? "OK" : "NULL");
    ESP_LOGCONFIG(TAG, "  Ready: %s", this->is_ready() ? "YES" : "NO");
}

bool BluettiRust::is_ready() const {
    return this->rust_ctx_ != nullptr && bluetti_is_ready(this->rust_ctx_);
}

void BluettiRust::gattc_event_handler(esp_gattc_cb_event_t event,
                                      esp_gatt_if_t gattc_if,
                                      esp_ble_gattc_cb_param_t *param) {
    (void)gattc_if;

    switch (event) {
    case ESP_GATTC_OPEN_EVT:
        if (param->open.status == ESP_GATT_OK) {
            ESP_LOGI(TAG, "Connected to Bluetti device");
        }
        break;

    case ESP_GATTC_DISCONNECT_EVT:
        ESP_LOGI(TAG, "Disconnected from Bluetti");
        this->notify_handle_ = 0;
        this->write_handle_ = 0;
        this->mark_metrics_unavailable();
        this->reset_poll_state();
        this->poll_index_ = 0;

        if (this->rust_ctx_ != nullptr) {
            bluetti_free(this->rust_ctx_);
            this->rust_ctx_ = nullptr;
        }

        this->rust_ctx_ = bluetti_init();
        if (this->rust_ctx_ == nullptr) {
            ESP_LOGE(TAG, "bluetti_init failed after disconnect");
            break;
        }

        if (bluetti_set_random_callback(this->rust_ctx_,
                                        &BluettiRust::random_callback,
                                        this) != BLUETTI_FFI_OK) {
            ESP_LOGE(TAG,
                     "bluetti_set_random_callback failed after disconnect");
        }
        break;

    case ESP_GATTC_SEARCH_CMPL_EVT:
        this->subscribe_notifications();
        break;

    case ESP_GATTC_REG_FOR_NOTIFY_EVT:
        if (param->reg_for_notify.status == ESP_GATT_OK) {
            ESP_LOGI(TAG, "Notification subscription active");
        }
        break;

    case ESP_GATTC_NOTIFY_EVT:
        if (param->notify.handle == this->notify_handle_) {
            this->process_notification(param->notify.value,
                                       param->notify.value_len);
        }
        break;

    case ESP_GATTC_WRITE_CHAR_EVT:
        if (param->write.status != ESP_GATT_OK) {
            ESP_LOGW(TAG, "Write char failed status=%d handle=%u",
                     param->write.status, param->write.handle);
        }
        break;

    default:
        break;
    }
}

void BluettiRust::subscribe_notifications() {
    auto *notify_chr = this->parent_->get_characteristic(
        this->service_uuid_, this->notify_char_uuid_);
    if (notify_chr == nullptr) {
        ESP_LOGE(TAG, "Notify characteristic not found");
        return;
    }

    this->notify_handle_ = notify_chr->handle;
    esp_ble_gattc_register_for_notify(this->parent_->get_gattc_if(),
                                      this->parent_->get_remote_bda(),
                                      notify_chr->handle);

    uint16_t notify_en = 0x0001;
    esp_ble_gattc_write_char_descr(
        this->parent_->get_gattc_if(), this->parent_->get_conn_id(),
        notify_chr->handle + 1, 2, reinterpret_cast<uint8_t *>(&notify_en),
        ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);

    auto *write_chr = this->parent_->get_characteristic(this->service_uuid_,
                                                        this->write_char_uuid_);
    if (write_chr == nullptr) {
        ESP_LOGE(TAG, "Write characteristic not found");
        return;
    }

    this->write_handle_ = write_chr->handle;
    ESP_LOGI(TAG, "Write characteristic found");
}

void BluettiRust::process_notification(const uint8_t *data, size_t len) {
    if (this->rust_ctx_ == nullptr || data == nullptr || len < 2) {
        return;
    }

    ESP_LOGVV(TAG, "Notify RX (%u bytes): %02X %02X",
              static_cast<unsigned>(len), data[0], data[1]);

    // Handle plain KEX messages (starts with magic bytes)
    if (data[0] == KEX_MAGIC_0 && data[1] == KEX_MAGIC_1) {
        if (len < 3) {
            return;
        }
        this->handle_kex_message(data, len);
        return;
    }

    // Handle encrypted messages
    this->handle_encrypted_message(data, len);
}

void BluettiRust::handle_kex_message(const uint8_t *data, size_t len) {
    size_t out_len = sizeof(this->tx_buffer_);
    int32_t rc = BLUETTI_FFI_ERR_INVALID_INPUT;

    switch (data[2]) {
    case 0x01: // Challenge
        this->awaiting_pubkey_accepted_ = false;
        this->cached_pubkey_response_len_ = 0;
        rc = bluetti_handle_challenge(this->rust_ctx_, data, len,
                                      this->tx_buffer_, &out_len);
        if (rc == BLUETTI_FFI_OK && out_len > 0) {
            if (!this->ble_write(this->tx_buffer_, out_len)) {
                ESP_LOGW(TAG, "Failed to write challenge response");
            }
        }
        break;

    case 0x03: // Challenge accepted
        ESP_LOGVV(TAG, "Challenge accepted");
        return;

    case 0x04: // Peer pubkey
        if (this->awaiting_pubkey_accepted_ &&
            this->cached_pubkey_response_len_ > 0) {
            ESP_LOGVV(TAG, "Duplicate peer pubkey; resending cached response");
            if (!this->ble_write(this->cached_pubkey_response_,
                                 this->cached_pubkey_response_len_)) {
                ESP_LOGW(TAG, "Failed to resend cached peer pubkey response");
            }
            return;
        }

        rc = bluetti_handle_peer_pubkey(this->rust_ctx_, data, len,
                                        this->tx_buffer_, &out_len);
        if (rc == BLUETTI_FFI_OK && out_len > 0) {
            std::memcpy(this->cached_pubkey_response_, this->tx_buffer_,
                        out_len);
            this->cached_pubkey_response_len_ = out_len;
            this->awaiting_pubkey_accepted_ = true;
            if (!this->ble_write(this->tx_buffer_, out_len)) {
                ESP_LOGW(TAG, "Failed to write peer pubkey response");
            }
        }
        break;

    case 0x06: // Pubkey accepted
        rc = bluetti_handle_pubkey_accepted(this->rust_ctx_, data, len);
        if (rc == BLUETTI_FFI_OK && this->is_ready()) {
            ESP_LOGI(TAG, "Encryption handshake complete");
            this->reset_poll_state();
        }
        break;

    default:
        ESP_LOGVV(TAG, "Unhandled plain KEX message type: 0x%02X", data[2]);
        return;
    }

    if (rc != BLUETTI_FFI_OK) {
        ESP_LOGW(TAG, "Rust FFI call failed (msg=0x%02X rc=%d)", data[2], rc);
    }
}

void BluettiRust::handle_encrypted_message(const uint8_t *data, size_t len) {
    size_t out_len = sizeof(this->tx_buffer_);
    int32_t rc = bluetti_decrypt_response(this->rust_ctx_, data, len,
                                          this->tx_buffer_, &out_len);

    if (rc != BLUETTI_FFI_OK) {
        ESP_LOGVV(TAG, "Ignoring encrypted notification (%u bytes)",
                  static_cast<unsigned>(len));
        return;
    }

    // If not ready, handle KEX inside encrypted message
    if (!this->is_ready()) {
        if (out_len < 3 || this->tx_buffer_[0] != KEX_MAGIC_0 ||
            this->tx_buffer_[1] != KEX_MAGIC_1) {
            ESP_LOGVV(TAG, "Ignoring encrypted notification (%u bytes)",
                      static_cast<unsigned>(len));
            return;
        }

        this->handle_encrypted_kex(out_len);
        return;
    }

    // Ready - handle as MODBUS response
    this->handle_decrypted_response(this->tx_buffer_, out_len);
}

void BluettiRust::handle_encrypted_kex(size_t decrypted_len) {
    const uint8_t kex_type = this->tx_buffer_[2];
    int32_t rc = BLUETTI_FFI_OK;

    switch (kex_type) {
    case 0x04: {
        if (this->awaiting_pubkey_accepted_ &&
            this->cached_pubkey_response_len_ > 0) {
            ESP_LOGVV(
                TAG,
                "Duplicate encrypted peer pubkey; resending cached response");
            if (!this->ble_write(this->cached_pubkey_response_,
                                 this->cached_pubkey_response_len_)) {
                ESP_LOGW(
                    TAG,
                    "Failed to resend cached encrypted peer pubkey response");
            }
            return;
        }

        size_t response_len = sizeof(this->tx_buffer_);
        rc = bluetti_handle_peer_pubkey(this->rust_ctx_, this->tx_buffer_,
                                        decrypted_len, this->tx_buffer_,
                                        &response_len);
        if (rc == BLUETTI_FFI_OK && response_len > 0) {
            std::memcpy(this->cached_pubkey_response_, this->tx_buffer_,
                        response_len);
            this->cached_pubkey_response_len_ = response_len;
            this->awaiting_pubkey_accepted_ = true;
            if (!this->ble_write(this->tx_buffer_, response_len)) {
                ESP_LOGW(TAG,
                         "Failed to write encrypted local pubkey response");
            }
        } else {
            ESP_LOGW(TAG, "Peer pubkey handling failed (rc=%d)", rc);
        }
        return;
    }

    case 0x06:
        rc = bluetti_handle_pubkey_accepted(this->rust_ctx_, this->tx_buffer_,
                                            decrypted_len);
        if (rc == BLUETTI_FFI_OK && this->is_ready()) {
            ESP_LOGI(TAG, "Encryption handshake complete");
            this->awaiting_pubkey_accepted_ = false;
            this->cached_pubkey_response_len_ = 0;
        } else if (rc != BLUETTI_FFI_OK) {
            ESP_LOGW(TAG, "Pubkey accepted handling failed (rc=%d)", rc);
        }
        return;

    default:
        ESP_LOGVV(TAG, "Unhandled decrypted KEX message type: 0x%02X",
                  kex_type);
        return;
    }
}

bool BluettiRust::ble_write(const uint8_t *data, size_t len) {
    if (this->write_handle_ == 0) {
        ESP_LOGE(TAG, "Write handle is not initialized");
        return false;
    }

    const esp_err_t err = esp_ble_gattc_write_char(
        this->parent_->get_gattc_if(), this->parent_->get_conn_id(),
        this->write_handle_, len, const_cast<uint8_t *>(data),
        ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "GATT write failed: %d", static_cast<int>(err));
        return false;
    }

    ESP_LOGVV(TAG, "TX (%u bytes): %02X %02X", static_cast<unsigned>(len),
              len > 0 ? data[0] : 0, len > 1 ? data[1] : 0);

    return true;
}

bool BluettiRust::send_modbus_command(const uint8_t *data, size_t len) {
    if (this->rust_ctx_ == nullptr || data == nullptr || len == 0) {
        return false;
    }

    if (!this->is_ready()) {
        ESP_LOGW(TAG, "Cannot send command before handshake is complete");
        return false;
    }

    size_t out_len = sizeof(this->tx_buffer_);
    const int32_t rc = bluetti_encrypt_command(this->rust_ctx_, data, len,
                                               this->tx_buffer_, &out_len);
    if (rc != BLUETTI_FFI_OK || out_len == 0) {
        ESP_LOGW(TAG, "Failed to encrypt MODBUS command (rc=%d)", rc);
        return false;
    }

    if (!this->ble_write(this->tx_buffer_, out_len)) {
        ESP_LOGW(TAG, "Failed to send encrypted MODBUS command");
        return false;
    }

    return true;
}

bool BluettiRust::set_output(const OutputConfig &cfg, bool enabled) {
    if (this->rust_ctx_ == nullptr || !this->is_ready()) {
        ESP_LOGW(TAG, "Cannot toggle %s output before handshake is complete",
                 cfg.name);
        return false;
    }

    const uint32_t now_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000);
    const uint32_t elapsed = now_ms - cfg.last_toggle_ms;
    if (cfg.last_toggle_ms != 0 && elapsed < cfg.debounce_ms) {
        ESP_LOGW(TAG, "Ignoring %s output toggle due to debounce (%u ms)",
                 cfg.name, static_cast<unsigned>(elapsed));
        return false;
    }

    if (cfg.state_known && cfg.enabled == enabled && !cfg.pending) {
        ESP_LOGI(TAG, "%s output already %s", cfg.name, enabled ? "ON" : "OFF");
        return true;
    }

    if (this->pending_register_ != 0) {
        cfg.pending = true;
        cfg.pending_value = enabled;
        cfg.last_toggle_ms = now_ms;
        ESP_LOGI(TAG, "Queued %s output toggle: %s", cfg.name,
                 enabled ? "ON" : "OFF");
        return true;
    }

    size_t cmd_len = sizeof(this->cmd_buffer_);
    const uint16_t value = enabled ? 1 : 0;
    if (!this->build_write_register_command(cfg.reg, value, this->cmd_buffer_,
                                            &cmd_len)) {
        ESP_LOGW(TAG, "Failed to build %s output write command", cfg.name);
        return false;
    }

    if (!this->send_modbus_command(this->cmd_buffer_, cmd_len)) {
        ESP_LOGW(TAG, "Failed to send %s output write command", cfg.name);
        return false;
    }

    cfg.pending = false;
    cfg.pending_value = enabled;
    cfg.last_toggle_ms = now_ms;
    ESP_LOGI(TAG, "%s output toggle requested: %s", cfg.name,
             enabled ? "ON" : "OFF");
    return true;
}

bool BluettiRust::set_ac_output(bool enabled) {
    OutputConfig cfg{
        .name = "AC",
        .reg = REG_CTRL_AC_OUTPUT,
        .debounce_ms = AC_TOGGLE_DEBOUNCE_MS,
        .last_toggle_ms = this->last_ac_toggle_request_ms_,
        .state_known = this->ac_output_state_known_,
        .enabled = this->ac_output_enabled_,
        .pending = this->pending_ac_toggle_,
        .pending_value = this->pending_ac_toggle_value_,
    };
    return this->set_output(cfg, enabled);
}

bool BluettiRust::set_dc_output(bool enabled) {
    OutputConfig cfg{
        .name = "DC",
        .reg = REG_CTRL_DC_OUTPUT,
        .debounce_ms = DC_TOGGLE_DEBOUNCE_MS,
        .last_toggle_ms = this->last_dc_toggle_request_ms_,
        .state_known = this->dc_output_state_known_,
        .enabled = this->dc_output_enabled_,
        .pending = this->pending_dc_toggle_,
        .pending_value = this->pending_dc_toggle_value_,
    };
    return this->set_output(cfg, enabled);
}

void BluettiRust::poll_next_register() {
    const uint32_t now_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000);

    if (this->rust_ctx_ == nullptr || this->write_handle_ == 0 ||
        !this->parent_->connected() || !this->is_ready()) {
        return;
    }

    if (this->pending_register_ != 0) {
        if (now_ms - this->pending_since_ms_ < 3000) {
            return;
        }

        ESP_LOGW(TAG, "MODBUS poll timeout on register %u; retrying next",
                 this->pending_register_);
        this->reset_poll_state();
        return;
    }

    // Handle pending toggles
    if (this->pending_ac_toggle_) {
        this->process_pending_toggle("AC", REG_CTRL_AC_OUTPUT,
                                     this->pending_ac_toggle_value_,
                                     this->pending_ac_toggle_);
        return;
    }

    if (this->pending_dc_toggle_) {
        this->process_pending_toggle("DC", REG_CTRL_DC_OUTPUT,
                                     this->pending_dc_toggle_value_,
                                     this->pending_dc_toggle_);
        return;
    }

    const uint16_t reg_addr = this->poll_registers_[this->poll_index_];
    size_t cmd_len = sizeof(this->cmd_buffer_);
    if (!this->build_read_register_command(reg_addr, 1, this->cmd_buffer_,
                                           &cmd_len)) {
        ESP_LOGW(TAG, "Failed to build MODBUS read command for register %u",
                 reg_addr);
        return;
    }

    if (this->send_modbus_command(this->cmd_buffer_, cmd_len)) {
        this->pending_register_ = reg_addr;
        this->pending_since_ms_ = now_ms;
        ESP_LOGVV(
            TAG,
            "Polling register %u (cmd=%02X %02X %02X %02X %02X %02X %02X %02X)",
            reg_addr, this->cmd_buffer_[0], this->cmd_buffer_[1],
            this->cmd_buffer_[2], this->cmd_buffer_[3], this->cmd_buffer_[4],
            this->cmd_buffer_[5], this->cmd_buffer_[6], this->cmd_buffer_[7]);
    } else {
        ESP_LOGW(TAG, "Failed to send MODBUS read for register %u", reg_addr);
    }
}

void BluettiRust::process_pending_toggle(const char *name, uint16_t reg,
                                         bool value, bool &pending_flag) {
    size_t cmd_len = sizeof(this->cmd_buffer_);
    const uint16_t int_value = value ? 1 : 0;
    if (!this->build_write_register_command(reg, int_value, this->cmd_buffer_,
                                            &cmd_len)) {
        ESP_LOGW(TAG, "Failed to build queued %s output write command", name);
        return;
    }

    if (!this->send_modbus_command(this->cmd_buffer_, cmd_len)) {
        ESP_LOGW(TAG, "Failed to send queued %s output write command", name);
        return;
    }

    pending_flag = false;
    ESP_LOGI(TAG, "%s output toggle requested: %s", name, value ? "ON" : "OFF");
}

bool BluettiRust::build_read_register_command(uint16_t reg_addr,
                                              uint16_t quantity, uint8_t *out,
                                              size_t *out_len) const {
    return this->build_modbus_command(0x03, reg_addr, quantity, out, out_len);
}

bool BluettiRust::build_write_register_command(uint16_t reg_addr,
                                               uint16_t value, uint8_t *out,
                                               size_t *out_len) const {
    return this->build_modbus_command(0x06, reg_addr, value, out, out_len);
}

bool BluettiRust::build_modbus_command(uint8_t func_code, uint16_t reg_addr,
                                       uint16_t value, uint8_t *out,
                                       size_t *out_len) const {
    if (out == nullptr || out_len == nullptr || *out_len < 8) {
        return false;
    }

    out[0] = 0x01;
    out[1] = func_code;
    out[2] = static_cast<uint8_t>(reg_addr >> 8);
    out[3] = static_cast<uint8_t>(reg_addr & 0xFF);
    out[4] = static_cast<uint8_t>(value >> 8);
    out[5] = static_cast<uint8_t>(value & 0xFF);

    const uint16_t crc = modbus_crc16(out, 6);
    out[6] = static_cast<uint8_t>(crc & 0xFF);
    out[7] = static_cast<uint8_t>(crc >> 8);
    *out_len = 8;

    return true;
}

void BluettiRust::mark_metrics_unavailable() {
    this->battery_soc_ = NAN;
    this->time_remaining_min_ = -1;
    this->dc_output_power_w_ = NAN;
    this->ac_output_power_w_ = NAN;
    this->dc_input_power_w_ = NAN;
    this->ac_input_power_w_ = NAN;
    this->ac_input_voltage_v_ = NAN;
    this->ac_output_enabled_ = false;
    this->ac_output_state_known_ = false;
    this->dc_output_enabled_ = false;
    this->dc_output_state_known_ = false;
}

void BluettiRust::reset_poll_state() {
    this->pending_register_ = 0;
    this->pending_since_ms_ = 0;
    // Don't reset poll_index_ here - it should advance after successful reads
    this->pending_ac_toggle_ = false;
    this->pending_ac_toggle_value_ = false;
    this->pending_dc_toggle_ = false;
    this->pending_dc_toggle_value_ = false;
    this->awaiting_pubkey_accepted_ = false;
    this->cached_pubkey_response_len_ = 0;
}

void BluettiRust::handle_decrypted_response(const uint8_t *data, size_t len) {
    if (data == nullptr || len < 5) {
        ESP_LOGV(TAG, "Response too short: %u bytes",
                 static_cast<unsigned>(len));
        return;
    }

    ESP_LOGVV(TAG, "RX (%u bytes): %02X %02X ... %02X %02X",
              static_cast<unsigned>(len), data[0], data[1], data[len - 2],
              data[len - 1]);

    const uint16_t crc_expected = modbus_crc16(data, len - 2);
    const uint16_t crc_actual = static_cast<uint16_t>(data[len - 2]) |
                                static_cast<uint16_t>(data[len - 1] << 8);
    if (crc_expected != crc_actual) {
        ESP_LOGW(TAG, "CRC mismatch: reg=%u expected=%04X actual=%04X",
                 this->pending_register_, crc_expected, crc_actual);
        return;
    }

    if (data[1] == 0x06 && len >= 8) {
        const uint16_t reg_addr = static_cast<uint16_t>(data[2] << 8) | data[3];
        const uint16_t value = static_cast<uint16_t>(data[4] << 8) | data[5];
        this->apply_register_value(reg_addr, value);
        ESP_LOGI(TAG, "Write acknowledged for register %u => %u", reg_addr,
                 value);
        return;
    }

    if (data[1] == 0x83) {
        const uint8_t ex = len >= 5 ? data[2] : 0;
        ESP_LOGW(TAG, "MODBUS exception for register %u (code=0x%02X)",
                 this->pending_register_, ex);
        this->reset_poll_state();
        this->poll_index_ = (this->poll_index_ + 1) % POLL_REGISTER_COUNT;
        return;
    }

    if (this->pending_register_ == 0) {
        ESP_LOGV(TAG, "Ignoring unsolicited response");
        return;
    }

    uint16_t value = 0;
    if (len >= 7 && data[1] == 0x03) {
        const uint8_t byte_count = data[2];
        if (byte_count < 2 || len < static_cast<size_t>(byte_count) + 5) {
            ESP_LOGW(TAG, "Malformed response: reg=%u byte_count=%u len=%u",
                     this->pending_register_, byte_count,
                     static_cast<unsigned>(len));
            return;
        }
        value = static_cast<uint16_t>(data[3] << 8) | data[4];
        ESP_LOGV(TAG, "Read reg=%u value=%u", this->pending_register_, value);
    } else if (len >= 7) {
        value = static_cast<uint16_t>(data[3] << 8) | data[4];
    } else {
        ESP_LOGV(TAG, "Short response (%u bytes) for register %u",
                 static_cast<unsigned>(len), this->pending_register_);
        return;
    }

    this->apply_register_value(this->pending_register_, value);
    this->reset_poll_state();
    this->poll_index_ = (this->poll_index_ + 1) % POLL_REGISTER_COUNT;
}

void BluettiRust::apply_register_value(uint16_t reg_addr, uint16_t value) {
    switch (reg_addr) {
    case REG_BATTERY_SOC:
        this->battery_soc_ = static_cast<float>(value);
        break;
    case REG_TIME_REMAINING:
        this->time_remaining_min_ = static_cast<int>(value);
        break;
    case REG_DC_OUTPUT_POWER:
        this->dc_output_power_w_ = static_cast<float>(value);
        break;
    case REG_AC_OUTPUT_POWER:
        this->ac_output_power_w_ = static_cast<float>(value);
        break;
    case REG_DC_INPUT_POWER:
        this->dc_input_power_w_ = static_cast<float>(value);
        break;
    case REG_AC_INPUT_POWER:
        this->ac_input_power_w_ = static_cast<float>(value);
        break;
    case REG_AC_INPUT_VOLTAGE:
        this->ac_input_voltage_v_ = static_cast<float>(value) / 10.0f;
        break;
    case REG_CTRL_AC_OUTPUT:
        this->ac_output_enabled_ = value != 0;
        this->ac_output_state_known_ = true;
        break;
    case REG_CTRL_DC_OUTPUT:
        this->dc_output_enabled_ = value != 0;
        this->dc_output_state_known_ = true;
        break;
    default:
        return;
    }

    ESP_LOGVV(TAG, "Updated register %u => %u", reg_addr, value);
}

uint16_t BluettiRust::modbus_crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (uint8_t j = 0; j < 8; ++j) {
            if ((crc & 0x0001U) != 0) {
                crc = static_cast<uint16_t>((crc >> 1) ^ 0xA001U);
            } else {
                crc = static_cast<uint16_t>(crc >> 1);
            }
        }
    }

    return crc;
}

int32_t BluettiRust::random_callback(void *user_data, uint8_t *output,
                                     size_t output_len) {
    (void)user_data;

    if (output == nullptr) {
        return BLUETTI_FFI_ERR_NULL_POINTER;
    }

    esp_fill_random(output, output_len);
    return BLUETTI_FFI_OK;
}

} // namespace bluetti_rust
} // namespace esphome
