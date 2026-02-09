#pragma once

#include "bluetti_ffi.h"

#include "esphome/components/ble_client/ble_client.h"
#include "esphome/core/component.h"

#include <cmath>

namespace esphome {
namespace bluetti_rust {

// Forward declaration for helper struct
struct OutputConfig;

class BluettiRust : public Component, public ble_client::BLEClientNode {
  public:
    ~BluettiRust();

    void setup() override;
    void dump_config() override;
    float get_setup_priority() const override { return setup_priority::DATA; }

    void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                             esp_ble_gattc_cb_param_t *param) override;

    bool is_ready() const;
    bool send_modbus_command(const uint8_t *data, size_t len);
    bool set_ac_output(bool enabled);
    bool set_dc_output(bool enabled);

    float battery_soc() const { return this->battery_soc_; }
    int time_remaining_minutes() const { return this->time_remaining_min_; }
    float dc_output_power() const { return this->dc_output_power_w_; }
    float ac_output_power() const { return this->ac_output_power_w_; }
    float dc_input_power() const { return this->dc_input_power_w_; }
    float ac_input_power() const { return this->ac_input_power_w_; }
    float ac_input_voltage() const { return this->ac_input_voltage_v_; }
    bool ac_output_enabled() const {
        return this->ac_output_state_known_ && this->ac_output_enabled_;
    }
    bool dc_output_enabled() const {
        return this->dc_output_state_known_ && this->dc_output_enabled_;
    }

  protected:
    static constexpr size_t TX_BUFFER_SIZE = 512;
    static constexpr uint8_t KEX_MAGIC_0 = 0x2A;
    static constexpr uint8_t KEX_MAGIC_1 = 0x2A;

    static constexpr uint16_t REG_BATTERY_SOC = 102;
    static constexpr uint16_t REG_TIME_REMAINING = 104;
    static constexpr uint16_t REG_DC_OUTPUT_POWER = 140;
    static constexpr uint16_t REG_AC_OUTPUT_POWER = 142;
    static constexpr uint16_t REG_DC_INPUT_POWER = 144;
    static constexpr uint16_t REG_AC_INPUT_POWER = 146;
    static constexpr uint16_t REG_AC_INPUT_VOLTAGE = 1314;
    static constexpr uint16_t REG_CTRL_AC_OUTPUT = 2011;
    static constexpr uint16_t REG_CTRL_DC_OUTPUT = 2012;

    static constexpr size_t POLL_REGISTER_COUNT = 9;
    static constexpr uint32_t POLL_INTERVAL_MS = 1000;
    static constexpr uint32_t AC_TOGGLE_DEBOUNCE_MS = 1000;
    static constexpr uint32_t DC_TOGGLE_DEBOUNCE_MS = 1000;

    esp32_ble::ESPBTUUID service_uuid_{
        esp32_ble::ESPBTUUID::from_raw("0000ff00-0000-1000-8000-00805f9b34fb")};
    esp32_ble::ESPBTUUID notify_char_uuid_{
        esp32_ble::ESPBTUUID::from_raw("0000FF01-0000-1000-8000-00805F9B34FB")};
    esp32_ble::ESPBTUUID write_char_uuid_{
        esp32_ble::ESPBTUUID::from_raw("0000FF02-0000-1000-8000-00805F9B34FB")};

    BluettiContext *rust_ctx_{nullptr};
    uint16_t notify_handle_{0};
    uint16_t write_handle_{0};
    uint8_t tx_buffer_[TX_BUFFER_SIZE];
    uint8_t cmd_buffer_[8]{};
    uint16_t poll_registers_[POLL_REGISTER_COUNT]{
        REG_BATTERY_SOC,      REG_TIME_REMAINING, REG_DC_OUTPUT_POWER,
        REG_AC_OUTPUT_POWER,  REG_DC_INPUT_POWER, REG_AC_INPUT_POWER,
        REG_AC_INPUT_VOLTAGE, REG_CTRL_AC_OUTPUT, REG_CTRL_DC_OUTPUT};
    size_t poll_index_{0};
    uint16_t pending_register_{0};
    uint32_t pending_since_ms_{0};
    uint32_t last_ac_toggle_request_ms_{0};
    uint32_t last_dc_toggle_request_ms_{0};
    bool pending_ac_toggle_{false};
    bool pending_ac_toggle_value_{false};
    bool pending_dc_toggle_{false};
    bool pending_dc_toggle_value_{false};
    bool awaiting_pubkey_accepted_{false};
    size_t cached_pubkey_response_len_{0};
    uint8_t cached_pubkey_response_[TX_BUFFER_SIZE]{};

    float battery_soc_{NAN};
    int time_remaining_min_{-1};
    float dc_output_power_w_{NAN};
    float ac_output_power_w_{NAN};
    float dc_input_power_w_{NAN};
    float ac_input_power_w_{NAN};
    float ac_input_voltage_v_{NAN};
    bool ac_output_enabled_{false};
    bool ac_output_state_known_{false};
    bool dc_output_enabled_{false};
    bool dc_output_state_known_{false};

    static int32_t random_callback(void *user_data, uint8_t *output,
                                   size_t output_len);

    static uint16_t modbus_crc16(const uint8_t *data, size_t len);

    void subscribe_notifications();
    void process_notification(const uint8_t *data, size_t len);
    void handle_kex_message(const uint8_t *data, size_t len);
    void handle_encrypted_message(const uint8_t *data, size_t len);
    void handle_encrypted_kex(size_t decrypted_len);
    void poll_next_register();
    bool build_read_register_command(uint16_t reg_addr, uint16_t quantity,
                                     uint8_t *out, size_t *out_len) const;
    bool build_write_register_command(uint16_t reg_addr, uint16_t value,
                                      uint8_t *out, size_t *out_len) const;
    bool build_modbus_command(uint8_t func_code, uint16_t reg_addr,
                              uint16_t value, uint8_t *out,
                              size_t *out_len) const;
    void mark_metrics_unavailable();
    void reset_poll_state();
    void handle_decrypted_response(const uint8_t *data, size_t len);
    void apply_register_value(uint16_t reg_addr, uint16_t value);
    bool ble_write(const uint8_t *data, size_t len);
    bool set_output(const OutputConfig &cfg, bool enabled);
    void process_pending_toggle(const char *name, uint16_t reg, bool value,
                                bool &pending_flag);
};

// Helper struct for output configuration (AC/DC)
struct OutputConfig {
    const char *name;
    uint16_t reg;
    uint32_t debounce_ms;
    uint32_t &last_toggle_ms;
    bool &state_known;
    bool &enabled;
    bool &pending;
    bool &pending_value;
};

} // namespace bluetti_rust
} // namespace esphome
