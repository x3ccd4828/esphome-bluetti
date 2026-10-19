#pragma once

#include "bluetti_encryption.h"
#include "esphome/core/component.h"
#include "esphome/core/defines.h"
#ifdef USE_RP2
#include "esphome/components/bluetooth_connection/bluetooth_connection_rp2.h"
#else
#include "esphome/components/ble_client/ble_client.h"
#endif

#include <cmath>

namespace esphome::bluetti {

class Bluetti : public Component,
#ifdef USE_RP2
                public ble_device_base::GattClientListener
#ifdef USE_OTA_STATE_LISTENER
    ,
                public ota::OTAGlobalStateListener
#endif
{
#else
                public ble_client::BLEClientNode {
#endif
  public:
    void setup() override;
    void dump_config() override;
    float get_setup_priority() const override { return setup_priority::DATA; }
#ifdef USE_RP2
    void loop() override;
    void set_backend(bluetooth_connection::RP2GattClient *backend) {
        backend_ = backend;
    }
    void set_mac_address(uint64_t address) { mac_address_ = address; }
    void set_address_type(uint8_t type) { address_type_ = type; }
    void set_enabled(bool enabled);
    bool is_enabled() const { return enabled_; }
    void on_connection_state(bool connected, uint16_t mtu, int error) override;
    void on_service_discovery_done(int error) override;
    void on_write_result(uint16_t handle, int error) override;
    void on_notify_state(uint16_t handle, bool enabled, int error) override;
    void on_notify_data(uint16_t handle, const uint8_t *data,
                        uint16_t len) override;
#ifdef USE_OTA_STATE_LISTENER
    void on_ota_global_state(ota::OTAState state, float progress, uint8_t error,
                             ota::OTAComponent *component) override;
#endif
#else
    void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                             esp_ble_gattc_cb_param_t *param) override;
#endif
    bool is_connected() const;

    bool is_ready() const { return crypto_ctx_.is_ready_for_commands(); }
    bool set_ac_output(bool enabled);
    bool set_dc_output(bool enabled);
    float battery_soc() const { return battery_soc_; }
    int time_remaining_minutes() const { return time_remaining_min_; }
    float dc_output_power() const { return dc_output_power_w_; }
    float ac_output_power() const { return ac_output_power_w_; }
    float dc_input_power() const { return dc_input_power_w_; }
    float ac_input_power() const { return ac_input_power_w_; }
    float ac_input_voltage() const { return ac_input_voltage_v_; }
    bool ac_output_enabled() const {
        return ac_output_.known && ac_output_.enabled;
    }
    bool dc_output_enabled() const {
        return dc_output_.known && dc_output_.enabled;
    }

  protected:
    struct OutputState {
        uint32_t last_toggle_ms{0};
        bool known{false};
        bool enabled{false};
        bool pending{false};
        bool pending_value{false};
    };

    static constexpr uint16_t REG_BATTERY_SOC = 102;
    static constexpr uint16_t REG_TIME_REMAINING = 104;
    static constexpr uint16_t REG_DC_OUTPUT_POWER = 140;
    static constexpr uint16_t REG_AC_OUTPUT_POWER = 142;
    static constexpr uint16_t REG_DC_INPUT_POWER = 144;
    static constexpr uint16_t REG_AC_INPUT_POWER = 146;
    static constexpr uint16_t REG_AC_INPUT_VOLTAGE = 1314;
    static constexpr uint16_t REG_CTRL_AC_OUTPUT = 2011;
    static constexpr uint16_t REG_CTRL_DC_OUTPUT = 2012;
    static constexpr uint16_t POLL_REGISTERS[] = {
        REG_BATTERY_SOC,      REG_TIME_REMAINING, REG_DC_OUTPUT_POWER,
        REG_AC_OUTPUT_POWER,  REG_DC_INPUT_POWER, REG_AC_INPUT_POWER,
        REG_AC_INPUT_VOLTAGE, REG_CTRL_AC_OUTPUT, REG_CTRL_DC_OUTPUT};
    static constexpr size_t POLL_REGISTER_COUNT =
        sizeof(POLL_REGISTERS) / sizeof(POLL_REGISTERS[0]);
    static constexpr uint32_t POLL_INTERVAL_MS = 1000;
    static constexpr uint32_t TOGGLE_DEBOUNCE_MS = 1000;

#ifdef USE_RP2
    enum class LinkState : uint8_t {
        IDLE,
        CONNECTING,
        DISCOVERING,
        SUBSCRIBING,
        READY,
        DISCONNECTING
    };
    struct PendingWrite {
        uint8_t data[BluettiEncryption::PUBKEY_RESPONSE_SIZE];
        uint16_t len;
    };
    static constexpr uint8_t WRITE_QUEUE_SIZE = 4;
    bluetooth_connection::RP2GattClient *backend_{nullptr};
    uint64_t mac_address_{0};
    uint32_t last_connect_attempt_{0};
    uint32_t link_started_{0};
    uint16_t cccd_handle_{0};
    uint8_t address_type_{0};
    LinkState link_state_{LinkState::IDLE};
    bool enabled_{true};
    bool ota_in_progress_{false};
    bool write_in_flight_{false};
    PendingWrite writes_[WRITE_QUEUE_SIZE];
    uint8_t write_head_{0}, write_count_{0};
    void flush_write();
    void disconnect();
#else
    esp32_ble::ESPBTUUID service_uuid_{
        esp32_ble::ESPBTUUID::from_raw("0000ff00-0000-1000-8000-00805f9b34fb")};
    esp32_ble::ESPBTUUID notify_char_uuid_{
        esp32_ble::ESPBTUUID::from_raw("0000FF01-0000-1000-8000-00805F9B34FB")};
    esp32_ble::ESPBTUUID write_char_uuid_{
        esp32_ble::ESPBTUUID::from_raw("0000FF02-0000-1000-8000-00805F9B34FB")};
    void subscribe_notifications();
#endif

    BluettiEncryption crypto_ctx_;
    uint16_t notify_handle_{0};
    uint16_t write_handle_{0};
    uint8_t tx_buffer_[512];
    uint8_t cached_pubkey_response_[BluettiEncryption::PUBKEY_RESPONSE_SIZE];
    size_t cached_pubkey_response_len_{0};
    size_t poll_index_{0};
    uint16_t pending_register_{0};
    uint32_t pending_since_ms_{0};
    OutputState ac_output_, dc_output_;

    float battery_soc_{NAN};
    int time_remaining_min_{-1};
    float dc_output_power_w_{NAN};
    float ac_output_power_w_{NAN};
    float dc_input_power_w_{NAN};
    float ac_input_power_w_{NAN};
    float ac_input_voltage_v_{NAN};

    void reset_connection();
    void reset_pending_read();
    void process_notification(const uint8_t *data, size_t len);
    void handle_kex_message(const uint8_t *data, size_t len, bool encrypted);
    void poll_next_register();
    void handle_decrypted_response(const uint8_t *data, size_t len);
    void apply_register_value(uint16_t reg_addr, uint16_t value);
    bool ble_write(const uint8_t *data, size_t len);
    bool send_modbus_command(uint8_t function, uint16_t reg, uint16_t value);
    bool set_output(OutputState &state, bool enabled, uint16_t reg,
                    const char *name);
    bool write_output(OutputState &state, bool enabled, uint16_t reg,
                      const char *name);
    static uint16_t modbus_crc16(const uint8_t *data, size_t len);
};

} // namespace esphome::bluetti
