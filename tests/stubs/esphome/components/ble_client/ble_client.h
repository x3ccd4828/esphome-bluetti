#pragma once

#include <cstdint>
#include <cstring>

using esp_gatt_if_t = int;
using esp_err_t = int;
constexpr int ESP_OK = 0;
constexpr int ESP_GATT_OK = 0;
constexpr int ESP_GATT_WRITE_TYPE_RSP = 0;
constexpr int ESP_GATT_AUTH_REQ_NONE = 0;
enum esp_gattc_cb_event_t {
    ESP_GATTC_OPEN_EVT,
    ESP_GATTC_DISCONNECT_EVT,
    ESP_GATTC_SEARCH_CMPL_EVT,
    ESP_GATTC_REG_FOR_NOTIFY_EVT,
    ESP_GATTC_NOTIFY_EVT,
    ESP_GATTC_WRITE_CHAR_EVT
};
struct esp_ble_gattc_cb_param_t {
    struct {
        int status{};
    } open, reg_for_notify;
    struct {
        int status{};
        uint16_t handle{};
    } write;
    struct {
        uint16_t handle{};
        uint8_t *value{};
        uint16_t value_len{};
    } notify;
};

int esp_ble_gattc_register_for_notify(int, uint8_t *, uint16_t);
int esp_ble_gattc_write_char_descr(int, uint16_t, uint16_t, uint16_t, uint8_t *,
                                   int, int);
int esp_ble_gattc_write_char(int, uint16_t, uint16_t, uint16_t, uint8_t *, int,
                             int);

namespace esphome {
namespace esp32_ble {
struct ESPBTUUID {
    const char *text;
    static ESPBTUUID from_raw(const char *text) { return {text}; }
};
} // namespace esp32_ble
namespace ble_client {
class BLEClient {
  public:
    struct Characteristic {
        uint16_t handle;
    } notify{10}, write{20};
    Characteristic *get_characteristic(esp32_ble::ESPBTUUID,
                                       esp32_ble::ESPBTUUID id) {
        return std::strstr(id.text, "FF01") != nullptr ? &notify : &write;
    }
    int get_gattc_if() const { return 1; }
    uint16_t get_conn_id() const { return 1; }
    uint8_t *get_remote_bda() { return address; }
    bool connected() const { return connected_; }
    bool connected_{true};
    uint8_t address[6]{};
};
class BLEClientNode {
  public:
    virtual ~BLEClientNode() = default;
    virtual void gattc_event_handler(esp_gattc_cb_event_t, esp_gatt_if_t,
                                     esp_ble_gattc_cb_param_t *) {}
    void set_ble_client_parent(BLEClient *parent) { parent_ = parent; }

  protected:
    BLEClient *parent_{nullptr};
};
} // namespace ble_client
} // namespace esphome
