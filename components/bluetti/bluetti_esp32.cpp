#include "esphome/core/defines.h"
#ifndef USE_RP2
#include "bluetti.h"
#include "esphome/core/log.h"

namespace esphome::bluetti {
namespace {
constexpr const char *TAG = "bluetti";
}

bool Bluetti::is_connected() const { return parent_->connected(); }

void Bluetti::gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t,
                                  esp_ble_gattc_cb_param_t *param) {
    switch (event) {
    case ESP_GATTC_OPEN_EVT:
        if (param->open.status == ESP_GATT_OK)
            ESP_LOGI(TAG, "Connected to Bluetti device");
        break;
    case ESP_GATTC_DISCONNECT_EVT:
        ESP_LOGI(TAG, "Disconnected from Bluetti");
        this->reset_connection();
        break;
    case ESP_GATTC_SEARCH_CMPL_EVT:
        this->subscribe_notifications();
        break;
    case ESP_GATTC_REG_FOR_NOTIFY_EVT:
        if (param->reg_for_notify.status == ESP_GATT_OK)
            ESP_LOGI(TAG, "Notification subscription active");
        break;
    case ESP_GATTC_NOTIFY_EVT:
        if (param->notify.handle == notify_handle_)
            this->process_notification(param->notify.value,
                                       param->notify.value_len);
        break;
    case ESP_GATTC_WRITE_CHAR_EVT:
        if (param->write.status != ESP_GATT_OK)
            ESP_LOGW(TAG, "Write char failed status=%d handle=%u",
                     param->write.status, param->write.handle);
        break;
    default:
        break;
    }
}

void Bluetti::subscribe_notifications() {
    auto *notify =
        parent_->get_characteristic(service_uuid_, notify_char_uuid_);
    auto *write = parent_->get_characteristic(service_uuid_, write_char_uuid_);
    if (notify == nullptr || write == nullptr) {
        ESP_LOGE(TAG, "Bluetti notify/write characteristic not found");
        return;
    }
    notify_handle_ = notify->handle;
    write_handle_ = write->handle;
    esp_ble_gattc_register_for_notify(
        parent_->get_gattc_if(), parent_->get_remote_bda(), notify_handle_);
    uint16_t enable = 1;
    esp_ble_gattc_write_char_descr(
        parent_->get_gattc_if(), parent_->get_conn_id(), notify_handle_ + 1, 2,
        reinterpret_cast<uint8_t *>(&enable), ESP_GATT_WRITE_TYPE_RSP,
        ESP_GATT_AUTH_REQ_NONE);
    ESP_LOGI(TAG, "Write characteristic found");
}

bool Bluetti::ble_write(const uint8_t *data, size_t len) {
    if (write_handle_ == 0)
        return false;
    const esp_err_t result = esp_ble_gattc_write_char(
        parent_->get_gattc_if(), parent_->get_conn_id(), write_handle_, len,
        const_cast<uint8_t *>(data), ESP_GATT_WRITE_TYPE_RSP,
        ESP_GATT_AUTH_REQ_NONE);
    if (result != ESP_OK)
        ESP_LOGW(TAG, "GATT write failed: %d", static_cast<int>(result));
    return result == ESP_OK;
}

} // namespace esphome::bluetti
#endif
