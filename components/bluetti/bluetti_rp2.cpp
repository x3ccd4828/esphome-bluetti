#include "esphome/core/defines.h"

#ifdef USE_RP2
#include "bluetti.h"
#include "esphome/core/hal.h"
#include "esphome/core/log.h"

#include <cstring>

namespace esphome::bluetti {
namespace {
constexpr const char *TAG = "bluetti";
constexpr uint32_t RETRY_MS = 5000;
constexpr uint32_t HANDSHAKE_TIMEOUT_MS = 30000;
} // namespace

bool Bluetti::is_connected() const {
    return enabled_ && link_state_ == LinkState::READY;
}

void Bluetti::set_enabled(bool enabled) {
    enabled_ = enabled;
    if (!enabled)
        this->disconnect();
}

void Bluetti::loop() {
    if (!enabled_ || ota_in_progress_)
        return;
    const uint32_t now = millis();
    if (link_state_ == LinkState::IDLE) {
        if (now - last_connect_attempt_ < RETRY_MS)
            return;
        last_connect_attempt_ = now;
        link_started_ = now;
        link_state_ = LinkState::CONNECTING;
        int error = backend_->connect(mac_address_, address_type_);
        if (error != 0) {
            link_state_ = LinkState::IDLE;
            ESP_LOGD(TAG, "Pico W connect deferred (error=%d)", error);
        }
    } else if (link_state_ != LinkState::DISCONNECTING && !this->is_ready() &&
               now - link_started_ >= HANDSHAKE_TIMEOUT_MS) {
        ESP_LOGW(TAG, "Pico W connection/handshake timed out; reconnecting");
        this->disconnect();
    } else {
        this->flush_write();
    }
}

#ifdef USE_OTA_STATE_LISTENER
void Bluetti::on_ota_global_state(ota::OTAState state, float, uint8_t,
                                  ota::OTAComponent *) {
    if (state == ota::OTA_STARTED) {
        // Keep the shared radio free for the update. The engine drops its
        // link too; this prevents our retry loop from immediately reopening it.
        ota_in_progress_ = true;
        this->disconnect();
    } else if (state == ota::OTA_ERROR || state == ota::OTA_ABORT) {
        ota_in_progress_ = false;
        last_connect_attempt_ = millis();
    }
}
#endif

void Bluetti::disconnect() {
    if (link_state_ == LinkState::DISCONNECTING)
        return;
    link_state_ = LinkState::DISCONNECTING;
    write_count_ = write_head_ = 0;
    write_in_flight_ = false;
    this->reset_connection();
    // Accepted teardown always completes through on_connection_state().
    if (backend_->gatt_disconnect() != 0) {
        link_state_ = LinkState::IDLE;
        last_connect_attempt_ = millis();
    }
}

void Bluetti::on_connection_state(bool connected, uint16_t mtu, int error) {
    if (!connected) {
        ESP_LOGI(TAG, "Disconnected from Bluetti (reason=%d)", error);
        link_state_ = LinkState::IDLE;
        last_connect_attempt_ = millis();
        write_count_ = write_head_ = 0;
        write_in_flight_ = false;
        cccd_handle_ = 0;
        this->reset_connection();
        return;
    }
    if (!enabled_ || link_state_ == LinkState::DISCONNECTING) {
        // A disable can race link establishment. Let the backend finish
        // its accepted cancellation without starting discovery.
        backend_->gatt_disconnect();
        return;
    }
    ESP_LOGI(TAG, "Connected to Bluetti device (Pico W, MTU=%u)", mtu);
    link_state_ = LinkState::DISCOVERING;
    if (backend_->discover_services() != 0)
        this->disconnect();
}

void Bluetti::on_service_discovery_done(int error) {
    if (link_state_ != LinkState::DISCOVERING)
        return;
    if (error != 0) {
        ESP_LOGW(TAG, "Pico W service discovery failed (error=%d)", error);
        this->disconnect();
        return;
    }
    using ble_device_base::ESPBTUUID;
    const auto table = backend_->get_service_table();
    for (uint16_t i = 0; i < table.service_count; ++i) {
        const auto &service = table.services[i];
        if (service.uuid != ESPBTUUID::from_uint16(0xFF00))
            continue;
        const size_t end = static_cast<size_t>(service.first_characteristic) +
                           service.characteristic_count;
        if (end > table.characteristic_count)
            break;
        for (size_t j = service.first_characteristic; j < end; ++j) {
            const auto &characteristic = table.characteristics[j];
            if (characteristic.uuid == ESPBTUUID::from_uint16(0xFF02))
                write_handle_ = characteristic.value_handle;
            if (characteristic.uuid != ESPBTUUID::from_uint16(0xFF01))
                continue;
            notify_handle_ = characteristic.value_handle;
            const size_t desc_end =
                static_cast<size_t>(characteristic.first_descriptor) +
                characteristic.descriptor_count;
            if (desc_end > table.descriptor_count)
                break;
            for (size_t k = characteristic.first_descriptor; k < desc_end;
                 ++k) {
                if (table.descriptors[k].uuid == ESPBTUUID::from_uint16(0x2902))
                    cccd_handle_ = table.descriptors[k].handle;
            }
        }
    }
    // Keep only handles; release the backend's transient discovery arena.
    backend_->release_services();
    if (notify_handle_ == 0 || write_handle_ == 0 || cccd_handle_ == 0) {
        ESP_LOGW(TAG, "Bluetti notify/write characteristic or CCCD not found");
        this->disconnect();
        return;
    }
    link_state_ = LinkState::SUBSCRIBING;
    int result = backend_->notify_characteristic(notify_handle_, true);
    if (result != 0 || link_state_ != LinkState::SUBSCRIBING) {
        this->disconnect();
        return;
    }
    const uint8_t enable[] = {1, 0};
    write_in_flight_ = true;
    if (backend_->write_descriptor(cccd_handle_, enable, sizeof(enable)) != 0)
        this->disconnect();
}

void Bluetti::on_notify_state(uint16_t, bool enabled, int error) {
    if (!enabled || error != 0) {
        ESP_LOGW(TAG, "Pico W notification registration failed (error=%d)",
                 error);
        this->disconnect();
    }
}

void Bluetti::on_notify_data(uint16_t handle, const uint8_t *data,
                             uint16_t len) {
    if (handle == notify_handle_ && (link_state_ == LinkState::SUBSCRIBING ||
                                     link_state_ == LinkState::READY))
        this->process_notification(data, len);
}

bool Bluetti::ble_write(const uint8_t *data, size_t len) {
    if ((link_state_ != LinkState::SUBSCRIBING &&
         link_state_ != LinkState::READY) ||
        len > sizeof(writes_[0].data) || write_count_ == WRITE_QUEUE_SIZE)
        return false;
    // BTstack accepts one GATT operation at a time. A peripheral can send
    // its next handshake notification before the previous write completes.
    // Copy responses now and serialize them through completion callbacks.
    auto &packet = writes_[(write_head_ + write_count_) % WRITE_QUEUE_SIZE];
    std::memcpy(packet.data, data, len);
    packet.len = len;
    ++write_count_;
    this->flush_write();
    return true;
}

void Bluetti::flush_write() {
    if (link_state_ != LinkState::READY || write_in_flight_ ||
        write_count_ == 0)
        return;
    auto &packet = writes_[write_head_];
    write_in_flight_ = true;
    // Synchronous rejection leaves the packet queued for the next loop.
    if (backend_->write_characteristic(write_handle_, packet.data, packet.len,
                                       true) != 0)
        write_in_flight_ = false;
}

void Bluetti::on_write_result(uint16_t handle, int error) {
    if (link_state_ == LinkState::DISCONNECTING ||
        link_state_ == LinkState::IDLE)
        return;
    if (error != 0) {
        ESP_LOGW(TAG, "Pico W GATT write failed (handle=%u error=%d)", handle,
                 error);
        this->disconnect();
        return;
    }
    if (link_state_ == LinkState::SUBSCRIBING && handle == cccd_handle_) {
        link_state_ = LinkState::READY;
        write_in_flight_ = false;
        ESP_LOGI(TAG, "Notification subscription active");
    } else if (handle == write_handle_ && write_in_flight_ &&
               write_count_ != 0) {
        write_head_ = (write_head_ + 1) % WRITE_QUEUE_SIZE;
        --write_count_;
        write_in_flight_ = false;
    }
    this->flush_write();
}
} // namespace esphome::bluetti
#endif
