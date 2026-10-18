#pragma once
#include "esphome/components/ota/ota_backend.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace esphome::ble_device_base {
struct ESPBTUUID {
    uint16_t value;
    static ESPBTUUID from_uint16(uint16_t value) { return {value}; }
    bool operator==(const ESPBTUUID &other) const {
        return value == other.value;
    }
    bool operator!=(const ESPBTUUID &other) const { return !(*this == other); }
};
struct GattDescriptor {
    ESPBTUUID uuid;
    uint16_t handle;
};
struct GattCharacteristic {
    ESPBTUUID uuid;
    uint16_t value_handle, end_handle;
    uint8_t properties;
    uint16_t first_descriptor, descriptor_count;
};
struct GattService {
    ESPBTUUID uuid;
    uint16_t start_handle, end_handle, first_characteristic,
        characteristic_count;
};
struct GattServiceTable {
    const GattService *services;
    const GattCharacteristic *characteristics;
    const GattDescriptor *descriptors;
    uint16_t service_count, characteristic_count, descriptor_count;
};
class GattClientListener {
  public:
    virtual void on_connection_state(bool, uint16_t, int) {}
    virtual void on_service_discovery_done(int) {}
    virtual void on_write_result(uint16_t, int) {}
    virtual void on_notify_state(uint16_t, bool, int) {}
    virtual void on_notify_data(uint16_t, const uint8_t *, uint16_t) {}
};
} // namespace esphome::ble_device_base

namespace esphome::bluetooth_connection {
class RP2GattClient {
  public:
    ble_device_base::GattClientListener *listener{};
    int connects{}, disconnects{}, discoveries{};
    uint64_t address{};
    uint8_t address_type{};
    uint16_t descriptor_handle{};
    int connect_error{}, write_error{};
    bool services_released{}, busy{};
    std::vector<std::vector<uint8_t>> writes;
    ble_device_base::GattService services[1]{{{0xff00}, 1, 100, 0, 2}};
    ble_device_base::GattCharacteristic chars[2]{{{0xff01}, 10, 19, 0x10, 0, 1},
                                                 {{0xff02}, 20, 30, 8, 1, 0}};
    // Deliberately not notify_handle + 1: discover the actual CCCD.
    ble_device_base::GattDescriptor descriptors[1]{{{0x2902}, 14}};
    int connect(uint64_t mac, uint8_t type) {
        ++connects;
        address = mac;
        address_type = type;
        return connect_error;
    }
    int gatt_disconnect() {
        ++disconnects;
        busy = false;
        return 0;
    }
    int discover_services() {
        ++discoveries;
        return 0;
    }
    ble_device_base::GattServiceTable get_service_table() {
        return {services, chars, descriptors, 1, 2, 1};
    }
    void release_services() { services_released = true; }
    int notify_characteristic(uint16_t handle, bool enable) {
        listener->on_notify_state(handle, enable, 0);
        return 0;
    }
    int write_descriptor(uint16_t handle, const uint8_t *data, uint16_t len) {
        descriptor_handle = handle;
        if (len != 2 || data[0] != 1 || data[1] != 0 || busy)
            return -1;
        busy = true;
        return 0;
    }
    int write_characteristic(uint16_t, const uint8_t *data, uint16_t len,
                             bool) {
        if (busy || write_error)
            return -1;
        busy = true;
        writes.emplace_back(data, data + len);
        return 0;
    }
    void complete(uint16_t handle = 20, int error = 0) {
        busy = false;
        listener->on_write_result(handle, error);
    }
};
} // namespace esphome::bluetooth_connection
