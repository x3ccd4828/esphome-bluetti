#pragma once
#include <cstdint>
#include <vector>
namespace esphome::ota {
enum OTAState {
    OTA_COMPLETED,
    OTA_STARTED,
    OTA_IN_PROGRESS,
    OTA_ABORT,
    OTA_ERROR
};
class OTAComponent {};
class OTAGlobalStateListener {
  public:
    virtual ~OTAGlobalStateListener() = default;
    virtual void on_ota_global_state(OTAState, float, uint8_t,
                                     OTAComponent *) = 0;
};
class OTAGlobalCallback {
  public:
    void add_global_state_listener(OTAGlobalStateListener *listener) {
        listeners.push_back(listener);
    }
    std::vector<OTAGlobalStateListener *> listeners;
};
inline OTAGlobalCallback *get_global_ota_callback() {
    static OTAGlobalCallback callback;
    return &callback;
}
} // namespace esphome::ota
