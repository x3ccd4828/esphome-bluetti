#pragma once

#include <cstdint>
#include <functional>

namespace esphome {
namespace setup_priority {
constexpr float DATA = 600;
}
class Component {
  public:
    virtual ~Component() = default;
    virtual void setup() {}
    virtual void loop() {}
    virtual void dump_config() {}
    virtual float get_setup_priority() const { return 0; }
    void set_interval(const char *, uint32_t, std::function<void()> callback) {
        interval_callback = callback;
    }
    std::function<void()> interval_callback;
};
} // namespace esphome
