#pragma once

inline void test_log(const char *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
inline void test_log(const char *, const char *, ...) {}
#define ESP_LOGE(tag, ...)      test_log(tag, __VA_ARGS__)
#define ESP_LOGW(tag, ...)      test_log(tag, __VA_ARGS__)
#define ESP_LOGI(tag, ...)      test_log(tag, __VA_ARGS__)
#define ESP_LOGD(tag, ...)      test_log(tag, __VA_ARGS__)
#define ESP_LOGV(tag, ...)      test_log(tag, __VA_ARGS__)
#define ESP_LOGVV(tag, ...)     test_log(tag, __VA_ARGS__)
#define ESP_LOGCONFIG(tag, ...) test_log(tag, __VA_ARGS__)
