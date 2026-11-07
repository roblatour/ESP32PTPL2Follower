#pragma once

#include <cstdio>

inline unsigned host_log_count = 0;
inline unsigned host_warning_count = 0;
inline char host_last_error[512]{};
inline char host_last_warning[512]{};

template <typename... Args>
void host_log_error(const char *, const char *format, Args... args)
{
    ++host_log_count;
    std::snprintf(host_last_error, sizeof(host_last_error), format, args...);
}

template <typename... Args>
void host_log_warning(const char *, const char *format, Args... args)
{
    ++host_log_count;
    ++host_warning_count;
    std::snprintf(host_last_warning, sizeof(host_last_warning), format, args...);
}

#define ESP_LOGE(...) host_log_error(__VA_ARGS__)
#define ESP_LOGW(...) host_log_warning(__VA_ARGS__)
