cmake_minimum_required(VERSION 3.22)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# The chip is selected with "idf.py set-target esp32p4" or
# "idf.py --preview set-target esp32s31"; board wiring follows the target.
if(NOT IDF_TARGET STREQUAL "esp32p4" AND NOT IDF_TARGET STREQUAL "esp32s31")
    message(FATAL_ERROR "ESP32PTPL2Follower supports only the esp32p4 and esp32s31 targets; found '${IDF_TARGET}'")
endif()

if(IDF_TARGET STREQUAL "esp32s31")
    set(COMPONENTS main)
endif()

project(ESP32PTPL2Follower
        VERSION 1.0.0
        SPDX_LICENSE MIT
        DESCRIPTION "ESP32 PTP Follower for your home network"
)

idf_build_set_property(MINIMAL_BUILD ON)

set(FOLLOWER_IDF_VERSION "${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}.${IDF_VERSION_PATCH}")
if(FOLLOWER_IDF_VERSION VERSION_LESS "6.1.0" OR NOT FOLLOWER_IDF_VERSION VERSION_LESS "6.2.0")
    message(FATAL_ERROR "ESP32PTPL2Follower requires ESP-IDF >= 6.1.0 and < 6.2.0; found ${FOLLOWER_IDF_VERSION}")
endif()

project(ESP32PTPL2Follower)
