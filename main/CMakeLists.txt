idf_component_register(
    SRCS
        "main.cpp"
        "auth.cpp"
        "clock_owner.cpp"
        "ethernet.cpp"
        "follower_core.cpp"
        "app_metadata.cpp"
    INCLUDE_DIRS "."
    REQUIRES
        esp_eth
        esp_event
        esp_timer
        mbedtls
        esp_driver_gpio
        esp_hw_support
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)

set(FOLLOWER_AUTH_DEFINITIONS
    FOLLOWER_PTP_AUTH_ENABLED
    FOLLOWER_PTP_AUTH_REQUIRED
    FOLLOWER_PTP_AUTH_SPP
    FOLLOWER_PTP_ACTIVE_KEY_ID
)
foreach(FOLLOWER_AUTH_DEFINITION IN LISTS FOLLOWER_AUTH_DEFINITIONS)
    if(DEFINED ${FOLLOWER_AUTH_DEFINITION})
        target_compile_definitions(
            ${COMPONENT_LIB}
            PRIVATE "${FOLLOWER_AUTH_DEFINITION}=${${FOLLOWER_AUTH_DEFINITION}}"
        )
    endif()
endforeach()

# Metadata definitions injected into the main component
target_compile_definitions(${COMPONENT_TARGET} PRIVATE
    APP_PROJECT_NAME="${CMAKE_PROJECT_NAME}"
    APP_VERSION="${PROJECT_VER}"
    APP_COPYRIGHT="Copyright Rob Latour, 2026"
    APP_LICENSE="MIT"
    APP_HOMEPAGE="https://github.com/roblatour/ESP32TimeServer"
    APP_BUILD_DATE="${BUILD_DATE}"
    APP_BUILD_TIME="${BUILD_TIME}"
    APP_GIT_SHA="${GIT_SHA}"
) 
