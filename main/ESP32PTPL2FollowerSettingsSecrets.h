// ESP32 PTP L2 Follower v1
// Copyright Rob Latour, 2026
// License: MIT
// Website: https://github.com/roblatour/ESP32PTPL2Follower
//

#pragma once

#include "setting_types.h"

// Privately provision matching PTP keys are set in this file.
//
// If used, they should match the keys configured on the master PTP device.
//
// Compiled keys can be recovered from firmware and build artifacts; keep those
// private too. Never log/export these arrays or persist keys in NVS.
//
namespace follower::settings
{
    // PTP uses independent 32-character alphanumeric keys. Configure before enabling.
    static constexpr PtpKey ptp_symmetric_keys[] = {
        {1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"},
    };
};
