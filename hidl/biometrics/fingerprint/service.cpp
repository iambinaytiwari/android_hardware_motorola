/*
 * Copyright (C) 2017 The Android Open Source Project
 *               2022 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "android.hardware.biometrics.fingerprint@2.3-service.motorola"

#include <android/hardware/biometrics/fingerprint/2.2/types.h>
#include <android/hardware/biometrics/fingerprint/2.3/IBiometricsFingerprint.h>
#include <android/log.h>
#include <hidl/HidlSupport.h>
#include <hidl/HidlTransportSupport.h>
#include <cutils/properties.h>
#include "BiometricsFingerprint.h"

using android::sp;
using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;
using android::hardware::biometrics::fingerprint::V2_3::IBiometricsFingerprint;
using android::hardware::biometrics::fingerprint::V2_3::implementation::BiometricsFingerprint;

int main() {
    ALOGD("Opening fingerprint hal library...");

    sp<BiometricsFingerprint> bio = static_cast<BiometricsFingerprint*>(BiometricsFingerprint::getInstance());

    configureRpcThreadpool(1, true /*callerWillJoin*/);

    if (bio != nullptr) {
        if (bio->init() == 0) {
            ALOGI(" Finish to initialize fingerprint HAL module !!!");
            if (::android::OK == bio->registerAsService()) {
                ALOGI(" Finish to register as service.");
                property_set("vendor.hw.fingerprint.status", "ok");
            } else {
                ALOGE("Fail to register as Service !!!");
                property_set("vendor.hw.fingerprint.status", "fail");
            }
        } else {
            ALOGE("Can't initialize the fingerprint HAL module !!!");
            property_set("vendor.hw.fingerprint.status", "fail");
        }
    } else {
        ALOGE("Can't create instance of BiometricsFingerprint, nullptr");
        property_set("vendor.hw.fingerprint.status", "fail");
    }

    joinRpcThreadpool();

    return 0;  // should never get here
}
