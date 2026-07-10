/*
 * Copyright (C) 2022 The Android Open Source Project
 * Copyright (C) 2026 The LineageOS Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#define LOG_TAG "FingerprintMotorolaHal"

#include <aidl/android/hardware/biometrics/common/SensorStrength.h>
#include <aidl/android/hardware/biometrics/fingerprint/ISessionCallback.h>
#include <android/binder_to_string.h>
#include <string>

#include <random>

#include <aidl/android/hardware/biometrics/fingerprint/SensorLocation.h>
#include <future>
#include <vector>

#include "LockoutTracker.h"

#include <fstream>
#include <atomic>
#include "fingerprint-motorola.h"

namespace common = ::aidl::android::hardware::biometrics::common;

namespace aidl::android::hardware::biometrics::fingerprint {

typedef struct rbs_fingerprint_device {
    int (*rbs_initialize)(int, int);
    int (*rbs_uninitialize)(void);
    int (*rbs_cancel)(void*, uint32_t);
    int (*rbs_active_user_group)(uint32_t gid, const char* store_path);
    int (*rbs_set_data_path)(int, const char*);
    int (*rbs_chk_secure_id)(uint32_t gid, uint64_t user_id);
    int (*rbs_pre_enroll)(uint32_t gid, uint32_t seed);
    int (*rbs_enroll)(void);
    int (*rbs_post_enroll)(void);
    int (*rbs_chk_auth_token)(const hw_auth_token_t* hat, uint32_t hat_size);
    int (*rbs_authenticator)(uint32_t gid, void*, uint32_t, uint64_t operation_id);
    int (*rbs_remove_fingerprint)(uint32_t gid, uint32_t fid);
    int (*rbs_get_fingerprint_ids)(uint32_t gid, uint32_t* fids, uint32_t* num_fids);
    int (*rbs_get_authenticator_id)(uint64_t* authenticator_id);
    int (*rbs_set_on_callback_proc)(void* callback_proc);
    int (*rbs_extra_api)(uint32_t, const uint8_t*, uint32_t, uint8_t*, uint32_t*);
} rbs_fingerprint_device_t;

class Session;

// A fingerprint engine that is backed by system properties instead of hardware.
class FingerprintEngine {
    friend class Session;
  public:
    FingerprintEngine();
    virtual ~FingerprintEngine();

    void setActiveGroup(int userId);
    void generateChallengeImpl(ISessionCallback* cb);
    void revokeChallengeImpl(ISessionCallback* cb, int64_t challenge);
    virtual void enrollImpl(ISessionCallback* cb, const keymaster::HardwareAuthToken& hat,
                            const std::future<void>& cancel);
    virtual void authenticateImpl(ISessionCallback* cb, int64_t operationId,
                                  const std::future<void>& cancel);
    virtual void detectInteractionImpl(ISessionCallback* cb, const std::future<void>& cancel);
    void enumerateEnrollmentsImpl(ISessionCallback* cb);
    void removeEnrollmentsImpl(ISessionCallback* cb, const std::vector<int32_t>& enrollmentIds);
    void getAuthenticatorIdImpl(ISessionCallback* cb);
    void invalidateAuthenticatorIdImpl(ISessionCallback* cb);
    void resetLockoutImpl(ISessionCallback* cb, const keymaster::HardwareAuthToken& /*hat*/);
    bool getSensorLocationConfig(std::vector<SensorLocation>& out);

    virtual ndk::ScopedAStatus onPointerDownImpl(int32_t pointerId, int32_t x, int32_t y,
                                                 float minor, float major);

    virtual ndk::ScopedAStatus onPointerUpImpl(int32_t pointerId);

    virtual ndk::ScopedAStatus onUiReadyImpl();

    virtual void getSensorLocation(std::vector<SensorLocation>& loc);

    virtual void fingerDownAction();

    int32_t getLatency(const std::vector<std::optional<std::int32_t>>& latencyVec);

    std::mt19937 mRandom;

    enum class WorkMode : int8_t { kIdle = 0, kAuthenticate, kEnroll, kDetectInteract };

    WorkMode getWorkMode() { return mWorkMode; }
    void notifyFingerdown() { mFingerIsDown = true; }
    bool isDeviceReady() { return mDevice != nullptr || mIsRbs; }

    virtual std::string toString() const {
        std::ostringstream os;
        os << "----- FingerprintEngine:: -----" << std::endl;
        os << "mWorkMode:" << (int)mWorkMode;
        os << "acquiredVendorInfoBase:" << FINGERPRINT_ACQUIRED_VENDOR_BASE;
        os << ", errorVendorBase:" << FINGERPRINT_ERROR_VENDOR_BASE << std::endl;
        os << mLockoutTracker.toString();
        return os.str();
    }

  protected:
    virtual void updateContext(WorkMode mode, ISessionCallback* cb, std::future<void>& cancel,
                               int64_t operationId, const keymaster::HardwareAuthToken& hat);

    bool onEnrollFingerDown(ISessionCallback* cb, const keymaster::HardwareAuthToken& hat,
                            const std::future<void>& cancel);
    bool onAuthenticateFingerDown(ISessionCallback* cb, int64_t operationId, const std::future<void>& cancel);
    bool onDetectInteractFingerDown(ISessionCallback* cb, const std::future<void>& cancel);

    WorkMode mWorkMode = WorkMode::kIdle;
    ISessionCallback* mCb = nullptr;
    keymaster::HardwareAuthToken mHat;
    std::future<void> mCancel;
    int64_t mOperationId = 0;
    bool mFingerIsDown = false;

    fingerprint_device_t* mDevice = nullptr;
    int mUserId;

    bool mIsRbs = false;
    rbs_fingerprint_device_t* mRbsDevice = nullptr;
    uint64_t mChallenge = 0;

  private:
    static FingerprintEngine* sInstance;
    static void rbsNotify(uint32_t eventId, uint32_t value1, uint32_t value2, void* buffer, uint32_t buffer_size);
    void handleRbsNotify(uint32_t eventId, uint32_t value1, uint32_t value2, void* buffer, uint32_t buffer_size);

    // static ndk::ScopedAStatus ErrorFilter(int32_t error);
    Error VendorErrorFilter(int32_t error, int32_t* vendorCode);
    AcquiredInfo VendorAcquiredFilter(int32_t info, int32_t* vendorCode);

    static constexpr int32_t FINGERPRINT_ACQUIRED_VENDOR_BASE = 1000;
    static constexpr int32_t FINGERPRINT_ERROR_VENDOR_BASE = 1000;
    std::pair<AcquiredInfo, int32_t> convertAcquiredInfo(int32_t code);
    std::pair<Error, int32_t> convertError(int32_t code);
    int32_t getRandomInRange(int32_t bound1, int32_t bound2);
    bool checkSensorLockout(ISessionCallback*);
    void clearLockout(ISessionCallback* cb, bool dueToTimeout = false);
    void waitForFingerDown(ISessionCallback* cb, const std::future<void>& cancel);

    LockoutTracker mLockoutTracker;

    fingerprint_device_t* openFingerprintHal();

  protected:
    // lockout timer
    void lockoutTimerExpired(ISessionCallback* cb);
    bool isLockoutTimerSupported = true;
    std::atomic<bool> isLockoutTimerStarted{false};
    std::atomic<bool> isLockoutTimerAborted{false};

  public:
    void startLockoutTimer(int64_t timeout, ISessionCallback* cb);
    bool getLockoutTimerStarted() { return isLockoutTimerStarted; }
};

}  // namespace aidl::android::hardware::biometrics::fingerprint
