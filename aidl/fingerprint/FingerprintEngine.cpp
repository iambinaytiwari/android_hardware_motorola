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

#include "FingerprintEngine.h"
#include <regex>
#include "Fingerprint.h"
#include "Legacy2Aidl.h"

#include <android-base/logging.h>
#include <android-base/parseint.h>

#include <fingerprint.sysprop.h>

#include "util/CancellationSignal.h"
#include "util/Util.h"
#include <dlfcn.h>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

using namespace ::android::fingerprint::motorola;
using ::android::base::ParseInt;

namespace aidl::android::hardware::biometrics::fingerprint {

FingerprintEngine* FingerprintEngine::sInstance = nullptr;

FingerprintEngine::FingerprintEngine() : mWorkMode(WorkMode::kIdle), mUserId(0), isLockoutTimerSupported(true) {
    sInstance = this;
    if (mDevice || mIsRbs) {
        LOG(INFO) << "Fingerprint HAL already opened";
    } else {
        mDevice = openFingerprintHal();

        if (!mDevice && !mIsRbs) {
            LOG(ERROR) << "Can't open fingerprint HAL module, please check ro.hardware.${class}";
        } else {
            LOG(INFO) << "Opened fingerprint HAL module";
        }
    }
}

FingerprintEngine::~FingerprintEngine() {
    if (mIsRbs && mRbsDevice) {
        mRbsDevice->rbs_uninitialize();
        free(mRbsDevice);
    }
}

void FingerprintEngine::setActiveGroup(int userId) {
    mUserId = userId;
    auto path = std::format("/data/vendor_de/{}/fpdata/", userId);
    if (mIsRbs) {
        LOG(INFO) << "setActiveGroup (RBS)";
        int rc = mRbsDevice->rbs_active_user_group(userId, path.c_str());
        if (rc != 0) {
            LOG(ERROR) << "rbs_active_user_group failed, error: " << rc;
        }
        rc = mRbsDevice->rbs_set_data_path(1, path.c_str());
        if (rc != 0) {
            LOG(ERROR) << "rbs_set_data_path failed, error: " << rc;
        }
        return;
    }
    if (mDevice) {
        LOG(INFO) << "setActiveGroup";
        mDevice->setActiveGroup(mDevice, userId, path.c_str());
    } else {
        LOG(ERROR) << "Failed to set active group!";
    }
}

fingerprint_device_t* FingerprintEngine::openFingerprintHal() {
    bool has_egis = (access("/dev/egis_fp", F_OK) == 0 || access("/dev/ets_fp", F_OK) == 0 || access("/dev/egis", F_OK) == 0 || access("/dev/esfp0", F_OK) == 0);
    if (has_egis) {
        void* rbs_handle = dlopen("libRbsFlow.so", RTLD_NOW);
        if (rbs_handle != nullptr) {
            LOG(INFO) << "Detected Egistec RBS library";
            mRbsDevice = (rbs_fingerprint_device_t*)malloc(sizeof(rbs_fingerprint_device_t));
            if (mRbsDevice) {
                mRbsDevice->rbs_initialize = reinterpret_cast<typeof(mRbsDevice->rbs_initialize)>(dlsym(rbs_handle, "rbs_initialize"));
                mRbsDevice->rbs_uninitialize = reinterpret_cast<typeof(mRbsDevice->rbs_uninitialize)>(dlsym(rbs_handle, "rbs_uninitialize"));
                mRbsDevice->rbs_cancel = reinterpret_cast<typeof(mRbsDevice->rbs_cancel)>(dlsym(rbs_handle, "rbs_cancel"));
                mRbsDevice->rbs_active_user_group = reinterpret_cast<typeof(mRbsDevice->rbs_active_user_group)>(dlsym(rbs_handle, "rbs_active_user_group"));
                mRbsDevice->rbs_set_data_path = reinterpret_cast<typeof(mRbsDevice->rbs_set_data_path)>(dlsym(rbs_handle, "rbs_set_data_path"));
                mRbsDevice->rbs_chk_secure_id = reinterpret_cast<typeof(mRbsDevice->rbs_chk_secure_id)>(dlsym(rbs_handle, "rbs_chk_secure_id"));
                mRbsDevice->rbs_pre_enroll = reinterpret_cast<typeof(mRbsDevice->rbs_pre_enroll)>(dlsym(rbs_handle, "rbs_pre_enroll"));
                mRbsDevice->rbs_enroll = reinterpret_cast<typeof(mRbsDevice->rbs_enroll)>(dlsym(rbs_handle, "rbs_enroll"));
                mRbsDevice->rbs_post_enroll = reinterpret_cast<typeof(mRbsDevice->rbs_post_enroll)>(dlsym(rbs_handle, "rbs_post_enroll"));
                mRbsDevice->rbs_chk_auth_token = reinterpret_cast<typeof(mRbsDevice->rbs_chk_auth_token)>(dlsym(rbs_handle, "rbs_chk_auth_token"));
                mRbsDevice->rbs_authenticator = reinterpret_cast<typeof(mRbsDevice->rbs_authenticator)>(dlsym(rbs_handle, "rbs_authenticator"));
                mRbsDevice->rbs_remove_fingerprint = reinterpret_cast<typeof(mRbsDevice->rbs_remove_fingerprint)>(dlsym(rbs_handle, "rbs_remove_fingerprint"));
                mRbsDevice->rbs_get_fingerprint_ids = reinterpret_cast<typeof(mRbsDevice->rbs_get_fingerprint_ids)>(dlsym(rbs_handle, "rbs_get_fingerprint_ids"));
                mRbsDevice->rbs_get_authenticator_id = reinterpret_cast<typeof(mRbsDevice->rbs_get_authenticator_id)>(dlsym(rbs_handle, "rbs_get_authenticator_id"));
                mRbsDevice->rbs_set_on_callback_proc = reinterpret_cast<typeof(mRbsDevice->rbs_set_on_callback_proc)>(dlsym(rbs_handle, "rbs_set_on_callback_proc"));
                mRbsDevice->rbs_extra_api = reinterpret_cast<typeof(mRbsDevice->rbs_extra_api)>(dlsym(rbs_handle, "rbs_extra_api"));

                if (mRbsDevice->rbs_initialize && mRbsDevice->rbs_uninitialize && mRbsDevice->rbs_cancel &&
                    mRbsDevice->rbs_active_user_group && mRbsDevice->rbs_chk_secure_id && mRbsDevice->rbs_pre_enroll &&
                    mRbsDevice->rbs_enroll && mRbsDevice->rbs_post_enroll && mRbsDevice->rbs_chk_auth_token &&
                    mRbsDevice->rbs_authenticator && mRbsDevice->rbs_remove_fingerprint && mRbsDevice->rbs_get_fingerprint_ids &&
                    mRbsDevice->rbs_get_authenticator_id && mRbsDevice->rbs_set_on_callback_proc) {

                    mRbsDevice->rbs_set_on_callback_proc(reinterpret_cast<void*>(FingerprintEngine::rbsNotify));
                    int err = mRbsDevice->rbs_initialize(0, 0);
                    if (err == 0) {
                        mIsRbs = true;
                        LOG(INFO) << "Initialized Egistec RBS fingerprint sensor successfully";
                        return nullptr;
                    } else {
                        LOG(ERROR) << "Can't initialize RBS fingerprint, error: " << err;
                    }
                } else {
                    LOG(ERROR) << "Failed to load all RBS symbols from libRbsFlow.so";
                }
                free(mRbsDevice);
                mRbsDevice = nullptr;
            }
        } else {
            LOG(ERROR) << "Failed to dlopen libRbsFlow.so: " << dlerror();
        }
    }

    const hw_module_t* hw_mdl = nullptr;

    LOG(INFO) << "Opening fingerprint hal library...";
    if (hw_get_module_by_class(FINGERPRINT_HARDWARE_MODULE_ID, "goodix", &hw_mdl) != 0) {
        LOG(ERROR) << "Can't open fingerprint HW Module";
        return nullptr;
    }

    if (!hw_mdl) {
        LOG(ERROR) << "No valid fingerprint module";
        return nullptr;
    }

    auto module = reinterpret_cast<const fingerprint_module_t*>(hw_mdl);
    if (!module->common.methods->open) {
        LOG(ERROR) << "No valid open method";
        return nullptr;
    }

    hw_device_t* device = nullptr;
    if (module->common.methods->open(hw_mdl, nullptr, &device) != 0) {
        LOG(ERROR) << "Can't open fingerprint methods";
        return nullptr;
    }

    if (module->common.module_api_version != FINGERPRINT_MODULE_API_VERSION_2_1) {
        LOG(ERROR) << "Hardware version doesn't match FINGERPRINT_MODULE_API_VERSION_2_1: "
                   << module->common.module_api_version;
        return nullptr;
    }

    auto fp_device = reinterpret_cast<fingerprint_device_t*>(device);
    if (fp_device->set_notify(fp_device, Fingerprint::notify) != 0) {
        LOG(ERROR) << "Can't register fingerprint module callback";
        return nullptr;
    }

    return fp_device;
}

void FingerprintEngine::generateChallengeImpl(ISessionCallback* cb) {
    BEGIN_OP(0);
    if (mIsRbs) {
        mChallenge = static_cast<uint64_t>(rand()) | (static_cast<uint64_t>(rand()) << 32);
        int rc = mRbsDevice->rbs_pre_enroll(mUserId, 10);
        if (rc != 0) {
            LOG(ERROR) << "rbs_pre_enroll failed in generateChallenge: " << rc;
        }
        cb->onChallengeGenerated(mChallenge);
        return;
    }
    uint64_t challenge = 0;
    if (mDevice->pre_enroll) {
        challenge = mDevice->pre_enroll(mDevice);
    }
    cb->onChallengeGenerated(challenge);
}

void FingerprintEngine::revokeChallengeImpl(ISessionCallback* cb, int64_t challenge) {
    BEGIN_OP(0);
    if (mIsRbs) {
        mChallenge = 0;
        int rc = mRbsDevice->rbs_post_enroll();
        if (rc != 0) {
            LOG(ERROR) << "rbs_post_enroll failed in revokeChallenge: " << rc;
        }
        cb->onChallengeRevoked(challenge);
        return;
    }
    if (mDevice->post_enroll) {
        int error = mDevice->post_enroll(mDevice);
        if (error) {
            LOG(ERROR) << "Failed to revoke challenge=" << challenge << " error=" << error;
        }
    }
    cb->onChallengeRevoked(challenge);
}

void FingerprintEngine::enrollImpl(ISessionCallback* cb, const keymaster::HardwareAuthToken& hat,
                                   const std::future<void>& cancel) {
    BEGIN_OP(0);

    if (mIsRbs) {
        hw_auth_token_t authToken;
        translate(hat, authToken);

        if (authToken.timestamp == 0) {
            LOG(ERROR) << "HAT timestamp is 0";
            cb->onError(Error::UNABLE_TO_PROCESS, 0);
            return;
        }

        if (authToken.challenge != mChallenge) {
            LOG(ERROR) << "Challenge does not match: " << authToken.challenge << " vs " << mChallenge;
            cb->onError(Error::UNABLE_TO_PROCESS, 0);
            return;
        }

        if (authToken.version != 0) {
            LOG(ERROR) << "Invalid HAT version = " << (int)authToken.version;
            cb->onError(Error::UNABLE_TO_PROCESS, 0);
            return;
        }

        int rc = mRbsDevice->rbs_chk_auth_token(&authToken, sizeof(hw_auth_token_t));
        if (rc != 0) {
            LOG(ERROR) << "Auth token check failed, error " << rc;
            cb->onError(Error::UNABLE_TO_PROCESS, rc);
            return;
        }

        rc = mRbsDevice->rbs_chk_secure_id(mUserId, authToken.user_id);
        if (rc != 0) {
            LOG(DEBUG) << "Secure ID check failed, error " << rc;
            if (rc == 0x21) {
                mRbsDevice->rbs_remove_fingerprint(mUserId, 0);
                rc = mRbsDevice->rbs_chk_secure_id(mUserId, authToken.user_id);
            }
            if (rc != 0) {
                LOG(ERROR) << "Secure ID check failed after check/remove, error " << rc;
                cb->onError(Error::UNABLE_TO_PROCESS, rc);
                return;
            }
        }

        updateContext(WorkMode::kEnroll, cb, const_cast<std::future<void>&>(cancel), 0, hat);

        std::thread([this]() {
            while (mWorkMode != WorkMode::kIdle) {
                if (mCancel.valid() && mCancel.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                    LOG(INFO) << "RBS cancellation signal triggered";
                    mRbsDevice->rbs_cancel(nullptr, 2);
                    mRbsDevice->rbs_cancel(nullptr, 3);
                    mRbsDevice->rbs_cancel(nullptr, 5);
                    mWorkMode = WorkMode::kIdle;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }).detach();

        rc = mRbsDevice->rbs_pre_enroll(mUserId, 10);
        if (rc != 0) {
            LOG(ERROR) << "rbs_pre_enroll failed: " << rc;
        }
        mRbsDevice->rbs_cancel(nullptr, 2);
        if (mRbsDevice->rbs_extra_api) {
            mRbsDevice->rbs_extra_api(3, nullptr, 0, nullptr, nullptr);
        }

        rc = mRbsDevice->rbs_enroll();
        if (rc != 0) {
            LOG(ERROR) << "rbs_enroll failed: " << rc;
            cb->onError(Error::UNABLE_TO_PROCESS, rc);
        }
        return;
    }

    // Do proper HAT verification in the real implementation.
    if (hat.mac.empty()) {
        LOG(ERROR) << "Fail: hat";
        cb->onError(Error::UNABLE_TO_PROCESS, 0 /* vendorError */);
        return;
    }

    updateContext(WorkMode::kEnroll, cb, const_cast<std::future<void>&>(cancel), 0, hat);

    hw_auth_token_t authToken;
    translate(hat, authToken);
    int error = mDevice->enroll(mDevice, &authToken, mUserId, 60 /* timeout_sec */);
    if (error) {
        LOG(ERROR) << "enroll failed: " << error;
        cb->onError(Error::UNABLE_TO_PROCESS, error);
    }
}

void FingerprintEngine::authenticateImpl(ISessionCallback* cb, int64_t operationId,
                                         const std::future<void>& cancel) {
    BEGIN_OP(0);

    // got lockout?
    if (checkSensorLockout(cb)) {
        return;
    }

    if (mIsRbs) {
        updateContext(WorkMode::kAuthenticate, cb, const_cast<std::future<void>&>(cancel), operationId,
                      keymaster::HardwareAuthToken());

        std::thread([this]() {
            while (mWorkMode != WorkMode::kIdle) {
                if (mCancel.valid() && mCancel.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                    LOG(INFO) << "RBS cancellation signal triggered";
                    mRbsDevice->rbs_cancel(nullptr, 2);
                    mRbsDevice->rbs_cancel(nullptr, 3);
                    mRbsDevice->rbs_cancel(nullptr, 5);
                    mWorkMode = WorkMode::kIdle;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }).detach();

        mRbsDevice->rbs_cancel(nullptr, 2);
        mRbsDevice->rbs_cancel(nullptr, 3);
        mRbsDevice->rbs_cancel(nullptr, 5);
        int rc = mRbsDevice->rbs_authenticator(mUserId, nullptr, 0, operationId);
        if (rc != 0) {
            LOG(ERROR) << "rbs_authenticator failed, error " << rc;
            cb->onError(Error::CANCELED, 0);
            if (rc == 4) {
                cb->onError(Error::HW_UNAVAILABLE, 0);
            }
        }
        return;
    }

    updateContext(WorkMode::kAuthenticate, cb, const_cast<std::future<void>&>(cancel), operationId,
                  keymaster::HardwareAuthToken());

    int error = mDevice->authenticate(mDevice, operationId, mUserId);
    if (error) {
        LOG(ERROR) << "authenticate failed: " << error;
    }
}

void FingerprintEngine::detectInteractionImpl(ISessionCallback* cb,
                                              const std::future<void>& cancel) {
    BEGIN_OP(0);

    auto detectInteractionSupported = Fingerprint::cfg().get<bool>("detect_interaction");
    if (!detectInteractionSupported) {
        LOG(ERROR) << "Detect interaction is not supported";
        cb->onError(Error::UNABLE_TO_PROCESS, 0 /* vendorError */);
        return;
    }

    updateContext(WorkMode::kDetectInteract, cb, const_cast<std::future<void>&>(cancel), 0,
                  keymaster::HardwareAuthToken());
}

void FingerprintEngine::updateContext(WorkMode mode, ISessionCallback* cb,
                                      std::future<void>& cancel, int64_t operationId,
                                      const keymaster::HardwareAuthToken& hat) {
    mCancel = std::move(cancel);
    mWorkMode = mode;
    mCb = cb;
    mOperationId = operationId;
    mHat = hat;
}

void FingerprintEngine::fingerDownAction() {
    bool isTerminal = false;
    LOG(INFO) << __func__;
    switch (mWorkMode) {
        case WorkMode::kAuthenticate:
            isTerminal = onAuthenticateFingerDown(mCb, mOperationId, mCancel);
            break;
        case WorkMode::kEnroll:
            isTerminal = onEnrollFingerDown(mCb, mHat, mCancel);
            break;
        case WorkMode::kDetectInteract:
            isTerminal = onDetectInteractFingerDown(mCb, mCancel);
            break;
        default:
            LOG(WARNING) << "unexpected mode: on fingerDownAction(), " << (int)mWorkMode;
            break;
    }

    if (isTerminal) {
        mWorkMode = WorkMode::kIdle;
    }
}

bool FingerprintEngine::onEnrollFingerDown(ISessionCallback* /*cb*/,
                                           const keymaster::HardwareAuthToken& /*hat*/,
                                           const std::future<void>& /*cancel*/) {
    return true;
}

bool FingerprintEngine::onAuthenticateFingerDown(ISessionCallback* /*cb*/, int64_t /*operationId*/,
                                                 const std::future<void>& /*cancel*/) {
    return true;
}

bool FingerprintEngine::onDetectInteractFingerDown(ISessionCallback* cb,
                                                   const std::future<void>& cancel) {
    BEGIN_OP(getLatency(
            Fingerprint::cfg().getopt<OptIntVec>("operation_detect_interaction_latency")));

    int32_t duration =
            Fingerprint::cfg().get<std::int32_t>("operation_detect_interaction_duration");

    auto acquired = Fingerprint::cfg().get<std::string>("operation_detect_interaction_acquired");
    auto acquiredInfos = Util::parseIntSequence(acquired);
    int N = acquiredInfos.size();
    int64_t now = Util::getSystemNanoTime();

    int i = 0;
    do {
        auto err = Fingerprint::cfg().get<std::int32_t>("operation_detect_interaction_error");
        if (err != 0) {
            LOG(ERROR) << "Fail: operation_detect_interaction_error";
            auto ec = convertError(err);
            cb->onError(ec.first, ec.second);
            return true;
        }

        if (shouldCancel(cancel)) {
            LOG(ERROR) << "Fail: cancel";
            cb->onError(Error::CANCELED, 0 /* vendorCode */);
            return true;
        }

        if (i < N) {
            auto ac = convertAcquiredInfo(acquiredInfos[i]);
            cb->onAcquired(ac.first, ac.second);
            i++;
        }
        SLEEP_MS(duration / (N + 1));
    } while (!Util::hasElapsed(now, duration));

    cb->onInteractionDetected();

    return true;
}

void FingerprintEngine::enumerateEnrollmentsImpl(ISessionCallback* cb) {
    BEGIN_OP(0);
    if (mIsRbs) {
        uint32_t num_fids = 0;
        uint32_t fids[5] = {};
        int rc = mRbsDevice->rbs_get_fingerprint_ids(mUserId, fids, &num_fids);
        if (rc != 0) {
            LOG(ERROR) << "RBS get_fingerprint_ids failed, error: " << rc;
            cb->onError(Error::UNABLE_TO_PROCESS, rc);
            return;
        }
        std::vector<int32_t> enrollments;
        for (uint32_t i = 0; i < num_fids; i++) {
            enrollments.push_back(fids[i]);
        }
        cb->onEnrollmentsEnumerated(enrollments);
        return;
    }
    int error = mDevice->enumerate(mDevice);
    if (error) {
        LOG(ERROR) << "enumerate failed: " << error;
    }
}

void FingerprintEngine::removeEnrollmentsImpl(ISessionCallback* cb,
                                              const std::vector<int32_t>& enrollmentIds) {
    BEGIN_OP(0);
    if (mIsRbs) {
        if (enrollmentIds.empty()) {
            uint32_t num_fids = 0;
            uint32_t fids[5] = {};
            int rc = mRbsDevice->rbs_get_fingerprint_ids(mUserId, fids, &num_fids);
            if (rc == 0 && num_fids > 0) {
                rc = mRbsDevice->rbs_remove_fingerprint(mUserId, 0);
                if (rc == 0) {
                    std::vector<int32_t> removedIds;
                    for (uint32_t i = 0; i < num_fids; i++) {
                        removedIds.push_back(fids[i]);
                    }
                    cb->onEnrollmentsRemoved(removedIds);
                } else {
                    LOG(ERROR) << "RBS remove failed, error: " << rc;
                    cb->onError(Error::UNABLE_TO_REMOVE, rc);
                }
            } else {
                cb->onEnrollmentsRemoved({});
            }
        } else {
            std::vector<int32_t> removedIds;
            for (int32_t fid : enrollmentIds) {
                int rc = mRbsDevice->rbs_remove_fingerprint(mUserId, fid);
                if (rc == 0) {
                    removedIds.push_back(fid);
                } else {
                    LOG(ERROR) << "RBS remove failed for fid " << fid << ", error: " << rc;
                }
            }
            cb->onEnrollmentsRemoved(removedIds);
        }
        return;
    }
    if (enrollmentIds.empty()) {
        mDevice->remove(mDevice, mUserId, 0);
    } else {
        for (int32_t fid : enrollmentIds) {
            mDevice->remove(mDevice, mUserId, fid);
        }
    }
}

void FingerprintEngine::getAuthenticatorIdImpl(ISessionCallback* cb) {
    BEGIN_OP(0);
    if (mIsRbs) {
        uint64_t auth_id = 0;
        int rc = mRbsDevice->rbs_get_authenticator_id(&auth_id);
        if (rc != 0) {
            LOG(ERROR) << "RBS get_authenticator_id failed, error: " << rc;
        }
        cb->onAuthenticatorIdRetrieved(auth_id);
        return;
    }
    uint64_t auth_id = 0;
    if (mDevice->get_authenticator_id) {
        auth_id = mDevice->get_authenticator_id(mDevice);
    }
    cb->onAuthenticatorIdRetrieved(auth_id);
}

void FingerprintEngine::invalidateAuthenticatorIdImpl(ISessionCallback* cb) {
    BEGIN_OP(0);
    if (mIsRbs) {
        uint64_t new_auth_id = 0;
        int rc = mRbsDevice->rbs_get_authenticator_id(&new_auth_id);
        if (rc != 0) {
            LOG(ERROR) << "RBS get_authenticator_id failed, error: " << rc;
        }
        cb->onAuthenticatorIdInvalidated(new_auth_id);
        return;
    }
    uint64_t new_auth_id = 0;
    if (mDevice->get_authenticator_id) {
        // Fallback: if no dedicated invalidate function, just retrieve current ID
        new_auth_id = mDevice->get_authenticator_id(mDevice);
    }
    cb->onAuthenticatorIdInvalidated(new_auth_id);
}

void FingerprintEngine::resetLockoutImpl(ISessionCallback* cb,
                                         const keymaster::HardwareAuthToken& hat) {
    BEGIN_OP(0);
    if (hat.mac.empty()) {
        LOG(ERROR) << "Fail: hat in resetLockout()";
        cb->onError(Error::UNABLE_TO_PROCESS, 0 /* vendorError */);
        return;
    }
    clearLockout(cb);
    if (isLockoutTimerStarted) isLockoutTimerAborted = true;
}

void FingerprintEngine::clearLockout(ISessionCallback* cb, bool dueToTimeout) {
    Fingerprint::cfg().set<bool>("lockout", false);
    cb->onLockoutCleared();
    mLockoutTracker.reset(dueToTimeout);
}

ndk::ScopedAStatus FingerprintEngine::onPointerDownImpl(int32_t /*pointerId*/, int32_t /*x*/,
                                                        int32_t /*y*/, float /*minor*/,
                                                        float /*major*/) {
    BEGIN_OP(0);
    fingerDownAction();
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngine::onPointerUpImpl(int32_t /*pointerId*/) {
    BEGIN_OP(0);
    mFingerIsDown = false;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus FingerprintEngine::onUiReadyImpl() {
    BEGIN_OP(0);
    return ndk::ScopedAStatus::ok();
}

bool FingerprintEngine::getSensorLocationConfig(std::vector<SensorLocation>& out) {
    auto locStr = Fingerprint::cfg().get<std::string>("sensor_location");
    auto isValidStr = false;

    // sensor_location format: x:y:r:d,x:y:r:d,...
    //   x: x location in pixel, y: y location in pixel, r: radus in pixel, d:display in string
    auto locations = Util::split(locStr, ",");
    for (int i = 0; i < locations.size(); i++) {
        auto loc = locations[i];

        // expect loc in the format: x:y:r  or x:y:d:r
        auto dim = Util::split(loc, ":");

        if (dim.size() < 3) {
            if (!loc.empty()) LOG(WARNING) << "Invalid sensor location input (x:y:radius):" + loc;
            out.clear();
            return false;
        } else {
            int32_t x, y, r;
            std::string d = "";
            if (dim.size() >= 3) {
                isValidStr = ParseInt(dim[0], &x) && ParseInt(dim[1], &y) && ParseInt(dim[2], &r);
            }
            if (dim.size() >= 4) {
                for (int i = 3; i < dim.size(); i++) {
                    if (i > 3) d += ':';
                    d += dim[i];
                }
            }
            if (isValidStr) {
                out.push_back(SensorLocation{.sensorLocationX = x,
                                             .sensorLocationY = y,
                                             .sensorRadius = r,
                                             .display = d});
            }
        }
    }

    LOG(INFO) << "getSensorLocationConfig: isValidStr=" << isValidStr << " locStr=" << locStr;
    if (isValidStr) {
        for (auto loc : out) {
            LOG(INFO) << loc.toString();
        }
    } else {
        out.clear();
    }

    return isValidStr;
}

void FingerprintEngine::getSensorLocation(std::vector<SensorLocation>& location) {
    if (!getSensorLocationConfig(location)) {
        LOG(FATAL) << "getSensorLocation: Failed to retrieve sensor location";
    }
}

std::pair<AcquiredInfo, int32_t> FingerprintEngine::convertAcquiredInfo(int32_t code) {
    std::pair<AcquiredInfo, int32_t> res;
    if (code >= FINGERPRINT_ACQUIRED_VENDOR_BASE) {
        if (code == FINGERPRINT_ACQUIRED_VENDOR_BASE + 8) {
            res.first = AcquiredInfo::TOO_FAST;
            res.second = 0;
        } else if (code == FINGERPRINT_ACQUIRED_VENDOR_BASE + 5 ||
                   code == FINGERPRINT_ACQUIRED_VENDOR_BASE + 6 ||
                   code == FINGERPRINT_ACQUIRED_VENDOR_BASE + 7) {
            res.first = AcquiredInfo::VENDOR;
            res.second = code - FINGERPRINT_ACQUIRED_VENDOR_BASE;
        } else {
            res.first = AcquiredInfo::VENDOR;
            res.second = code - FINGERPRINT_ACQUIRED_VENDOR_BASE;
        }
    } else {
        res.first = (AcquiredInfo)code;
        res.second = 0;
    }
    return res;
}

std::pair<Error, int32_t> FingerprintEngine::convertError(int32_t code) {
    std::pair<Error, int32_t> res;
    if (code >= FINGERPRINT_ERROR_VENDOR_BASE) {
        if (code == FINGERPRINT_ERROR_VENDOR_BASE + 1 ||
            code == FINGERPRINT_ERROR_VENDOR_BASE + 2 ||
            code == FINGERPRINT_ERROR_VENDOR_BASE + 3) {
            res.first = Error::HW_UNAVAILABLE;
            res.second = 0;
        } else if (code == FINGERPRINT_ERROR_VENDOR_BASE + 4 ||
                   code == FINGERPRINT_ERROR_VENDOR_BASE + 5) {
            res.first = Error::UNABLE_TO_PROCESS;
            res.second = 0;
        } else {
            res.first = Error::VENDOR;
            res.second = code - FINGERPRINT_ERROR_VENDOR_BASE;
        }
    } else {
        res.first = (Error)code;
        res.second = 0;
    }
    return res;
}

int32_t FingerprintEngine::getLatency(const std::vector<std::optional<std::int32_t>>& latencyIn) {
    int32_t res = DEFAULT_LATENCY;

    std::vector<int32_t> latency;
    for (auto x : latencyIn)
        if (x.has_value()) latency.push_back(*x);

    switch (latency.size()) {
        case 0:
            break;
        case 1:
            res = latency[0];
            break;
        case 2:
            res = getRandomInRange(latency[0], latency[1]);
            break;
        default:
            LOG(ERROR) << "ERROR: unexpected input of size " << latency.size();
            break;
    }

    return res;
}

int32_t FingerprintEngine::getRandomInRange(int32_t bound1, int32_t bound2) {
    std::uniform_int_distribution<int32_t> dist(std::min(bound1, bound2), std::max(bound1, bound2));
    return dist(mRandom);
}

bool FingerprintEngine::checkSensorLockout(ISessionCallback* cb) {
    LockoutTracker::LockoutMode lockoutMode = mLockoutTracker.getMode();
    if (lockoutMode == LockoutTracker::LockoutMode::kPermanent) {
        LOG(ERROR) << "Fail: lockout permanent";
        cb->onLockoutPermanent();
        isLockoutTimerAborted = true;
        return true;
    } else if (lockoutMode == LockoutTracker::LockoutMode::kTimed) {
        int64_t timeLeft = mLockoutTracker.getLockoutTimeLeft();
        LOG(ERROR) << "Fail: lockout timed " << timeLeft;
        cb->onLockoutTimed(timeLeft);
        if (isLockoutTimerSupported && !isLockoutTimerStarted) startLockoutTimer(timeLeft, cb);
        return true;
    }
    return false;
}

void FingerprintEngine::startLockoutTimer(int64_t timeout, ISessionCallback* cb) {
    BEGIN_OP(0);
    std::function<void(ISessionCallback*)> action =
            std::bind(&FingerprintEngine::lockoutTimerExpired, this, std::placeholders::_1);
    std::thread([timeout, action, cb]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
        action(cb);
    }).detach();

    isLockoutTimerStarted = true;
}
void FingerprintEngine::lockoutTimerExpired(ISessionCallback* cb) {
    BEGIN_OP(0);
    if (!isLockoutTimerAborted) {
        clearLockout(cb, true);
    }
    isLockoutTimerStarted = false;
    isLockoutTimerAborted = false;
}

void FingerprintEngine::waitForFingerDown(ISessionCallback* cb, const std::future<void>& cancel) {
    if (mFingerIsDown) {
        LOG(WARNING) << "waitForFingerDown: mFingerIsDown==true already!";
    }

    while (!mFingerIsDown) {
        if (shouldCancel(cancel)) {
            LOG(ERROR) << "waitForFingerDown, Fail: cancel";
            cb->onError(Error::CANCELED, 0 /* vendorCode */);
            return;
        }
        SLEEP_MS(10);
    }
}

void FingerprintEngine::rbsNotify(uint32_t eventId, uint32_t value1, uint32_t value2, void* buffer, uint32_t buffer_size) {
    if (sInstance) {
        sInstance->handleRbsNotify(eventId, value1, value2, buffer, buffer_size);
    }
}

void FingerprintEngine::handleRbsNotify(uint32_t eventId, uint32_t value1, uint32_t value2, void* buffer, uint32_t /* buffer_size */) {
    LOG(INFO) << "handleRbsNotify: eventId = " << eventId << ", value1 = " << value1 << ", value2 = " << value2;
    fingerprint_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    bool isTerminal = false;

    switch (eventId) {
        // Error
        case 0x3eb:
        case 0x401:
            msg.type = FINGERPRINT_ERROR;
            msg.data.error = FINGERPRINT_ERROR_CANCELED;
            isTerminal = true;
            break;
        case 0x40e:
            msg.type = FINGERPRINT_ERROR;
            msg.data.error = FINGERPRINT_ERROR_TIMEOUT;
            isTerminal = true;
            break;
        // Acquired
        case 0x3ec:
        case 0x3ed:
            msg.type = FINGERPRINT_ACQUIRED;
            msg.data.acquired.acquired_info = FINGERPRINT_ACQUIRED_TOO_SLOW;
            break;
        case 0x3ee:
        case 0x3ef:
            msg.type = FINGERPRINT_ACQUIRED;
            msg.data.acquired.acquired_info = ::FINGERPRINT_ACQUIRED_VENDOR_BASE; // VENDOR
            break;
        case 0x3f5:
            msg.type = FINGERPRINT_ACQUIRED;
            msg.data.acquired.acquired_info = FINGERPRINT_ACQUIRED_INSUFFICIENT;
            break;
        case 0x3f7:
        case 0x3f8:
            msg.type = FINGERPRINT_ACQUIRED;
            msg.data.acquired.acquired_info = FINGERPRINT_ACQUIRED_PARTIAL;
            break;
        case 0x3f9:
        case 0x3fa:
        case 0x3fb:
            msg.type = FINGERPRINT_ACQUIRED;
            msg.data.acquired.acquired_info = FINGERPRINT_ACQUIRED_TOO_FAST;
            break;
        case 0x3fe:
            msg.type = FINGERPRINT_ACQUIRED;
            msg.data.acquired.acquired_info = FINGERPRINT_ACQUIRED_GOOD;
            break;
        // Enrolling
        case 0x40d:
            msg.type = FINGERPRINT_TEMPLATE_ENROLLING;
            msg.data.enroll.finger.fid = value1;
            msg.data.enroll.finger.gid = mUserId;
            msg.data.enroll.samples_remaining = value2;
            if (value2 == 0) {
                isTerminal = true;
            }
            break;
        // Authenticated
        case 0x3f2:
        case 0x3f3:
            msg.type = FINGERPRINT_AUTHENTICATED;
            msg.data.authenticated.finger.gid = value1;
            msg.data.authenticated.finger.fid = value2;
            if (value2 != 0 && buffer != nullptr) {
                memcpy(&msg.data.authenticated.hat, buffer, sizeof(hw_auth_token_t));
            }
            isTerminal = true;
            break;
        default:
            LOG(WARNING) << "handleRbsNotify: unknown eventId " << eventId;
            return;
    }

    if (isTerminal) {
        mWorkMode = WorkMode::kIdle;
    }

    Fingerprint::notify(&msg);
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
