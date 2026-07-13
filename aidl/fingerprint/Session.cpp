/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "Session.h"

#include <android-base/logging.h>

#include "util/CancellationSignal.h"

#undef LOG_TAG
#define LOG_TAG "FingerprintMotorolaSession"

namespace aidl::android::hardware::biometrics::fingerprint {

void onClientDeath(void* cookie) {
    LOG(INFO) << "FingerprintService has died";
    Session* session = static_cast<Session*>(cookie);
    if (session && !session->isClosed()) {
        session->close();
    }
}

Session::Session(int sensorId, int userId, std::shared_ptr<ISessionCallback> cb,
                 FingerprintEngine* engine, WorkerThread* worker)
    : mSensorId(sensorId),
      mUserId(userId),
      mCb(std::move(cb)),
      mEngine(engine),
      mWorker(worker),
      mScheduledState(SessionState::IDLING),
      mCurrentState(SessionState::IDLING) {
    CHECK_GE(mSensorId, 0);
    CHECK_GE(mUserId, 0);
    CHECK(mEngine);
    CHECK(mWorker);
    CHECK(mCb);

    mDeathRecipient = AIBinder_DeathRecipient_new(onClientDeath);
    mEngine->setActiveGroup(mUserId);
}

binder_status_t Session::linkToDeath(AIBinder* binder) {
    return AIBinder_linkToDeath(binder, mDeathRecipient, this);
}

void Session::scheduleStateOrCrash(SessionState state) {
    // TODO(b/166800618): call enterIdling from the terminal callbacks and restore these checks.
    // CHECK(mScheduledState == SessionState::IDLING);
    // CHECK(mCurrentState == SessionState::IDLING);
    mScheduledState = state;
}

void Session::enterStateOrCrash(SessionState state) {
    mCurrentState = state;
    mScheduledState = SessionState::IDLING;
}

void Session::enterIdling() {
    // TODO(b/166800618): call enterIdling from the terminal callbacks and rethink this conditional.
    if (mCurrentState != SessionState::CLOSED) {
        mCurrentState = SessionState::IDLING;
    }
}

bool Session::isClosed() {
    return mCurrentState == SessionState::CLOSED;
}

ndk::ScopedAStatus Session::generateChallenge() {
    LOG(INFO) << "generateChallenge";
    scheduleStateOrCrash(SessionState::GENERATING_CHALLENGE);

    mWorker->schedule(Callable::from([this] {
        enterStateOrCrash(SessionState::GENERATING_CHALLENGE);
        mEngine->generateChallengeImpl(mCb.get());
        enterIdling();
    }));

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::revokeChallenge(int64_t challenge) {
    LOG(INFO) << "revokeChallenge";
    scheduleStateOrCrash(SessionState::REVOKING_CHALLENGE);

    mWorker->schedule(Callable::from([this, challenge] {
        enterStateOrCrash(SessionState::REVOKING_CHALLENGE);
        mEngine->revokeChallengeImpl(mCb.get(), challenge);
        enterIdling();
    }));

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::enroll(const keymaster::HardwareAuthToken& hat,
                                   std::shared_ptr<common::ICancellationSignal>* out) {
    LOG(INFO) << "enroll";
    scheduleStateOrCrash(SessionState::ENROLLING);

    std::promise<void> cancellationPromise;
    auto cancFuture = cancellationPromise.get_future();

    mWorker->schedule(Callable::from([this, hat, cancFuture = std::move(cancFuture)] {
        enterStateOrCrash(SessionState::ENROLLING);
        if (shouldCancel(cancFuture)) {
            mCb->onError(Error::CANCELED, 0 /* vendorCode */);
        } else {
            mEngine->enrollImpl(mCb.get(), hat, cancFuture);
        }
        enterIdling();
    }));

    *out = SharedRefBase::make<CancellationSignal>(std::move(cancellationPromise));
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::authenticate(int64_t operationId,
                                         std::shared_ptr<common::ICancellationSignal>* out) {
    LOG(INFO) << "authenticate";
    scheduleStateOrCrash(SessionState::AUTHENTICATING);

    std::promise<void> cancPromise;
    auto cancFuture = cancPromise.get_future();

    mWorker->schedule(Callable::from([this, operationId, cancFuture = std::move(cancFuture)] {
        enterStateOrCrash(SessionState::AUTHENTICATING);
        if (shouldCancel(cancFuture)) {
            mCb->onError(Error::CANCELED, 0 /* vendorCode */);
        } else {
            mEngine->authenticateImpl(mCb.get(), operationId, cancFuture);
        }
        enterIdling();
    }));

    *out = SharedRefBase::make<CancellationSignal>(std::move(cancPromise));
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::detectInteraction(std::shared_ptr<common::ICancellationSignal>* out) {
    LOG(INFO) << "detectInteraction";
    scheduleStateOrCrash(SessionState::DETECTING_INTERACTION);

    std::promise<void> cancellationPromise;
    auto cancFuture = cancellationPromise.get_future();

    mWorker->schedule(Callable::from([this, cancFuture = std::move(cancFuture)] {
        enterStateOrCrash(SessionState::DETECTING_INTERACTION);
        if (shouldCancel(cancFuture)) {
            mCb->onError(Error::CANCELED, 0 /* vendorCode */);
        } else {
            mEngine->detectInteractionImpl(mCb.get(), cancFuture);
        }
        enterIdling();
    }));

    *out = SharedRefBase::make<CancellationSignal>(std::move(cancellationPromise));
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::enumerateEnrollments() {
    LOG(INFO) << "enumerateEnrollments";
    scheduleStateOrCrash(SessionState::ENUMERATING_ENROLLMENTS);

    mWorker->schedule(Callable::from([this] {
        enterStateOrCrash(SessionState::ENUMERATING_ENROLLMENTS);
        mAccumulatedEnrollments.clear();
        mEngine->enumerateEnrollmentsImpl(mCb.get());
        enterIdling();
    }));

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::removeEnrollments(const std::vector<int32_t>& enrollmentIds) {
    LOG(INFO) << "removeEnrollments, size:" << enrollmentIds.size();
    scheduleStateOrCrash(SessionState::REMOVING_ENROLLMENTS);

    mWorker->schedule(Callable::from([this, enrollmentIds] {
        enterStateOrCrash(SessionState::REMOVING_ENROLLMENTS);
        mAccumulatedRemoved.clear();
        mEngine->removeEnrollmentsImpl(mCb.get(), enrollmentIds);
        enterIdling();
    }));

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::getAuthenticatorId() {
    LOG(INFO) << "getAuthenticatorId";
    scheduleStateOrCrash(SessionState::GETTING_AUTHENTICATOR_ID);

    mWorker->schedule(Callable::from([this] {
        enterStateOrCrash(SessionState::GETTING_AUTHENTICATOR_ID);
        mEngine->getAuthenticatorIdImpl(mCb.get());
        enterIdling();
    }));

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::invalidateAuthenticatorId() {
    LOG(INFO) << "invalidateAuthenticatorId";
    scheduleStateOrCrash(SessionState::INVALIDATING_AUTHENTICATOR_ID);

    mWorker->schedule(Callable::from([this] {
        enterStateOrCrash(SessionState::INVALIDATING_AUTHENTICATOR_ID);
        mEngine->invalidateAuthenticatorIdImpl(mCb.get());
        enterIdling();
    }));

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::resetLockout(const keymaster::HardwareAuthToken& hat) {
    LOG(INFO) << "resetLockout";
    scheduleStateOrCrash(SessionState::RESETTING_LOCKOUT);

    mWorker->schedule(Callable::from([this, hat] {
        enterStateOrCrash(SessionState::RESETTING_LOCKOUT);
        mEngine->resetLockoutImpl(mCb.get(), hat);
        enterIdling();
    }));

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::close() {
    LOG(INFO) << "close";
    // TODO(b/166800618): call enterIdling from the terminal callbacks and restore this check.
    // CHECK(mCurrentState == SessionState::IDLING) << "Can't close a non-idling session.
    // Crashing.";
    mEngine->isLockoutTimerAborted = true;  // Cancel any pending lockout timer
    mCurrentState = SessionState::CLOSED;
    mCb->onSessionClosed();
    AIBinder_DeathRecipient_delete(mDeathRecipient);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerDown(int32_t pointerId, int32_t x, int32_t y, float minor,
                                          float major) {
    LOG(INFO) << "onPointerDown";
    mEngine->notifyFingerdown();
    mWorker->schedule(Callable::from([this, pointerId, x, y, minor, major] {
        mEngine->onPointerDownImpl(pointerId, x, y, minor, major);
        enterIdling();
    }));
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerUp(int32_t pointerId) {
    LOG(INFO) << "onPointerUp";
    mWorker->schedule(Callable::from([this, pointerId] {
        mEngine->onPointerUpImpl(pointerId);
        enterIdling();
    }));
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onUiReady() {
    LOG(INFO) << "onUiReady";
    mWorker->schedule(Callable::from([this] {
        mEngine->onUiReadyImpl();
        enterIdling();
    }));
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::authenticateWithContext(
        int64_t operationId, const common::OperationContext& /*context*/,
        std::shared_ptr<common::ICancellationSignal>* out) {
    return authenticate(operationId, out);
}

ndk::ScopedAStatus Session::enrollWithContext(const keymaster::HardwareAuthToken& hat,
                                              const common::OperationContext& /*context*/,
                                              std::shared_ptr<common::ICancellationSignal>* out) {
    return enroll(hat, out);
}

ndk::ScopedAStatus Session::detectInteractionWithContext(
        const common::OperationContext& /*context*/,
        std::shared_ptr<common::ICancellationSignal>* out) {
    return detectInteraction(out);
}

ndk::ScopedAStatus Session::onPointerDownWithContext(const PointerContext& context) {
    return onPointerDown(context.pointerId, context.x, context.y, context.minor, context.major);
}

ndk::ScopedAStatus Session::onPointerUpWithContext(const PointerContext& context) {
    return onPointerUp(context.pointerId);
}

ndk::ScopedAStatus Session::onContextChanged(const common::OperationContext& /*context*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerCancelWithContext(const PointerContext& /*context*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::setIgnoreDisplayTouches(bool /*shouldIgnore*/) {
    return ndk::ScopedAStatus::ok();
}

// Translate from errors returned by traditional HAL (see fingerprint.h) to
// AIDL-compliant Error
Error Session::VendorErrorFilter(int32_t error, int32_t* vendorCode) {
    *vendorCode = 0;

    switch (error) {
        case FINGERPRINT_ERROR_HW_UNAVAILABLE:
        case FINGERPRINT_ERROR_VENDOR_BASE + 1:
        case FINGERPRINT_ERROR_VENDOR_BASE + 2:
        case FINGERPRINT_ERROR_VENDOR_BASE + 3:
            return Error::HW_UNAVAILABLE;
        case FINGERPRINT_ERROR_UNABLE_TO_PROCESS:
        case FINGERPRINT_ERROR_VENDOR_BASE + 4:
        case FINGERPRINT_ERROR_VENDOR_BASE + 5:
            return Error::UNABLE_TO_PROCESS;
        case FINGERPRINT_ERROR_TIMEOUT:
            return Error::TIMEOUT;
        case FINGERPRINT_ERROR_NO_SPACE:
            return Error::NO_SPACE;
        case FINGERPRINT_ERROR_CANCELED:
            return Error::CANCELED;
        case FINGERPRINT_ERROR_UNABLE_TO_REMOVE:
            return Error::UNABLE_TO_REMOVE;
        case FINGERPRINT_ERROR_LOCKOUT: {
            *vendorCode = FINGERPRINT_ERROR_LOCKOUT;
            return Error::VENDOR;
        }
        default:
            if (error >= FINGERPRINT_ERROR_VENDOR_BASE) {
                // vendor specific code.
                *vendorCode = error - FINGERPRINT_ERROR_VENDOR_BASE;
                return Error::VENDOR;
            }
    }
    LOG(ERROR) << "Unknown error from fingerprint vendor library: " << error;
    return Error::UNABLE_TO_PROCESS;
}

// Translate acquired messages returned by traditional HAL (see fingerprint.h)
// to AIDL-compliant AcquiredInfo
AcquiredInfo Session::VendorAcquiredFilter(int32_t info, int32_t* vendorCode) {
    *vendorCode = 0;

    switch (info) {
        case FINGERPRINT_ACQUIRED_GOOD:
            return AcquiredInfo::GOOD;
        case FINGERPRINT_ACQUIRED_PARTIAL:
            return AcquiredInfo::PARTIAL;
        case FINGERPRINT_ACQUIRED_INSUFFICIENT:
            return AcquiredInfo::INSUFFICIENT;
        case FINGERPRINT_ACQUIRED_IMAGER_DIRTY:
            return AcquiredInfo::SENSOR_DIRTY;
        case FINGERPRINT_ACQUIRED_TOO_SLOW:
            return AcquiredInfo::TOO_SLOW;
        case FINGERPRINT_ACQUIRED_TOO_FAST:
        case FINGERPRINT_ACQUIRED_VENDOR_BASE + 8:
            return AcquiredInfo::TOO_FAST;
        case FINGERPRINT_ACQUIRED_VENDOR_BASE + 5:
        case FINGERPRINT_ACQUIRED_VENDOR_BASE + 6:
        case FINGERPRINT_ACQUIRED_VENDOR_BASE + 7:
            *vendorCode = info - FINGERPRINT_ACQUIRED_VENDOR_BASE;
            return AcquiredInfo::VENDOR;
        default:
            if (info >= FINGERPRINT_ACQUIRED_VENDOR_BASE) {
                // vendor specific code.
                *vendorCode = info - FINGERPRINT_ACQUIRED_VENDOR_BASE;
                return AcquiredInfo::VENDOR;
            }
    }

    LOG(ERROR) << "Unknown acquired message from fingerprint vendor library: " << info;
    return AcquiredInfo::INSUFFICIENT;
}

void Session::notify(const fingerprint_msg_t* msg) {
    fingerprint_msg_t msgCopy = *msg;
    mWorker->schedule(Callable::from([this, msgCopy]() mutable {
        processHalMessage(&msgCopy);
    }));
}

void Session::processHalMessage(const fingerprint_msg_t* msg) {
    switch (msg->type) {
        case FINGERPRINT_ERROR: {
            int32_t vendorCode = 0;
            Error result = VendorErrorFilter(msg->data.error, &vendorCode);
            LOG(INFO) << "onError(" << static_cast<int>(result) << ", " << vendorCode << ")";
            mCb->onError(result, vendorCode);
        } break;
        case FINGERPRINT_ACQUIRED: {
            int32_t vendorCode = 0;
            AcquiredInfo result =
                    VendorAcquiredFilter(msg->data.acquired.acquired_info, &vendorCode);
            LOG(INFO) << "onAcquired(" << static_cast<int>(result) << ", " << vendorCode << ")";
            // Filter specific vendor codes that cause framework to incorrectly disable
            // UDFPS display mode during processing. Pass through other vendor messages
            // that may contain useful user feedback.
            if (result == AcquiredInfo::VENDOR && (vendorCode >= 5 && vendorCode <= 7)) {
                LOG(DEBUG) << "Filtering vendor acquired code " << vendorCode;
            } else {
                mCb->onAcquired(result, vendorCode);
            }
        } break;
        case FINGERPRINT_TEMPLATE_ENROLLING: {
            LOG(INFO) << "onEnrollResult(fid=" << msg->data.enroll.finger.fid
                      << ", rem=" << msg->data.enroll.samples_remaining << ")";
            mCb->onEnrollmentProgress(msg->data.enroll.finger.fid, msg->data.enroll.samples_remaining);
        } break;
        case FINGERPRINT_TEMPLATE_REMOVED: {
            // Goodix HAL on some Motorola devices sends all removed fingers in a single array.
            // Check if the second element has a valid finger ID to detect this format.
            if (msg->data.removed.fingers[1].fid != 0) {
                std::vector<int32_t> enrollments;
                for (unsigned int i = 0; i < NUM_FINGERS; i++) {
                    int32_t fid = msg->data.removed.fingers[i].fid;
                    if (!fid) break;
                    LOG(DEBUG) << "onRemove(fid=" << fid << ")";
                    enrollments.push_back(fid);
                }
                mCb->onEnrollmentsRemoved(enrollments);
            } else {
                int32_t fid = msg->data.removed.fingers[0].fid;
                uint32_t remaining = msg->data.removed.fingers[1].gid;

                if (fid != 0) {
                    mAccumulatedRemoved.push_back(fid);
                    LOG(DEBUG) << "onRemove accumulated(fid=" << fid << ", remaining=" << remaining << ")";
                }

                if (remaining == 0) {
                    mCb->onEnrollmentsRemoved(mAccumulatedRemoved);
                    mAccumulatedRemoved.clear();
                }
            }
        } break;
        case FINGERPRINT_AUTHENTICATED: {
            LOG(INFO) << "onAuthenticated(fid=" << msg->data.authenticated.finger.fid << ")";
            if (msg->data.authenticated.finger.fid != 0) {
                const hw_auth_token_t hat = msg->data.authenticated.hat;
                keymaster::HardwareAuthToken authToken;
                translate(hat, authToken);

                mCb->onAuthenticationSucceeded(msg->data.authenticated.finger.fid, authToken);
                mEngine->mLockoutTracker.reset(true);
            } else {
                mCb->onAuthenticationFailed();
                mEngine->mLockoutTracker.addFailedAttempt();
                mEngine->checkSensorLockout(mCb.get());
            }
            mEngine->onPointerUpImpl(0);
        } break;
        case FINGERPRINT_TEMPLATE_ENUMERATING: {
            // Goodix HAL on some Motorola devices sends all enumerated fingers in a single array.
            // Check if the second element has a valid finger ID to detect this format.
            if (msg->data.enumerated.fingers[1].fid != 0) {
                std::vector<int32_t> enrollments;
                for (unsigned int i = 0; i < NUM_FINGERS; i++) {
                    int32_t fid = msg->data.enumerated.fingers[i].fid;
                    if (!fid) break;
                    LOG(DEBUG) << "onEnumerate(fid=" << fid << ")";
                    enrollments.push_back(fid);
                }
                mCb->onEnrollmentsEnumerated(enrollments);
            } else {
                int32_t fid = msg->data.enumerated.fingers[0].fid;
                uint32_t remaining = msg->data.enumerated.fingers[1].gid;

                if (fid != 0) {
                    mAccumulatedEnrollments.push_back(fid);
                    LOG(DEBUG) << "onEnumerate accumulated(fid=" << fid << ", remaining=" << remaining << ")";
                }

                if (remaining == 0) {
                    mCb->onEnrollmentsEnumerated(mAccumulatedEnrollments);
                    mAccumulatedEnrollments.clear();
                }
            }
        } break;
        case FINGERPRINT_GENERATE_CHALLENGE: {
            int64_t challenge = msg->data.data;
            LOG(INFO) << "onChallengeGenerated: " << challenge;
            mCb->onChallengeGenerated(challenge);
        } break;
        case FINGERPRINT_REVOKE_CHALLENGE: {
            int64_t challenge = msg->data.data;
            LOG(INFO) << "onChallengeRevoked: " << challenge;
            mCb->onChallengeRevoked(challenge);
        } break;
        case FINGERPRINT_GET_AUTHENTICATOR_ID: {
            int auth_id = msg->data.data;
            LOG(INFO) << "onAuthenticatorIDRetrieved: " << auth_id;
            mEngine->onPointerUpImpl(0);
            mCb->onAuthenticatorIdRetrieved(auth_id);
        } break;
        case FINGERPRINT_INVALIDATE_AUTHENTICATOR_ID: {
            int64_t new_auth_id = msg->data.data;
            LOG(INFO) << "onAuthenticatorIDInvalidated, new auth id: " << new_auth_id;
            mCb->onAuthenticatorIdInvalidated(new_auth_id);
        } break;
        default:
            LOG(ERROR) << "received unknown message: " << msg->type;
    }
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
