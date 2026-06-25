/*
 * Copyright (C) 2026 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "UdfpsHandler.h"
#include <dlfcn.h>
#include <android/log.h>

#define LOG_TAG "libudfpshandlerfactory"
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define UDFPS_HANDLER_LIB_NAME "libudfpshandler.so"
#define UDFPS_HANDLER_FACTORY "UDFPS_HANDLER_FACTORY"

UdfpsHandlerFactory* getUdfpsHandlerFactory() {
    void* libudfpshander = dlopen(UDFPS_HANDLER_LIB_NAME, RTLD_LAZY);
    if (!libudfpshander) {
        ALOGE("Failed to dlopen %s: %s", UDFPS_HANDLER_LIB_NAME, dlerror());
        return nullptr;
    }

    UdfpsHandlerFactory* factory_handler = (UdfpsHandlerFactory*)dlsym(libudfpshander, UDFPS_HANDLER_FACTORY);
    if (!factory_handler) {
        ALOGE("Failed to dlsym %s: %s", UDFPS_HANDLER_FACTORY, dlerror());
        dlclose(libudfpshander);
        return nullptr;
    }

    return factory_handler;
}
