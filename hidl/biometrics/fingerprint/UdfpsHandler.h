/*
 * Copyright (C) 2026 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>

class UdfpsHandler {
  public:
    virtual ~UdfpsHandler() = default;

    virtual void onFingerDown(uint32_t x, uint32_t y, float minor, float major) = 0;
    virtual void onFingerUp() = 0;
    virtual void cancel() = 0;
};

struct UdfpsHandlerFactory {
    UdfpsHandler* (*create)();
    void (*destroy)(UdfpsHandler* handler);
};

UdfpsHandlerFactory* getUdfpsHandlerFactory();
