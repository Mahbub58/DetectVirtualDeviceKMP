package com.mahbub.detectvirtualdevicekmp.detect

import android.app.Application

actual fun getPlatformContext(): Any? {
    return try {
        val cls = Class.forName("android.app.ActivityThread")
        val method = cls.getDeclaredMethod("currentApplication")
        method.invoke(null) as? Application
    } catch (_: Throwable) {
        null
    }
}

