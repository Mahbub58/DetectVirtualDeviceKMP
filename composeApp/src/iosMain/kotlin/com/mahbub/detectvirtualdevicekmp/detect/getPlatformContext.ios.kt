package com.mahbub.detectvirtualdevicekmp.detect

import platform.UIKit.UIApplication

actual fun getPlatformContext(): Any? = UIApplication.sharedApplication

