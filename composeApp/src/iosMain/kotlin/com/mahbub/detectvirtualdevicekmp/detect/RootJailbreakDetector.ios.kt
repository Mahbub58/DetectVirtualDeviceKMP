package com.mahbub.detectvirtualdevicekmp.detect

import platform.Foundation.NSFileManager
import platform.Foundation.NSProcessInfo
import platform.UIKit.UIApplication
import platform.Foundation.NSURL
import platform.posix.fopen
import platform.posix.fclose
import kotlinx.cinterop.ExperimentalForeignApi

actual object RootJailbreakDetector {
    @OptIn(ExperimentalForeignApi::class)
    actual fun collectSignals(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()

        val fm = NSFileManager.defaultManager
        val paths = listOf(
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/",
            "/private/var/lib/cydia",
            "/var/mobile/Library/Preferences/com.saurik.Cydia.plist"
        )
        val hasFiles = paths.any { fm.fileExistsAtPath(it) }
        signals += DetectionSignal("ios.jb.files","Known jailbreak files",hasFiles,3)

        val writablePrivate = runCatching {
            val f = fopen("/private/jb.txt","w")
            if (f != null) { fclose(f); true } else false
        }.getOrElse { false }
        signals += DetectionSignal("ios.jb.private_writable","Writable private path",writablePrivate,3)

        val env = NSProcessInfo.processInfo.environment
        val dyldInsert = env["DYLD_INSERT_LIBRARIES"] != null
        signals += DetectionSignal("ios.jb.dyld_insert","DYLD insert present",dyldInsert,3)

        val canOpenCydia = runCatching {
            val url = NSURL.URLWithString("cydia://")
            if (url != null) UIApplication.sharedApplication.canOpenURL(url) else false
        }.getOrElse { false }
        signals += DetectionSignal("ios.jb.cydia_scheme","Can open cydia://",canOpenCydia,2)

        val restrictedDirs = listOf(
            "/System/Library/PrivateFrameworks",
            "/usr/libexec/"
        )
        val canAccessRestricted = restrictedDirs.any { fm.fileExistsAtPath(it) }
        signals += DetectionSignal("ios.jb.restricted_access","Access restricted dirs",canAccessRestricted,2)

        return signals
    }

    actual fun collectSignalsWithContext(context: Any?): List<DetectionSignal> {
        return collectSignals()
    }
}
