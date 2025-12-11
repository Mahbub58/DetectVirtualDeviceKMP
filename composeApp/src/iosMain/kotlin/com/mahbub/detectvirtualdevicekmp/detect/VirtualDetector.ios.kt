package com.mahbub.detectvirtualdevicekmp.detect

import platform.Foundation.NSProcessInfo
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager
import platform.posix.fopen
import platform.posix.fclose
import platform.Foundation.NSURL
import platform.UIKit.UIApplication

actual object VirtualDetector {
    @OptIn(ExperimentalForeignApi::class)
    actual fun collectSignals(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()

        val env = NSProcessInfo.processInfo.environment
        val hasSimulatorVars = listOf("SIMULATOR_DEVICE_NAME", "SIMULATOR_UDID").any { env[it] != null }
        signals += DetectionSignal(
            id = "ios.env.simulator",
            description = "Simulator environment variables present",
            triggered = hasSimulatorVars,
            weight = 3
        )

        

        val xpcCoreSim = (env["XPC_SERVICE_NAME"] as? String)?.contains("CoreSimulator") == true
        signals += DetectionSignal(
            id = "ios.env.xpc",
            description = "XPC service indicates CoreSimulator",
            triggered = xpcCoreSim,
            weight = 3
        )

        val jailbreakFiles = listOf(
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/usr/bin/ssh"
        )
        val fm = NSFileManager.defaultManager
        val hasJbFiles = jailbreakFiles.any { fm.fileExistsAtPath(it) }
        signals += DetectionSignal(
            id = "ios.fs.jailbreak_files",
            description = "Known jailbreak files exist",
            triggered = hasJbFiles,
            weight = 3
        )

        val writablePrivate = runCatching {
            val file = fopen("/private/jb.txt", "w")
            if (file != null) {
                fclose(file)
                true
            } else false
        }.getOrElse { false }
        signals += DetectionSignal(
            id = "ios.fs.private_writable",
            description = "Writable private path",
            triggered = writablePrivate,
            weight = 3
        )

        val dyldInsert = env["DYLD_INSERT_LIBRARIES"] != null
        signals += DetectionSignal(
            id = "ios.env.dyld_insert",
            description = "DYLD insert libraries present",
            triggered = dyldInsert,
            weight = 3
        )

        return signals
    }

    actual fun collectSignalsWithContext(context: Any?): List<DetectionSignal> {
        return collectSignals()
    }

    
}
