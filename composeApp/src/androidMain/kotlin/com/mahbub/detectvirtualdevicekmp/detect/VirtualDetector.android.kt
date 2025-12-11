package com.mahbub.detectvirtualdevicekmp.detect

import android.os.Build
import java.io.File
import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.telephony.TelephonyManager

actual object VirtualDetector {
    actual fun collectSignals(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()

        val fpGeneric = Build.FINGERPRINT.lowercase().let { it.startsWith("generic") || it.contains("vbox") || it.contains("test-keys") }
        signals += DetectionSignal(
            id = "android.build.fingerprint",
            description = "Build fingerprint indicates emulator",
            triggered = fpGeneric,
            weight = 2
        )

        val modelEmu = Build.MODEL.contains("Emulator", ignoreCase = true) || Build.MODEL.contains("Android SDK built for", ignoreCase = true)
        signals += DetectionSignal(
            id = "android.build.model",
            description = "Model string suggests emulator",
            triggered = modelEmu,
            weight = 2
        )

        val brandDeviceGeneric = Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")
        signals += DetectionSignal(
            id = "android.build.brand_device",
            description = "Generic brand/device",
            triggered = brandDeviceGeneric,
            weight = 1
        )

        val manuGeny = Build.MANUFACTURER.contains("Genymotion", ignoreCase = true)
        signals += DetectionSignal(
            id = "android.build.manufacturer",
            description = "Manufacturer indicates Genymotion",
            triggered = manuGeny,
            weight = 2
        )

        val productSdk = listOf("google_sdk", "sdk_gphone", "sdk", "emulator", "simulator").any { Build.PRODUCT.contains(it, ignoreCase = true) }
        signals += DetectionSignal(
            id = "android.build.product",
            description = "Product string suggests emulator",
            triggered = productSdk,
            weight = 2
        )

        val hardwareEmu = listOf("goldfish", "ranchu", "vbox").any { Build.HARDWARE.contains(it, ignoreCase = true) }
        signals += DetectionSignal(
            id = "android.build.hardware",
            description = "Hardware string indicates emulator",
            triggered = hardwareEmu,
            weight = 3
        )

        val testKeys = Build.TAGS?.contains("test-keys") == true
        signals += DetectionSignal(
            id = "android.build.tags.test_keys",
            description = "Build tags contain test-keys",
            triggered = testKeys,
            weight = 2
        )

        val cpuInfo = readFileSafe("/proc/cpuinfo").lowercase()
        val cpuQemu = cpuInfo.contains("qemu") || cpuInfo.contains("virtualbox") || cpuInfo.contains("bochs")
        signals += DetectionSignal(
            id = "android.proc.cpuinfo",
            description = "CPU info indicates virtualization",
            triggered = cpuQemu,
            weight = 2
        )

        val ttyDrivers = readFileSafe("/proc/tty/drivers").lowercase()
        val goldfish = ttyDrivers.contains("goldfish")
        signals += DetectionSignal(
            id = "android.proc.tty.drivers",
            description = "Goldfish driver present",
            triggered = goldfish,
            weight = 3
        )

        val qemuArtifacts = listOf(
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props"
        ).any { File(it).exists() }
        signals += DetectionSignal(
            id = "android.files.qemu",
            description = "QEMU artifact files exist",
            triggered = qemuArtifacts,
            weight = 2
        )

        val rootArtifacts = listOf(
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/system/app/Superuser.apk",
            "/system/xbin/daemonsu",
            "/sbin/.magisk",
            "/data/adb/magisk"
        ).any { File(it).exists() }
        signals += DetectionSignal(
            id = "android.files.root",
            description = "Root artifacts present",
            triggered = rootArtifacts,
            weight = 3
        )

        return signals
    }

    actual fun collectSignalsWithContext(context: Any?): List<DetectionSignal> {
        val base = collectSignals().toMutableList()
        val ctx = context as? Context
        if (ctx != null) {
            val sm = ctx.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
            val hasAccel = sm?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null
            val hasGyro = sm?.getDefaultSensor(Sensor.TYPE_GYROSCOPE) != null
            base += DetectionSignal(
                id = "android.sensor.accelerometer_missing",
                description = "Accelerometer missing",
                triggered = !hasAccel,
                weight = 1
            )
            base += DetectionSignal(
                id = "android.sensor.gyroscope_missing",
                description = "Gyroscope missing",
                triggered = !hasGyro,
                weight = 1
            )

            val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            val noTelephony = tm?.phoneType == TelephonyManager.PHONE_TYPE_NONE
            base += DetectionSignal(
                id = "android.telephony.none",
                description = "No telephony hardware",
                triggered = noTelephony,
                weight = 1
            )
        }
        return base
    }

    private fun readFileSafe(path: String): String {
        return try {
            val f = File(path)
            if (f.exists() && f.canRead()) f.readText() else ""
        } catch (_: Throwable) {
            ""
        }
    }
}
