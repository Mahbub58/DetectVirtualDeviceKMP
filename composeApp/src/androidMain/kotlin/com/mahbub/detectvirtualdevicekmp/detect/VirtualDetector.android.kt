package com.mahbub.detectvirtualdevicekmp.detect

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorManager
import android.net.wifi.WifiManager
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import android.telephony.TelephonyManager
import androidx.core.content.ContextCompat
import java.io.File
import java.net.NetworkInterface
import java.util.regex.Pattern

actual object VirtualDetector {

    private val EMULATOR_HARDWARE = setOf("goldfish", "ranchu", "vbox86", "qemu", "simics", "ttVM_Haxm")
    private val EMULATOR_PRODUCTS = setOf(
        "sdk", "google_sdk", "sdk_gphone", "sdk_google", "emulator", "simulator",
        "android_x86", "vbox86p", "full_x86", "nox", "bluestacks", "ldplayer", "memu",
        "sdk_gphone64_arm64", "sdk_gphone_x86", "aosp_x86"
    )
    private val EMULATOR_MANUFACTURERS = setOf(
        "genymotion", "genuineintel", "nox", "bluestacks", "memu", "ldplayer",
        "andy", "phoenixos", "google", "netease"
    )
    private val EMULATOR_BRANDS = setOf("generic", "android-x86", "nox", "bluestacks", "google")

    private val QEMU_PIPES = arrayOf(
        "/dev/qemu_pipe",
        "/dev/socket/qemud",
        "/dev/socket/baseband_genyd",
        "/dev/socket/genyd",
        "/dev/goldfish_pipe"
    )

    private val EMULATOR_FILES = arrayOf(
        "/system/lib/libdroid4x.so",
        "/system/bin/nox-prop",
        "/system/bin/ldplayer-prop",
        "/system/priv-app/BluestacksServices",
        "/system/bin/microvirt-prop",
        "/system/bin/windroyed",
        "/ueventd.android_x86.rc",
        "/init.android_x86.rc",
        "/system/etc/init.d/01bluestacks",
        "/system/bin/priv-app/MEmuServices",
        "/data/data/com.microvirt.guestservices",
        "/system/app/GenyMotion",
        "/system/lib/libgenymotion.so",
        "/fstab.vbox86",
        "/init.vbox86.rc",
        "/ueventd.vbox86.rc"
    )

    private val ROOT_BINARIES = arrayOf(
        "/system/xbin/su",
        "/system/bin/su",
        "/system/sbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su"
    )

    private val MAGISK_FILES = arrayOf(
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/data/adb/magisk.img",
        "/data/adb/magisk.db",
        "/data/adb/magisk_simple"
    )

    actual fun collectSignals(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()

        // === Build Properties ===
        signals += checkBuildFingerprint()
        signals += checkBuildModel()
        signals += checkBuildHardware()
        signals += checkBuildProduct()
        signals += checkBuildManufacturerAndBrand()
        signals += checkBuildTags()
        signals += checkBuildBoard()
        signals += checkBuildDevice()
        signals += checkBuildHost()
        signals += checkBuildRadioVersion()
//        println("VirtualDetector"+" checkBuildFingerprint: ${checkBuildFingerprint()}")
//        println("VirtualDetector"+" checkBuildModel: ${checkBuildModel()}")
//        println("VirtualDetector"+" checkBuildHardware: ${checkBuildHardware()}")
//        println("VirtualDetector"+" checkBuildProduct: ${checkBuildProduct()}")
//        println("VirtualDetector"+" checkBuildManufacturerAndBrand: ${checkBuildManufacturerAndBrand()}")
//        println("VirtualDetector"+" checkBuildTags: ${checkBuildTags()}")
//        println("VirtualDetector"+" checkBuildBoard: ${checkBuildBoard()}")
//        println("VirtualDetector"+" checkBuildDevice: ${checkBuildDevice()}")
//        println("VirtualDetector"+" checkBuildHost: ${checkBuildHost()}")
//        println("VirtualDetector"+" checkBuildRadioVersion: ${checkBuildRadioVersion()}")



        //Root or file Masking
        signals += checkRootBinaries()
        signals += checkMagiskFiles()



        // === System Properties ===
        val props = readGetProp()
//        signals += checkRoKernelQemu(props)
//        signals += checkRoBootmode(props)
        signals += checkRoSecure(props)
        signals += checkRoDebuggable(props)
        signals += checkQemuHwMainkeys(props)
        signals += checkInitSvc(props)
        signals += checkVirtualizationProps(props)
        signals += checkEmulatorProps(props)
//        println("VirtualDetector"+" checkRoKernelQemu: ${checkRoKernelQemu(props)}")
//        println("VirtualDetector"+" checkRoBootmode: ${checkRoBootmode(props)}")
//        println("VirtualDetector"+" checkRoSecure: ${checkRoSecure(props)}")
//        println("VirtualDetector"+" checkRoDebuggable: ${checkRoDebuggable(props)}")
//        println("VirtualDetector"+" checkQemuHwMainkeys: ${checkQemuHwMainkeys(props)}")
//        println("VirtualDetector"+" checkInitSvc: ${checkInitSvc(props)}")
//        println("VirtualDetector"+" checkVirtualizationProps: ${checkVirtualizationProps(props)}")
//        println("VirtualDetector"+" checkEmulatorProps: ${checkEmulatorProps(props)}")



        // === File System Checks ===
        signals += checkQemuPipes()
        signals += checkEmulatorFiles()
        signals += checkCpuInfo()
        signals += checkTtyDrivers()
        signals += checkMounts()
        signals += checkPartitions()
//        println("VirtualDetector"+" checkQemuPipes: ${checkQemuPipes()}")
//        println("VirtualDetector"+" checkEmulatorFiles: ${checkEmulatorFiles()}")
//        println("VirtualDetector"+" checkCpuInfo: ${checkCpuInfo()}")
//        println("VirtualDetector"+" checkTtyDrivers: ${checkTtyDrivers()}")
//        println("VirtualDetector"+" checkMounts: ${checkMounts()}")
//        println("VirtualDetector"+" checkPartitions: ${checkPartitions()}")




        // === Network ===
        signals += checkDefaultMacAddress()
        signals += checkVirtualNetworkInterfaces()
        signals += checkIpAddress()
//        println("VirtualDetector"+" checkDefaultMacAddress: ${checkDefaultMacAddress()}")
//        println("VirtualDetector"+" checkVirtualNetworkInterfaces: ${checkVirtualNetworkInterfaces()}")
//        println("VirtualDetector"+" checkIpAddress: ${checkIpAddress()}")




        // === ABI & Architecture ===
        signals += checkX86OnArmDevice()
        signals += checkAbiCount()
//        println("VirtualDetector"+" checkX86OnArmDevice: ${checkX86OnArmDevice()}")
//        println("VirtualDetector"+" checkAbiCount: ${checkAbiCount()}")


        // === Hardware Characteristics ===
        signals += checkProcessorCount()
        signals += checkMemorySize()
        signals += checkScreenDensity()
//        println("VirtualDetector"+" checkProcessorCount: ${checkProcessorCount()}")
//        println("VirtualDetector"+" checkMemorySize: ${checkMemorySize()}")
//        println("VirtualDetector"+" checkScreenDensity: ${checkScreenDensity()}")

        // === Vendor-specific Hints ===
        signals += checkKnownEmulatorVendors()
//        println("VirtualDetector"+" checkKnownEmulatorVendors: ${checkKnownEmulatorVendors()}")
//        println("VirtualDetector"+" checkKnownEmulatorVendors: ${checkKnownEmulatorVendors()}")



        // === Timing and Performance ===
        signals += checkBootTime()
       // println("VirtualDetector"+" checkBootTime: ${checkBootTime()}")

        signals.filter { it.triggered }.forEach {
            println("VirtualDetector ${it.description} ${it.id} weight=${it.weight} triggered=${it.triggered}")
        }
        return signals.filter { it.triggered }
    }

    actual fun collectSignalsWithContext(context: Any?): List<DetectionSignal> {
        val signals = collectSignals().toMutableList()
        val ctx = context as? Context ?: return signals

        signals += checkSensors(ctx)
        signals += checkTelephony(ctx)
        signals += checkBatteryStatus(ctx)
        signals += checkPowerThermalState(ctx)
        signals += checkGpsStatus(ctx)
        signals += checkLightAndMagneticSensors(ctx)
        signals += checkWifiMacAddress(ctx)
        signals += checkBluetoothAdapter(ctx)
        signals += checkCameraFeatures(ctx)
        signals += checkNfcFeature(ctx)
        signals += checkAndroidId(ctx)
        signals += checkDrmInfo(ctx)
        signals += checkMultiTouch(ctx)
        signals += checkUSBAccessories(ctx)

        signals.filter { it.triggered }.forEach {
            println("VirtualDetectorContext ${it.id} weight=${it.weight} triggered=${it.triggered}")
        }
        return signals
    }


    /**
     *  Individual Checks
      */



    private fun checkBuildFingerprint(): DetectionSignal = DetectionSignal(
        id = "build.fingerprint.generic",
        description = "Generic or test-keys fingerprint",
        triggered = Build.FINGERPRINT.let {
            it.startsWith("generic", ignoreCase = true) ||
                    it.contains("vbox", ignoreCase = true) ||
                    it.contains("test-keys", ignoreCase = true) ||
                    it.contains("/sdk_gphone") ||
                    it.contains("/emulator") ||
                    it.contains("unknown", ignoreCase = true)
        },

        weight = 3
    )

    private fun checkBuildModel(): DetectionSignal = DetectionSignal(
        id = "build.model.emulator",
        description = "Model indicates emulator",
        triggered = Build.MODEL.let {
            it.contains("emulator", ignoreCase = true) ||
                    it.contains("sdk", ignoreCase = true) ||
                    it.contains("android sdk built for", ignoreCase = true) ||
                    it.equals("google_sdk", ignoreCase = true)
        },
        weight = 2
    )

    private fun checkBuildHardware(): DetectionSignal = DetectionSignal(
        id = "build.hardware.virtual",
        description = "Hardware is goldfish/ranchu/vbox/qemu",
        triggered = EMULATOR_HARDWARE.any { Build.HARDWARE.contains(it, ignoreCase = true) },
        weight = 4
    )

    private fun checkBuildProduct(): DetectionSignal = DetectionSignal(
        id = "build.product.emulator",
        description = "Product name indicates emulator",
        triggered = EMULATOR_PRODUCTS.any { Build.PRODUCT.contains(it, ignoreCase = true) },
        weight = 3
    )

    private fun checkBuildManufacturerAndBrand(): DetectionSignal {
        val isSuspicious = EMULATOR_MANUFACTURERS.any { Build.MANUFACTURER.contains(it, ignoreCase = true) } ||
                EMULATOR_BRANDS.any { Build.BRAND.contains(it, ignoreCase = true) } ||
                (Build.BRAND.equals("generic", ignoreCase = true) && Build.DEVICE.startsWith("generic"))

        return DetectionSignal(
            id = "build.brand_manufacturer.generic",
            description = "Generic or known emulator brand/manufacturer",
            triggered = isSuspicious,
            weight = 2
        )
    }

    private fun checkBuildTags(): DetectionSignal = DetectionSignal(
        id = "build.tags.testkeys",
        description = "Build tags contain test-keys",
        triggered = Build.TAGS?.contains("test-keys", ignoreCase = true) == true,
        weight = 2
    )

    private fun checkBuildBoard(): DetectionSignal = DetectionSignal(
        id = "build.board.virtual",
        description = "Board name is unknown or virtual",
        triggered = Build.BOARD.let {
            it.isBlank() || it.lowercase() in setOf("unknown", "android", "qc_reference_phone", "goldfish")
        },
        weight = 1
    )

    private fun checkBuildDevice(): DetectionSignal = DetectionSignal(
        id = "build.device.generic",
        description = "Device name is generic",
        triggered = Build.DEVICE.let {
            it.startsWith("generic", ignoreCase = true) ||
                    it.contains("vbox", ignoreCase = true) ||
                    it.contains("emulator", ignoreCase = true)
        },
        weight = 2
    )

    private fun checkBuildHost(): DetectionSignal = DetectionSignal(
        id = "build.host.suspicious",
        description = "Build host suggests emulator build",
        triggered = Build.HOST.let {
            it.contains("ubuntu", ignoreCase = true) ||
                    it.contains("google.com", ignoreCase = true) ||
                    it.contains("android.com", ignoreCase = true)
        },
        weight = 1
    )

    private fun checkBuildRadioVersion(): DetectionSignal = DetectionSignal(
        id = "build.radio.missing",
        description = "No radio/baseband version",
        triggered = Build.getRadioVersion().isNullOrBlank(),
        weight = 2
    )

    private fun checkRoKernelQemu(props: Map<String, String>): DetectionSignal = DetectionSignal(
        id = "prop.ro.kernel.qemu",
        description = "ro.kernel.qemu=1",
        triggered = props["ro.kernel.qemu"] == "1" || props["ro.kernel.qemu.gles"] != null,
        weight = 5
    )

    private fun checkRoBootmode(props: Map<String, String>): DetectionSignal = DetectionSignal(
        id = "prop.ro.bootmode",
        description = "ro.bootmode=unknown (common in emulators)",
        triggered = props["ro.bootmode"] == "unknown",
        weight = 2
    )

    private fun checkRoSecure(props: Map<String, String>): DetectionSignal = DetectionSignal(
        id = "prop.ro.secure",
        description = "ro.secure=0 (insecure mode)",
        triggered = props["ro.secure"] == "0",
        weight = 2
    )

    private fun checkRoDebuggable(props: Map<String, String>): DetectionSignal = DetectionSignal(
        id = "prop.ro.debuggable",
        description = "ro.debuggable=1",
        triggered = props["ro.debuggable"] == "1",
        weight = 3
    )

    private fun checkQemuHwMainkeys(props: Map<String, String>): DetectionSignal = DetectionSignal(
        id = "prop.qemu.hw.mainkeys",
        description = "qemu.hw.mainkeys property exists",
        triggered = props.containsKey("qemu.hw.mainkeys"),
        weight = 3
    )

    private fun checkVirtualizationProps(props: Map<String, String>): DetectionSignal {
        val virtualProps = listOf(
            "ro.hardware.virtual_device",
            "ro.kernel.android.qemud",
            "ro.hardware.audio.primary"
        )
        val triggered = virtualProps.any { props[it]?.contains("goldfish", ignoreCase = true) == true }
        return DetectionSignal("prop.virtualization", "Virtualization properties found", triggered, 3)
    }

    private fun checkEmulatorProps(props: Map<String, String>): DetectionSignal {
        val emulatorIndicators = listOf("sdk", "emulator", "simulator", "genymotion")
        val triggered = props.values.any { value ->
            emulatorIndicators.any { value.contains(it, ignoreCase = true) }
        }
        return DetectionSignal("prop.emulator_values", "Properties contain emulator keywords", triggered, 2)
    }

    private fun checkInitSvc(props: Map<String, String>): DetectionSignal {
        val suspicious = listOf("qemud", "goldfish", "vbox", "genyd").any { svc ->
            props.keys.any { it.startsWith("init.svc.$svc") && props[it] in setOf("running", "restarting") }
        }
        return DetectionSignal(
            id = "prop.init.svc.emulator",
            description = "Emulator-related init service running",
            triggered = suspicious,
            weight = 4
        )
    }

    private fun checkQemuPipes(): DetectionSignal = DetectionSignal(
        id = "files.qemu_pipes",
        description = "QEMU control pipes exist",
        triggered = QEMU_PIPES.any { File(it).exists() },
        weight = 5
    )

    private fun checkEmulatorFiles(): DetectionSignal = DetectionSignal(
        id = "files.emulator_markers",
        description = "Known emulator-specific files found",
        triggered = EMULATOR_FILES.any { File(it).exists() },
        weight = 4
    )

    private fun checkRootBinaries(): DetectionSignal = DetectionSignal(
        id = "files.root_markers",
        description = "Known root-specific files found",
        triggered = ROOT_BINARIES.any { File(it).exists() },
        weight = 4
    )

    private fun checkMagiskFiles(): DetectionSignal = DetectionSignal(
        id = "files.root_markers",
        description = "Known root-specific files found",
        triggered = MAGISK_FILES.any { File(it).exists() },
        weight = 4
    )

    private fun checkCpuInfo(): DetectionSignal {
        val content = readFileSafe("/proc/cpuinfo")
        val triggered = content.let {
            it.contains("qemu", ignoreCase = true) ||
                    it.contains("virtualbox", ignoreCase = true) ||
                    it.contains("bochs", ignoreCase = true) ||
                    (it.contains("intel", ignoreCase = true) && it.contains("genuine intel", ignoreCase = true))
        }
        return DetectionSignal("proc.cpuinfo.virtual", "CPU info suggests virtualization", triggered, 2)
    }

    private fun checkTtyDrivers(): DetectionSignal = DetectionSignal(
        id = "proc.tty.drivers.goldfish",
        description = "/proc/tty/drivers contains goldfish",
        triggered = readFileSafe("/proc/tty/drivers").contains("goldfish", ignoreCase = true),
        weight = 3
    )

    private fun checkMounts(): DetectionSignal {
        val content = readFileSafe("/proc/mounts")
        val triggered = content.contains("vboxsf", ignoreCase = true) ||
                content.contains("/dev/block/vda", ignoreCase = true)
        return DetectionSignal("proc.mounts.virtual", "Virtual filesystem mounts detected", triggered, 3)
    }

    private fun checkPartitions(): DetectionSignal {
        val content = readFileSafe("/proc/partitions")
        val triggered = content.contains("vda", ignoreCase = true) ||
                content.contains("vdb", ignoreCase = true) ||
                content.contains("vbox", ignoreCase = true)
        return DetectionSignal("proc.partitions.virtual", "Virtual disk partitions detected", triggered, 3)
    }

    private fun checkDefaultMacAddress(): DetectionSignal {
        return try {
            val triggered = NetworkInterface.getNetworkInterfaces()?.asSequence()
                ?.mapNotNull { it.hardwareAddress }
                ?.any { mac ->
                    mac.size == 6 && (
                            mac.all { b -> b == 0x00.toByte() } ||
                                    mac.contentEquals(byteArrayOf(0x02, 0x00, 0x00, 0x00, 0x00, 0x00)) ||
                                    mac.contentEquals(byteArrayOf(0x00, 0x0F, 0x54.toByte(), 0x00, 0x00, 0x00))
                            )
                } == true

            DetectionSignal("net.mac.default", "Default emulator MAC detected", triggered, 2)
        } catch (e: Exception) {
            DetectionSignal("net.mac.error", "MAC check failed", false, 0)
        }
    }

    private fun checkVirtualNetworkInterfaces(): DetectionSignal {
        val triggered = try {
            NetworkInterface.getNetworkInterfaces().asSequence()
                .any { ni ->
                    val name = ni.name.lowercase()
                    (name == "eth0" || name == "eth1") && !ni.isLoopback
                }
        } catch (e: Exception) { false }

        return DetectionSignal("net.interface.eth", "eth0/eth1 interface present", triggered, 1)
    }

    private fun checkIpAddress(): DetectionSignal {
        val triggered = try {
            NetworkInterface.getNetworkInterfaces().asSequence()
                .flatMap { it.inetAddresses.asSequence() }
                .any { addr ->
                    val ip = addr.hostAddress
                    ip?.startsWith("10.0.2.") == true || // Android Emulator default
                            ip?.startsWith("192.168.56.") == true // VirtualBox default
                }
        } catch (e: Exception) { false }

        return DetectionSignal("net.ip.emulator_range", "IP in emulator range (10.0.2.x)", triggered, 2)
    }

    private fun checkX86OnArmDevice(): DetectionSignal {
        val hasX86 = Build.SUPPORTED_ABIS?.any { it.contains("x86") } == true
        val hasArm = Build.SUPPORTED_ABIS?.any { it.contains("arm") } == true
        val triggered = hasX86 && !hasArm
        return DetectionSignal("abi.x86_only", "x86 ABI only (no ARM translation)", triggered, 3)
    }

    private fun checkAbiCount(): DetectionSignal {
        val abiCount = Build.SUPPORTED_ABIS?.size ?: 0
        val triggered = abiCount == 1 && Build.SUPPORTED_ABIS?.get(0)?.contains("x86") == true
        return DetectionSignal("abi.single_x86", "Single x86 ABI (suspicious)", triggered, 2)
    }

    private fun checkProcessorCount(): DetectionSignal {
        val processors = Runtime.getRuntime().availableProcessors()
        // Real devices typically have 4-8+ cores; 1-2 cores is suspicious
        val triggered = processors <= 2
        return DetectionSignal("hardware.low_cpu_count", "Unusually low CPU count ($processors)", triggered, 1)
    }

    private fun checkMemorySize(): DetectionSignal {
        val runtime = Runtime.getRuntime()
        val maxMemory = runtime.maxMemory() / (1024 * 1024) // MB
        // Very low or very high (exact powers of 2 like 512, 1024, 2048) can be suspicious
        val triggered = maxMemory < 512 || (maxMemory % 512 == 0L && maxMemory <= 2048)
        return DetectionSignal("hardware.suspicious_memory", "Suspicious memory config (${maxMemory}MB)", triggered, 1)
    }

    private fun checkScreenDensity(): DetectionSignal {
        val density = android.content.res.Resources.getSystem().displayMetrics.densityDpi
        // Common emulator densities: 160, 240, 320, 480
        val commonEmulatorDensities = setOf(160, 240, 320, 480, 560, 640)
        val triggered = density in commonEmulatorDensities
        return DetectionSignal("display.standard_density", "Standard emulator density ($density)", triggered, 1)
    }

    private fun checkKnownEmulatorVendors(): DetectionSignal {
        val vendors = listOf(
            "bluestacks","nox","memu","ldplayer","gameloop","tencent","mumu",
            "microvirt","windroy","koplayer","droid4x","phoenix","andy","netease"
        )
        val triggered = vendors.any {
            Build.MANUFACTURER.contains(it, true) ||
                    Build.BRAND.contains(it, true) ||
                    Build.MODEL.contains(it, true) ||
                    Build.PRODUCT.contains(it, true) ||
                    Build.DEVICE.contains(it, true)
        }
        return DetectionSignal("vendor.known_emulator", "Known third-party emulator vendor", triggered, 4)
    }

    private fun checkBootTime(): DetectionSignal {
        val uptimeMillis = SystemClock.elapsedRealtime()
        val uptimeMinutes = uptimeMillis / 60000
        // Very short uptime (<1 min) can indicate fresh emulator start
        val triggered = uptimeMinutes < 1
        return DetectionSignal("system.fresh_boot", "Device just booted (<1 min uptime)", triggered, 1)
    }


    /**
     *
     * Context-based Checks ===============================
      */
    private fun checkSensors(context: Context): List<DetectionSignal> {
        val sm = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager ?: return emptyList()
        val signals = mutableListOf<DetectionSignal>()

        val missingAccel = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) == null
        val missingGyro = sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE) == null
        val missingMag = sm.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD) == null
        val missingLight = sm.getDefaultSensor(Sensor.TYPE_LIGHT) == null
        val missingPressure = sm.getDefaultSensor(Sensor.TYPE_PRESSURE) == null
        val missingProximity = sm.getDefaultSensor(Sensor.TYPE_PROXIMITY) == null

        signals += DetectionSignal("sensor.accel.missing", "No accelerometer", missingAccel, 2)
        signals += DetectionSignal("sensor.gyro.missing", "No gyroscope", missingGyro, 2)
        signals += DetectionSignal("sensor.mag.missing", "No magnetic field sensor", missingMag, 3)
        signals += DetectionSignal("sensor.light.missing", "No light sensor", missingLight, 2)
        signals += DetectionSignal("sensor.pressure.missing", "No pressure sensor", missingPressure, 2)
        signals += DetectionSignal("sensor.proximity.missing", "No proximity sensor", missingProximity, 2)

        // Check total sensor count
        val totalSensors = sm.getSensorList(Sensor.TYPE_ALL).size
        signals += DetectionSignal("sensor.low_count", "Unusually low sensor count ($totalSensors)", totalSensors < 10, 2)

        return signals
    }


    private fun checkTelephony(context: Context): List<DetectionSignal> {
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        val signals = mutableListOf<DetectionSignal>()

        val noPhoneType = tm?.phoneType == TelephonyManager.PHONE_TYPE_NONE
        val hasPerm = ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED

        if (hasPerm && Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            @Suppress("DEPRECATION")
            val deviceId = tm?.deviceId
            val fakeImei = deviceId in setOf("000000000000000", null, "") || deviceId?.all { it == '0' } == true
            signals += DetectionSignal("telephony.imei.fake", "Fake or zero IMEI", fakeImei, 3)
        }

        val networkOperator = tm?.networkOperatorName
        val noOperator = networkOperator.isNullOrBlank() || networkOperator == "Android"

        signals += DetectionSignal("telephony.none", "No cellular radio", noPhoneType, 2)
        signals += DetectionSignal("telephony.no_operator", "No network operator", noOperator, 2)

        return signals
    }

    private fun checkBatteryStatus(context: Context): List<DetectionSignal> {
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager ?: return emptyList()
        val isCharging = bm.isCharging
        val batteryLevel = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)

        val suspiciousLevel = batteryLevel == 50 || batteryLevel == 100
        val neverCharging = !isCharging && batteryLevel == 100

        return listOf(
            DetectionSignal("battery.always_50_or_100", "Battery stuck at 0% or 100%", suspiciousLevel, 2),
            DetectionSignal("battery.never_charging", "100% battery but not charging", neverCharging, 2)
        )
    }

    private fun checkPowerThermalState(context: Context): List<DetectionSignal> {
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return emptyList()
        val thermal = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            pm.currentThermalStatus
        } else {
            PowerManager.THERMAL_STATUS_NONE
        }

        val suspicious = thermal <= PowerManager.THERMAL_STATUS_LIGHT

        return listOf(DetectionSignal("thermal.low_or_none", "Unrealistic thermal state", suspicious, 2))
    }

    private fun checkLightAndMagneticSensors(context: Context): List<DetectionSignal> {
        val sm = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager ?: return emptyList()

        val hasLight = sm.getDefaultSensor(Sensor.TYPE_LIGHT) != null
        val hasMag = sm.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD) != null

        return listOf(
            DetectionSignal("sensor.light.missing", "Light sensor missing", !hasLight, 3),
            DetectionSignal("sensor.magnetic.missing", "Magnetic sensor missing", !hasMag, 3)
        )
    }

    private fun checkGpsStatus(context: Context): DetectionSignal {
        val hasGps = context.packageManager.hasSystemFeature(PackageManager.FEATURE_LOCATION_GPS)
        return DetectionSignal("gps.missing", "No GPS hardware", !hasGps, 1)
    }

    private fun checkWifiMacAddress(context: Context): DetectionSignal {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        val wifiInfo = wifiManager?.connectionInfo
        val bssid = wifiInfo?.bssid

        val isDefault = bssid in setOf(
            "02:00:00:00:00:00",
            "00:00:00:00:00:00",
            null
        )

        return DetectionSignal("wifi.bssid.default", "Default emulator WiFi BSSID", isDefault, 2)
    }

    private fun checkBluetoothAdapter(context: Context): DetectionSignal {
        val hasBluetooth = context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH)
        return DetectionSignal("bluetooth.missing", "No Bluetooth hardware", !hasBluetooth, 2)
    }

    private fun checkCameraFeatures(context: Context): DetectionSignal {
        val hasCamera = context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)
        val hasFrontCamera = context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_FRONT)
        val triggered = !hasCamera && !hasFrontCamera
        return DetectionSignal("camera.missing", "No camera hardware", triggered, 2)
    }

    private fun checkNfcFeature(context: Context): DetectionSignal {
        val hasNfc = context.packageManager.hasSystemFeature(PackageManager.FEATURE_NFC)
        return DetectionSignal("nfc.missing", "No NFC hardware (common in emulators)", !hasNfc, 1)
    }

    private fun checkAndroidId(context: Context): DetectionSignal {
        val androidId = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        val isSuspicious = androidId.isNullOrBlank() ||
                androidId == "9774d56d682e549c" || // Known emulator ID
                androidId.all { it == '0' }
        return DetectionSignal("settings.android_id.suspicious", "Suspicious Android ID", isSuspicious, 2)
    }

    private fun checkDrmInfo(context: Context): DetectionSignal {
        val triggered = try {
            val hasDrm = context.packageManager.hasSystemFeature("android.software.drm")
            !hasDrm
        } catch (e: Exception) {
            false
        }
        return DetectionSignal("drm.missing", "No DRM support (common in emulators)", triggered, 1)
    }

    private fun checkMultiTouch(context: Context): DetectionSignal {
        val hasMultiTouch = context.packageManager.hasSystemFeature(PackageManager.FEATURE_TOUCHSCREEN_MULTITOUCH)
        return DetectionSignal("touchscreen.multitouch.missing", "No multitouch support", !hasMultiTouch, 1)
    }

    private fun checkUSBAccessories(context: Context): DetectionSignal {
        val hasUSB = context.packageManager.hasSystemFeature(PackageManager.FEATURE_USB_ACCESSORY)
        return DetectionSignal("usb.accessory.missing", "No USB accessory support", !hasUSB, 1)
    }


    /**
     *    Helper Functions
      */



    private fun readFileSafe(path: String): String = try {
        File(path).takeIf { it.exists() && it.canRead() }?.readText() ?: ""
    } catch (t: Throwable) { "" }

    private fun readGetProp(): Map<String, String> = try {
        val process = Runtime.getRuntime().exec("getprop")
        val output = process.inputStream.bufferedReader().readText()
        val map = mutableMapOf<String, String>()
        Pattern.compile("\\[(.+?)\\]: \\[(.+?)\\]").matcher(output).apply {
            while (find()) map[group(1)] = group(2)
        }
        map
    } catch (t: Throwable) { emptyMap() }
}
