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
import android.provider.Settings
import android.telephony.TelephonyManager
import androidx.core.content.ContextCompat
import com.mahbub.detectvirtualdevicekmp.detect.RootJailbreakDetector.collectSignals
import java.io.File
import java.net.NetworkInterface
import java.util.regex.Pattern

actual object VirtualDetector {

    private val EMULATOR_HARDWARE =
        setOf("goldfish", "ranchu", "vbox86", "qemu", "simics", "ttVM_Haxm", "bluestacks", "bstk")
    private val EMULATOR_PRODUCTS = setOf(
        "sdk",
        "google_sdk",
        "sdk_gphone",
        "sdk_google",
        "emulator",
        "simulator",
        "android_x86",
        "vbox86p",
        "full_x86",
        "nox",
        "bluestacks",
        "ldplayer",
        "memu",
        "sdk_gphone64_arm64",
        "sdk_gphone_x86",
        "aosp_x86",
        "sdk_gphone64_arm64",
        "sdk_gphone_x86",
        "aosp_x86",
        "bluestack",
        "bstk",
        "bstacks"
    )
    private val EMULATOR_MANUFACTURERS = setOf(
        "genymotion", "genuineintel", "nox", "bluestacks", "memu", "ldplayer",
        "andy", "phoenixos", "netease"
    )
    private val EMULATOR_BRANDS = setOf("generic", "android-x86", "nox", "bluestacks")

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
        "/ueventd.vbox86.rc",
        // Enhanced Bluestacks-specific files
        "/data/data/com.bluestacks.appmart",
        "/data/data/com.bluestacks.BstCommandProcessor",
        "/data/data/com.bluestacks.help",
        "/data/data/com.bluestacks.home",
        "/data/data/com.bluestacks.s2p",
        "/data/data/com.bluestacks.search",
        "/data/data/com.bluestacks.settings",
        "/data/data/com.bluestacks.setup",
        "/data/data/com.bluestacks.appfinder",
        "/system/app/BluestacksAppPlayer",
        "/system/priv-app/BluestacksAppPlayer",
        "/system/etc/permissions/com.bluestacks.xposed.bridge.xml",
        "/data/data/com.bluestacks.keymapping",
        "/data/data/com.bluestacks.gamecontrols",
        "/data/data/com.bluestacks.multiinstance",
        "/data/data/com.bluestacks.bstfolder",
        "/system/bin/bstk",
        "/system/bin/bststatus",
        "/system/bin/bstservice"

    )

    private val ROOT_BINARIES = arrayOf(
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/system/bin/busybox",
        "/system/xbin/busybox",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/system/app/Magisk.apk",
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/cache/.magisk",
        "/system/bin/daemonsu",
        "/system/xbin/daemonsu"
    )

    private val MAGISK_FILES = arrayOf(
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/data/adb/magisk.img",
        "/data/adb/magisk.db",
        "/data/adb/magisk_simple"
    )

    // Known legitimate manufacturers to whitelist
    private val LEGITIMATE_MANUFACTURERS = setOf(
        "samsung", "xiaomi", "huawei", "oppo", "vivo", "realme", "oneplus",
        "motorola", "nokia", "sony", "lg", "asus", "lenovo", "zte", "tcl",
        "fairphone", "honor", "infinix", "tecno", "redmi"
    )

    actual fun collectSignals(context: Any?): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()

        // Early whitelist check - if it's a known legitimate manufacturer, reduce false positives
        val isLegitimateDevice = LEGITIMATE_MANUFACTURERS.any {
            Build.MANUFACTURER.contains(it, ignoreCase = true)
        }

        // === Build Properties ===
        signals += checkBuildFingerprint()
        signals += checkBuildModel()
        signals += checkBuildHardware()
        signals += checkBuildProduct()
        signals += checkBuildManufacturerAndBrand()
        signals += checkBuildTags()
        signals += checkBuildBoard(isLegitimateDevice)
        signals += checkBuildDevice()
        // Removed checkBuildHost() - too many false positives
        signals += checkBuildRadioVersion(isLegitimateDevice)

        //Root or file Masking===
        signals += checkRootBinaries()
        signals += checkMagiskFiles()

        //== Blustaks ===
        // Kernel & Network checks (permission-friendly)
        signals += checkCpuInfoHypervisorFlag()
        signals += checkProcModulesForVirtualDrivers()
//        signals += checkNetworkMacOuisAndNames()
//        signals += checkIpRangesForEmulator()
//        signals += checkVirtualNetworkStackComposite()
        signals += checkBluestacksKernel()
//        signals += checkBluestacksNetwork()
//        signals += checkBluestacksBuildProps()
//        signals += checkBluestacksDrivers()
//        signals += checkBluestacksQemuProp()
//        signals += checkBluestacksByFullGetprop()
//        signals += checkThermalImpossible()
        signals += checkBluestacksGralloc()
        signals += checkBluestacksBuild()


        // === System Properties ===
        val props = readGetProp()
        signals += checkRoKernelQemu(props)
        signals += checkRoBootmode(props)
        signals += checkRoSecure(props)
        signals += checkRoDebuggable(props, isLegitimateDevice)
        signals += checkInitSvc(props)
        signals += checkVirtualizationProps(props)
        signals += checkEmulatorProps(props)
        signals += checkBluestacksProps(props)


        // === File System Checks ===
        signals += checkQemuPipes()
        signals += checkEmulatorFiles()
        signals += checkCpuInfo()
        signals += checkTtyDrivers()
        signals += checkMounts()
        signals += checkPartitions()


        // === Network ===
        signals += checkDefaultMacAddress()
        signals += checkVirtualNetworkInterfaces()
        signals += checkIpAddress()


        // === ABI & Architecture ===
        signals += checkX86OnArmDevice()
        signals += checkAbiCount()


        // === Hardware Characteristics ===
        // Removed unreliable hardware checks that cause false positives:
        // - checkProcessorCount() - budget phones can have 2 cores
        // - checkMemorySize() - legitimate devices use these configs
        // - checkScreenDensity() - standard densities are common on real devices
        // - checkBootTime() - devices get rebooted normally

        // === Vendor-specific Hints ===
        signals += checkKnownEmulatorVendors()

        signals.filter { it.triggered }.forEach {
            println("VirtualDetector ${it.description} ${it.id} weight=${it.weight} triggered=${it.triggered}")
        }
        return signals.filter { it.triggered }
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
                    it.contains("bluestacks", ignoreCase = true) ||
                    it.contains("bstk", ignoreCase = true) ||
                    it.contains("bstacks", ignoreCase = true)
            // Removed "unknown" check - too broad, causes false positives
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
        description = "Hardware is goldfish/ranchu/vbox/qemu/bluestacks",
        triggered = EMULATOR_HARDWARE.any { Build.HARDWARE.contains(it, ignoreCase = true) },
        weight = 4
    )

    private fun checkBuildProduct(): DetectionSignal = DetectionSignal(
        id = "build.product.emulator",
        description = "Product name indicates emulator",
        triggered = EMULATOR_PRODUCTS.any { Build.PRODUCT.contains(it, ignoreCase = true) },
        weight = 4
    )

    private fun checkBuildManufacturerAndBrand(): DetectionSignal {
        // Removed "unknown" from EMULATOR_MANUFACTURERS set
        val isSuspicious =
            EMULATOR_MANUFACTURERS.any { Build.MANUFACTURER.contains(it, ignoreCase = true) } ||
                    EMULATOR_BRANDS.any { Build.BRAND.contains(it, ignoreCase = true) } ||
                    (Build.BRAND.equals(
                        "generic",
                        ignoreCase = true
                    ) && Build.DEVICE.startsWith("generic"))

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

    private fun checkBuildBoard(isLegitimateDevice: Boolean): DetectionSignal {
        // Don't flag qc_reference_phone if it's a legitimate manufacturer (Xiaomi, etc.)
        val triggered = if (isLegitimateDevice) {
            Build.BOARD.let {
                it.isBlank() || it.lowercase() in setOf("unknown", "goldfish")
            }
        } else {
            Build.BOARD.let {
                it.isBlank() || it.lowercase() in setOf(
                    "unknown",
                    "android",
                    "qc_reference_phone",
                    "goldfish"
                )
            }
        }

        return DetectionSignal(
            id = "build.board.virtual",
            description = "Board name is unknown or virtual",
            triggered = triggered,
            weight = 1
        )
    }

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

    // --- Kernel / CPU Flags: hypervisor presence in /proc/cpuinfo ---
    private fun checkCpuInfoHypervisorFlag(): DetectionSignal {
        val content = readFileSafe("/proc/cpuinfo")
        // Look for either "hypervisor" in flags or explicit "Hypervisor vendor" / "hypervisor" mentions
        val triggered = content.let {
            it.contains("hypervisor", ignoreCase = true) ||
                    it.contains("Hypervisor", ignoreCase = true) ||
                    // Some builds include "flags\t: ... hypervisor ..." line
                    Regex("""flags\s*:.*\bhypervisor\b""", RegexOption.IGNORE_CASE).containsMatchIn(
                        it
                    )
        }

        return DetectionSignal(
            id = "proc.cpuinfo.hypervisor_flag",
            description = "CPU flags or cpuinfo indicate hypervisor",
            triggered = triggered,
            weight = 5
        )
    }

    // --- Kernel Modules: vbox / hyperv / vmbus / vboxsf etc. in /proc/modules ---
    private fun checkProcModulesForVirtualDrivers(): DetectionSignal {
        val content = readFileSafe("/proc/modules")
        val suspects = listOf(
            "vboxguest", "vboxsf", "vboxvideo", "vboxdrv", "vboxnetadp", "vboxnetflt",
            "hv_vmbus", "vmbus", "hyperv", "xen", "kvm", "vbox"
        )
        val triggered = suspects.any { content.contains(it, ignoreCase = true) }

        return DetectionSignal(
            id = "proc.modules.virtual_drivers",
            description = "VirtualBox / Hyper-V / KVM kernel modules present",
            triggered = triggered,
            weight = 5
        )
    }

    // --- Network: MAC OUI & interface name heuristics (no storage permission) ---
    private fun checkNetworkMacOuisAndNames(): DetectionSignal {
        return try {
            val virtualMacPrefixes = listOf(
                // VirtualBox
                byteArrayOf(0x08, 0x00, 0x27),
                // KVM/QEMU
                byteArrayOf(0x52, 0x54, 0x00),
                // Microsoft Hyper-V
                byteArrayOf(0x00, 0x15, 0x5D),
                // Common emulator placeholder / BlueStacks sometimes uses 02:00:00:..
                byteArrayOf(0x02, 0x00, 0x00),
                // Old VirtualBox alternate
                byteArrayOf(0x00, 0x1C, 0x42)
            )

            val ifaceNameIndicators = listOf(
                "vbox",
                "virtual",
                "virbr",
                "veth",
                "android_vm",
                "eth0",
                "eth1",
                "enp0s",
                "tbv"
            ) // eth0/eth1 are suspicious if not loopback

            val found = NetworkInterface.getNetworkInterfaces().asSequence().any { ni ->
                try {
                    val name = ni.name.lowercase()
                    val mac = ni.hardwareAddress
                    val macPrefixMatch =
                        mac != null && mac.size >= 3 && virtualMacPrefixes.any { prefix ->
                            mac[0] == prefix[0] && mac[1] == prefix[1] && mac[2] == prefix[2]
                        }

                    val nameSuspect =
                        ifaceNameIndicators.any { name.contains(it) } && !ni.isLoopback

                    // treat eth0/eth1 as suspicious only if not a loopback and not a mobile interface
                    val ethSuspicious = (name == "eth0" || name == "eth1") && !ni.isLoopback

                    macPrefixMatch || nameSuspect || ethSuspicious
                } catch (_: Exception) {
                    false
                }
            }

            DetectionSignal(
                "net.ifaces.mac_oui",
                "Network interfaces look virtual (MAC OUI / names)",
                found,
                4
            )
        } catch (e: Exception) {
            DetectionSignal("net.ifaces.error", "Network interface check failed", false, 0)
        }
    }

    // --- Network: IP address ranges commonly used by emulators/VirtualBox/BlueStacks ---
    private fun checkIpRangesForEmulator(): DetectionSignal {
        val triggered = try {
            NetworkInterface.getNetworkInterfaces().asSequence()
                .flatMap { it.inetAddresses.asSequence() }
                .any { addr ->
                    val ip = addr.hostAddress ?: return@any false
                    // Existing emulator ranges: 10.0.2.x (Android emulator), 192.168.56.x (VirtualBox), add 192.168.59.x (BlueStacks observed)
                    ip.startsWith("10.0.2.") ||
                            ip.startsWith("192.168.56.") ||
                            ip.startsWith("192.168.59.") ||
                            // KVM libvirt default NAT
                            ip.startsWith("192.168.122.") ||
                            // Docker/bridge ranges (suspicious when present with other signals)
                            ip.startsWith("172.17.") ||
                            ip.startsWith("172.18.")
                }
        } catch (e: Exception) {
            false
        }

        return DetectionSignal(
            "net.ip.emulator_ranges_ext",
            "IP address matches common emulator/virtual ranges",
            triggered,
            3
        )
    }

    // --- Combine a stronger "virtual network stack" signal: modules + mac + ip (composite) ---
    private fun checkVirtualNetworkStackComposite(): DetectionSignal {
        val modules = checkProcModulesForVirtualDrivers().triggered
        val macs = checkNetworkMacOuisAndNames().triggered
        val ips = checkIpRangesForEmulator().triggered

        val triggered = (modules && (macs || ips)) || (macs && ips) || modules && macs

        return DetectionSignal(
            id = "net.virtual_stack_composite",
            description = "Composite network/kernel signals indicate a virtualized environment",
            triggered = triggered,
            weight = 6
        )
    }

    private fun checkBluestacksKernel(): DetectionSignal {
        val kernel = System.getProperty("os.version")?.lowercase() ?: ""
        val triggered =
            kernel.contains("bluestacks") ||
                    kernel.contains("bst") ||
                    kernel.contains("android_x86") ||
                    kernel.contains("x86_64") // Real phones NEVER report x86_64 kernel

        return DetectionSignal(
            id = "bluestacks.kernel",
            description = "Kernel properties indicate BlueStacks / x86 emulator environment",
            triggered = triggered,
            weight = 10
        )
    }

    private fun checkBluestacksNetwork(): DetectionSignal {
        val interfaces = try {
            java.net.NetworkInterface.getNetworkInterfaces().toList().map { it.name.lowercase() }
        } catch (e: Exception) {
            emptyList()
        }

        val triggered =
            "vboxnet" in interfaces ||
                    "virbr0" in interfaces ||
                    "eth0" in interfaces && "wlan0" !in interfaces

        return DetectionSignal(
            id = "bluestacks.network",
            description = "BlueStacks-like virtual network interfaces detected",
            triggered = triggered,
            weight = 10
        )
    }

    private fun checkBluestacksBuildProps(): DetectionSignal {
        val hw = Build.HARDWARE.lowercase()
        val product = Build.PRODUCT.lowercase()
        val device = Build.DEVICE.lowercase()
        val model = Build.MODEL.lowercase()

        val triggered =
            hw.contains("android_x86") ||
                    hw.contains("x86") ||
                    product.contains("android_x86") ||
                    device.contains("android_x86") ||
                    model.contains("bluestacks") ||     // Some versions expose this
                    model.contains("nox") ||            // Other emulators
                    model.contains("sdk")               // Generic emulator build

        return DetectionSignal(
            id = "bluestacks.buildprops",
            description = "Build properties match BlueStacks patterns",
            triggered = triggered,
            weight = 8
        )
    }

    private fun checkBluestacksDrivers(): DetectionSignal {
        val drivers = listOf(
            "vboxpipe",
            "vboxguest",
            "qemu_pipe",
            "qemud",
            "vmsvga",
            "hyperv_fb"
        )

        val kernelInfo = System.getProperty("os.version")?.lowercase() ?: ""

        val triggered = drivers.any { kernelInfo.contains(it) }

        return DetectionSignal(
            id = "bluestacks.drivers",
            description = "Virtualization drivers detected (QEMU/VirtualBox/Hyper-V)",
            triggered = triggered,
            weight = 7
        )
    }

    private fun checkBluestacksQemuProp(): DetectionSignal {
        val qemu = getSystemProperty("ro.kernel.qemu") == "1"

        return DetectionSignal(
            id = "bluestacks.qemu",
            description = "QEMU system property indicates emulator environment",
            triggered = qemu,
            weight = 10
        )
    }

    // helper
    private fun getSystemProperty(key: String): String {
        return try {
            val cls = Class.forName("android.os.SystemProperties")
            val method = cls.getMethod("get", String::class.java)
            method.invoke(null, key) as String
        } catch (e: Exception) {
            ""
        }
    }

    private fun checkBluestacksByFullGetprop(): DetectionSignal {
        val props = readAllSystemProps()

        val bsKeys = listOf(
            "bluestacks",
            "ro.bluestacks",
            "sys.bluestacks",
            "init.bluestacks",
            "persist.bluestacks"
        )

        val hvKeys = listOf(
            "hyperv",
            "ro.hardware.vmm",
            "ro.hardware.hyperv",
            "hw.vmm"
        )

        val lowerProps = props.lowercase()

        val triggered =
            bsKeys.any { lowerProps.contains(it) } ||
                    hvKeys.any { lowerProps.contains(it) }

        return DetectionSignal(
            id = "bluestacks.fullprop",
            description = "Detected BlueStacks/Hyper-V through system properties",
            triggered = triggered,
            weight = 20
        )
    }

    // Helper: reads ALL system properties (no permission required)
    private fun readAllSystemProps(): String {
        return try {
            val process = Runtime.getRuntime().exec("getprop")
            process.inputStream.bufferedReader().use { it.readText() }
        } catch (e: Exception) {
            ""
        }
    }

    private fun checkThermalImpossible(): DetectionSignal {
        val dir = File("/sys/class/thermal/")
        val triggered = try {
            if (!dir.exists()) true
            else {
                val zones =
                    dir.listFiles()?.filter { it.name.contains("thermal_zone", ignoreCase = true) }
                zones == null || zones.isEmpty()
            }
        } catch (e: Exception) {
            true // If access fails → emulator
        }

        return DetectionSignal(
            id = "hardware.thermal_missing",
            description = "Thermal zones missing (impossible for real device)",
            triggered = triggered,
            weight = 2
        )
    }


    private fun checkBluestacksCpuInfo(): DetectionSignal {
        val content = readFileSafe("/proc/cpuinfo")
        val triggered = content.contains("bluestacks", ignoreCase = true)

        return DetectionSignal(
            id = "bluestacks.cpuinfo",
            description = "BlueStacks pattern found in /proc/cpuinfo",
            triggered = triggered,
            weight = 5
        )
    }

    private fun checkBluestacksGralloc(): DetectionSignal {
        val paths = listOf(
            "/system/lib/hw/gralloc.vbox86.so",
            "/system/lib64/hw/gralloc.vbox86.so"
        )

        val triggered = paths.any { File(it).exists() }

        return DetectionSignal(
            id = "bluestacks.gralloc",
            description = "BlueStacks VirtualBox gralloc detected",
            triggered = triggered,
            weight = 5
        )
    }

    private fun checkBluestacksBuild(): DetectionSignal {
        val hw = Build.HARDWARE.lowercase()
        val product = Build.PRODUCT.lowercase()
        val device = Build.DEVICE.lowercase()

        val triggered =
            hw.contains("android_x86") ||
                    hw.contains("x86") ||
                    product.contains("android_x86") ||
                    product.contains("x86") ||
                    device.contains("android_x86") ||
                    device.contains("x86")

        return DetectionSignal(
            id = "bluestacks.build",
            description = "BlueStacks-like Android_x86 / x86 build detected",
            triggered = triggered,
            weight = 3
        )
    }


    private fun checkBuildRadioVersion(isLegitimateDevice: Boolean): DetectionSignal {
        val noRadio = Build.getRadioVersion().isNullOrBlank()

        return DetectionSignal(
            id = "build.radio.missing",
            description = "No radio/baseband version",
            // Only flag if no radio AND not a legitimate device (some tablets/WiFi-only devices have no radio)
            triggered = noRadio && !isLegitimateDevice,
            weight = 2
        )
    }

    private fun checkRoKernelQemu(props: Map<String, String>): DetectionSignal {
        // Only trigger if ro.kernel.qemu=1 (not just existence)
        // Many Xiaomi devices have ro.kernel.qemu.gles=0 as bringup property (not emulator)
        val isQemu = props["ro.kernel.qemu"] == "1"

        return DetectionSignal(
            id = "prop.ro.kernel.qemu",
            description = "ro.kernel.qemu=1",
            triggered = isQemu,
            weight = 4 // Higher weight since this is more reliable now
        )
    }

    private fun checkRoBootmode(props: Map<String, String>): DetectionSignal = DetectionSignal(
        id = "prop.ro.bootmode",
        description = "ro.bootmode=unknown (common in emulators)",
        triggered = props["ro.bootmode"] == "unknown",
        weight = 1
    )

    private fun checkRoSecure(props: Map<String, String>): DetectionSignal = DetectionSignal(
        id = "prop.ro.secure",
        description = "ro.secure=0 (insecure mode)",
        triggered = props["ro.secure"] == "0",
        weight = 2
    )

    private fun checkRoDebuggable(
        props: Map<String, String>,
        isLegitimateDevice: Boolean
    ): DetectionSignal {
        val isDebuggable = props["ro.debuggable"] == "1"

        return DetectionSignal(
            id = "prop.ro.debuggable",
            description = "ro.debuggable=1",
            triggered = isDebuggable,
            // Lower weight for legitimate devices (developer devices can have this enabled)
            weight = if (isLegitimateDevice) 1 else 3
        )
    }

    private fun checkVirtualizationProps(props: Map<String, String>): DetectionSignal {
        val virtualProps = listOf(
            "ro.hardware.virtual_device",
            "ro.kernel.android.qemud",
            "ro.hardware.audio.primary"
        )
        val triggered =
            virtualProps.any { props[it]?.contains("goldfish", ignoreCase = true) == true }
        return DetectionSignal(
            "prop.virtualization",
            "Virtualization properties found",
            triggered,
            3
        )
    }

    private fun checkEmulatorProps(props: Map<String, String>): DetectionSignal {
        val emulatorIndicators =
            listOf("sdk", "emulator", "simulator", "genymotion", "bluestacks", "bstk")
        val triggered = props.values.any { value ->
            emulatorIndicators.any { value.contains(it, ignoreCase = true) }
        }
        return DetectionSignal(
            "prop.emulator_values",
            "Properties contain emulator keywords",
            triggered,
            2
        )
    }

    private fun checkBluestacksProps(props: Map<String, String>): DetectionSignal {
        val bluestacksProps = listOf(
            "ro.product.bluestacks.version",
            "ro.product.bluestacks.version.major",
            "ro.product.bluestacks.version.minor",
            "ro.product.bluestacks.version.patch",
            "ro.product.bluestacks.version.full",
            "ro.product.bluestacks.device",
            "ro.product.bluestacks.model",
            "ro.product.bluestacks.brand",
            "ro.product.bluestacks.manufacturer",
            "ro.product.bluestacks.name",
            "ro.bluestacks.version",
            "ro.bluestacks.device",
            "ro.bluestacks.model",
            "ro.bluestacks.btk.version",
            "ro.bluestacks.vm.name",
            "ro.bluestacks.vm.version",
            "ro.bluestacks.vm.id",
            "ro.bluestacks.vm.guid",
            "ro.bluestacks.vm.uuid",
            "ro.bluestacks.vm.device",
            "ro.bluestacks.vm.model",
            "ro.bluestacks.vm.brand",
            "ro.bluestacks.vm.manufacturer",
            "ro.bluestacks.vm.product",
            "ro.bluestacks.vm.hardware",
            "ro.bluestacks.vm.board",
            "ro.bluestacks.vm.display",
            "ro.bluestacks.vm.fingerprint",
            "ro.bluestacks.vm.version.release",
            "ro.bluestacks.vm.version.sdk",
            "ro.bluestacks.vm.version.codename",
            "ro.bluestacks.vm.version.incremental",
            "ro.bluestacks.vm.version.security_patch",
            "ro.bluestacks.vm.build.version.release",
            "ro.bluestacks.vm.build.version.sdk",
            "ro.bluestacks.vm.build.version.codename",
            "ro.bluestacks.vm.build.version.incremental",
            "ro.bluestacks.vm.build.version.security_patch",
            "ro.bluestacks.vm.build.fingerprint",
            "ro.bluestacks.vm.build.id",
            "ro.bluestacks.vm.build.tags",
            "ro.bluestacks.vm.build.type",
            "ro.bluestacks.vm.build.user",
            "ro.bluestacks.vm.build.host",
            "ro.bluestacks.vm.build.date",
            "ro.bluestacks.vm.build.time",
            "ro.bluestacks.vm.build.display.id",
            "ro.bluestacks.vm.build.version.all_codenames",
            "ro.bluestacks.vm.build.version.active_codenames",
            "ro.bluestacks.vm.build.version.preview_sdk",
            "ro.bluestacks.vm.build.version.preview_sdk_fingerprint",
            "ro.bluestacks.vm.build.version.base_os",
            "ro.bluestacks.vm.build.version.security_index",
            "ro.bluestacks.vm.build.version.media_performance_class",
            "ro.bluestacks.vm.build.version.min_supported_target_sdk",
            "ro.bluestacks.vm.build.version.min_supported_target_sdk_fingerprint"
        )

        val triggered = bluestacksProps.any { prop ->
            props.containsKey(prop) && !props[prop].isNullOrBlank()
        }

        return DetectionSignal(
            "prop.bluestacks",
            "Bluestacks-specific properties found",
            triggered,
            5
        )
    }

    private fun checkInitSvc(props: Map<String, String>): DetectionSignal {
        val suspicious = listOf("qemud", "goldfish", "vbox", "genyd").any { svc ->
            props.keys.any {
                it.startsWith("init.svc.$svc") && props[it] in setOf(
                    "running",
                    "restarting"
                )
            }
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
        id = "files.root_binaries",
        description = "Known root binaries found",
        triggered = ROOT_BINARIES.any { File(it).exists() },
        weight = 4
    )

    private fun checkMagiskFiles(): DetectionSignal = DetectionSignal(
        id = "files.magisk_markers",
        description = "Magisk files found",
        triggered = MAGISK_FILES.any { File(it).exists() },
        weight = 4
    )

    private fun checkCpuInfo(): DetectionSignal {
        val content = readFileSafe("/proc/cpuinfo")
        val triggered = content.let {
            it.contains("qemu", ignoreCase = true) ||
                    it.contains("virtualbox", ignoreCase = true) ||
                    it.contains("bochs", ignoreCase = true) ||
                    it.contains("bluestacks", ignoreCase = true) ||
                    it.contains("bstk", ignoreCase = true) ||
                    it.contains("hyper-v", ignoreCase = true) ||
                    it.contains("vmware", ignoreCase = true)
            // Removed Intel GenuineIntel check - legitimate x86 devices exist
        }
        return DetectionSignal(
            "proc.cpuinfo.virtual",
            "CPU info suggests virtualization",
            triggered,
            2
        )
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
        return DetectionSignal(
            "proc.mounts.virtual",
            "Virtual filesystem mounts detected",
            triggered,
            3
        )
    }

    private fun checkPartitions(): DetectionSignal {
        val content = readFileSafe("/proc/partitions")
        val triggered = content.contains("vda", ignoreCase = true) ||
                content.contains("vdb", ignoreCase = true) ||
                content.contains("vbox", ignoreCase = true)
        return DetectionSignal(
            "proc.partitions.virtual",
            "Virtual disk partitions detected",
            triggered,
            3
        )
    }

    private fun checkDefaultMacAddress(): DetectionSignal {
        return try {
            val triggered = NetworkInterface.getNetworkInterfaces()?.asSequence()
                ?.mapNotNull { it.hardwareAddress }
                ?.any { mac ->
                    mac.size == 6 && (
                            mac.all { b -> b == 0x00.toByte() } ||
                                    mac.contentEquals(
                                        byteArrayOf(
                                            0x02,
                                            0x00,
                                            0x00,
                                            0x00,
                                            0x00,
                                            0x00
                                        )
                                    ) ||
                                    mac.contentEquals(
                                        byteArrayOf(
                                            0x00,
                                            0x0F,
                                            0x54.toByte(),
                                            0x00,
                                            0x00,
                                            0x00
                                        )
                                    )
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
        } catch (e: Exception) {
            false
        }

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
        } catch (e: Exception) {
            false
        }

        return DetectionSignal(
            "net.ip.emulator_range",
            "IP in emulator range (10.0.2.x)",
            triggered,
            2
        )
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

    // REMOVED: checkProcessorCount() - Budget phones legitimately have 2 cores
    // REMOVED: checkMemorySize() - Legitimate devices use these memory configurations
    // REMOVED: checkScreenDensity() - Real devices commonly use standard densities (160, 240, 320, 480, etc.)
    // REMOVED: checkBootTime() - Devices get rebooted normally for updates, etc.

    private fun checkKnownEmulatorVendors(): DetectionSignal {
        val vendors = listOf(
            "bluestacks",
            "bstacks",
            "bstk",
            "nox",
            "memu",
            "ldplayer",
            "gameloop",
            "tencent",
            "mumu",
            "microvirt",
            "windroy",
            "koplayer",
            "droid4x",
            "phoenix",
            "andy",
            "netease"
        )

        val fields = listOf(
            Build.MANUFACTURER,
            Build.BRAND,
            Build.MODEL,
            Build.PRODUCT,
            Build.DEVICE
        ).map { it.lowercase() }

        val triggered = vendors.any { vendor ->
            fields.any { field ->
                field.contains(vendor)
            }
        }

        return DetectionSignal(
            "vendor.known_emulator",
            "Known third-party emulator vendor",
            triggered,
            3
        )
    }


    /**
     *
     * Context-based Checks ===============================
     */
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

//        signals.filter { it.triggered }.forEach {
//            println("VirtualDetectorContext ${it.id} weight=${it.weight} triggered=${it.triggered}")
//        }
        return signals
    }

    private fun checkSensors(context: Context): List<DetectionSignal> {
        val sm =
            context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager ?: return emptyList()
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
        signals += DetectionSignal(
            "sensor.pressure.missing",
            "No pressure sensor",
            missingPressure,
            2
        )
        signals += DetectionSignal(
            "sensor.proximity.missing",
            "No proximity sensor",
            missingProximity,
            2
        )

        // Check total sensor count
        val totalSensors = sm.getSensorList(Sensor.TYPE_ALL).size
        signals += DetectionSignal(
            "sensor.low_count",
            "Unusually low sensor count ($totalSensors)",
            totalSensors < 10,
            2
        )

        return signals
    }


    private fun checkTelephony(context: Context): List<DetectionSignal> {
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        val signals = mutableListOf<DetectionSignal>()

        val noPhoneType = tm?.phoneType == TelephonyManager.PHONE_TYPE_NONE
        val hasPerm = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.READ_PHONE_STATE
        ) == PackageManager.PERMISSION_GRANTED

        if (hasPerm && Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            @Suppress("DEPRECATION")
            val deviceId = tm?.deviceId
            val fakeImei = deviceId in setOf(
                "000000000000000",
                null,
                ""
            ) || deviceId?.all { it == '0' } == true
            signals += DetectionSignal("telephony.imei.fake", "Fake or zero IMEI", fakeImei, 3)
        }

        val networkOperator = tm?.networkOperatorName
        val noOperator = networkOperator.isNullOrBlank() || networkOperator == "Android"

        signals += DetectionSignal("telephony.none", "No cellular radio", noPhoneType, 2)
        signals += DetectionSignal("telephony.no_operator", "No network operator", noOperator, 2)

        return signals
    }

    private fun checkBatteryStatus(context: Context): List<DetectionSignal> {
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
            ?: return emptyList()
        val isCharging = bm.isCharging
        val batteryLevel = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)

        val suspiciousLevel = batteryLevel == 50 || batteryLevel == 100
        val neverCharging = !isCharging && batteryLevel == 100

        return listOf(
            DetectionSignal(
                "battery.always_50_or_100",
                "Battery stuck at 0% or 100%",
                suspiciousLevel,
                2
            ),
            DetectionSignal(
                "battery.never_charging",
                "100% battery but not charging",
                neverCharging,
                2
            )
        )
    }

    private fun checkPowerThermalState(context: Context): List<DetectionSignal> {
        val pm =
            context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return emptyList()
        val thermal = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            pm.currentThermalStatus
        } else {
            PowerManager.THERMAL_STATUS_NONE
        }

        val suspicious = thermal <= PowerManager.THERMAL_STATUS_LIGHT

        return listOf(
            DetectionSignal(
                "thermal.low_or_none",
                "Unrealistic thermal state",
                suspicious,
                2
            )
        )
    }

    private fun checkLightAndMagneticSensors(context: Context): List<DetectionSignal> {
        val sm =
            context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager ?: return emptyList()

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
        val wifiManager =
            context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
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
        val hasFrontCamera =
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_FRONT)
        val triggered = !hasCamera && !hasFrontCamera
        return DetectionSignal("camera.missing", "No camera hardware", triggered, 2)
    }

    private fun checkNfcFeature(context: Context): DetectionSignal {
        val hasNfc = context.packageManager.hasSystemFeature(PackageManager.FEATURE_NFC)
        return DetectionSignal("nfc.missing", "No NFC hardware (common in emulators)", !hasNfc, 1)
    }

    private fun checkAndroidId(context: Context): DetectionSignal {
        val androidId =
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        val isSuspicious = androidId.isNullOrBlank() ||
                androidId == "9774d56d682e549c" || // Known emulator ID
                androidId.all { it == '0' }
        return DetectionSignal(
            "settings.android_id.suspicious",
            "Suspicious Android ID",
            isSuspicious,
            2
        )
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
        val hasMultiTouch =
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_TOUCHSCREEN_MULTITOUCH)
        return DetectionSignal(
            "touchscreen.multitouch.missing",
            "No multitouch support",
            !hasMultiTouch,
            1
        )
    }

    private fun checkUSBAccessories(context: Context): DetectionSignal {
        val hasUSB = context.packageManager.hasSystemFeature(PackageManager.FEATURE_USB_ACCESSORY)
        return DetectionSignal("usb.accessory.missing", "No USB accessory support", !hasUSB, 1)
    }

    private fun checkBluestacksPackages(context: Context): DetectionSignal {
        val bluestacksPackages = listOf(
            "com.bluestacks.appmart",
            "com.bluestacks.BstCommandProcessor",
            "com.bluestacks.help",
            "com.bluestacks.home",
            "com.bluestacks.s2p",
            "com.bluestacks.search",
            "com.bluestacks.settings",
            "com.bluestacks.setup",
            "com.bluestacks.appfinder",
            "com.bluestacks.keymapping",
            "com.bluestacks.gamecontrols",
            "com.bluestacks.multiinstance",
            "com.bluestacks.bstfolder",
            "com.bluestacks.launcher",
            "com.bluestacks.windows_messaging",
            "com.bluestacks.windows_notification",
            "com.bluestacks.bluetooth",
            "com.bluestacks.camera",
            "com.bluestacks.location",
            "com.bluestacks.microphone",
            "com.bluestacks.sensor",
            "com.bluestacks.network",
            "com.bluestacks.telephony",
            "com.bluestacks.wifi",
            "com.bluestacks.xposed.bridge",
            "com.bluestacks.xposed.installer",
            "com.bluestacks.xposed.modules",
            "com.bluestacks.xposed.services",
            "com.bluestacks.xposed.utils",
            "com.bluestacks.xposed.config",
            "com.bluestacks.xposed.preferences",
            "com.bluestacks.xposed.ui",
            "com.bluestacks.xposed.widgets",
            "com.bluestacks.xposed.core",
            "com.bluestacks.xposed.framework",
            "com.bluestacks.xposed.hooks",
            "com.bluestacks.xposed.patches",
            "com.bluestacks.xposed.plugins",
            "com.bluestacks.xposed.tweaks",
            "com.bluestacks.xposed.customization",
            "com.bluestacks.xposed.performance",
            "com.bluestacks.xposed.security",
            "com.bluestacks.xposed.privacy",
            "com.bluestacks.xposed.adblock",
            "com.bluestacks.xposed.gps",
            "com.bluestacks.xposed.camera",
            "com.bluestacks.xposed.microphone",
            "com.bluestacks.xposed.sensor",
            "com.bluestacks.xposed.network",
            "com.bluestacks.xposed.bluetooth",
            "com.bluestacks.xposed.storage",
            "com.bluestacks.xposed.battery",
            "com.bluestacks.xposed.display",
            "com.bluestacks.xposed.audio",
            "com.bluestacks.xposed.input",
            "com.bluestacks.xposed.touch",
            "com.bluestacks.xposed.keyboard",
            "com.bluestacks.xposed.mouse",
            "com.bluestacks.xposed.gamepad",
            "com.bluestacks.xposed.controller",
            "com.bluestacks.xposed.joystick",
            "com.bluestacks.xposed.wheel",
            "com.bluestacks.xposed.accelerometer",
            "com.bluestacks.xposed.gyroscope",
            "com.bluestacks.xposed.compass",
            "com.bluestacks.xposed.light",
            "com.bluestacks.xposed.proximity",
            "com.bluestacks.xposed.pressure",
            "com.bluestacks.xposed.humidity",
            "com.bluestacks.xposed.temperature",
            "com.bluestacks.xposed.rotation",
            "com.bluestacks.xposed.orientation",
            "com.bluestacks.xposed.gravity",
            "com.bluestacks.xposed.linear_acceleration",
            "com.bluestacks.xposed.rotation_vector",
            "com.bluestacks.xposed.game_rotation_vector",
            "com.bluestacks.xposed.geomagnetic_rotation_vector",
            "com.bluestacks.xposed.significant_motion",
            "com.bluestacks.xposed.step_counter",
            "com.bluestacks.xposed.step_detector"
        )

        val packageManager = context.packageManager
        val triggered = bluestacksPackages.any { packageName ->
            try {
                packageManager.getPackageInfo(packageName, 0)
                true
            } catch (e: Exception) {
                false
            }
        }

        return DetectionSignal("packages.bluestacks", "Bluestacks packages detected", triggered, 4)
    }


    /**
     *    Helper Functions
     */


    private fun readFileSafe(path: String): String = try {
        File(path).takeIf { it.exists() && it.canRead() }?.readText() ?: ""
    } catch (t: Throwable) {
        ""
    }

    private fun readGetProp(): Map<String, String> = try {
        val process = Runtime.getRuntime().exec("getprop")
        val output = process.inputStream.bufferedReader().readText()
        val map = mutableMapOf<String, String>()
        Pattern.compile("\\[(.+?)\\]: \\[(.+?)\\]").matcher(output).apply {
            while (find()) map[group(1)] = group(2)
        }
        map
    } catch (t: Throwable) {
        emptyMap()
    }
}