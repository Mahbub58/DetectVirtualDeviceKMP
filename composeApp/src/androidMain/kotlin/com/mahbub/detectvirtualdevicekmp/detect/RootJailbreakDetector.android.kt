package com.mahbub.detectvirtualdevicekmp.detect

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit

actual object RootJailbreakDetector {
    actual fun collectSignals(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()

        val rootBins = listOf(
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
        ).any { File(it).exists() }
        signals += DetectionSignal("android.root.files","Known root artifacts",rootBins,3)

        val mounts = readFileSafe("/proc/self/mounts")
        val systemRw = mounts.lines().any { it.contains(" /system ") && it.contains("rw,") }
        signals += DetectionSignal("android.root.system_rw","/system mounted rw",systemRw,3)

        val testKeys = Build.TAGS?.contains("test-keys") == true
        signals += DetectionSignal("android.root.test_keys","Build tags contain test-keys",testKeys,2)

        val props = readGetProp()
        val roSecureZero = props["ro.secure"] == "0"
        val roDebugOne = props["ro.debuggable"] == "1"
        signals += DetectionSignal("android.root.ro.secure_zero","ro.secure=0",roSecureZero,2)
        signals += DetectionSignal("android.root.ro.debuggable_one","ro.debuggable=1",roDebugOne,2)

        val whichSu = execCmd(arrayOf("sh","-c","which su"))
        signals += DetectionSignal("android.root.which_su","which su returns path",whichSu.isNotBlank(),3)

        val idRoot = execCmd(arrayOf("sh","-c","su -c id"))
        val uid0 = idRoot.contains("uid=0")
        signals += DetectionSignal("android.root.su_id","su -c id uid=0",uid0,4)

        val magiskHide = File("/sbin/.magisk").exists() || props.keys.any { it.startsWith("magisk.") }
        signals += DetectionSignal("android.root.magisk_hide","Magisk hide indicators",magiskHide,3)

        return signals
    }

    actual fun collectSignalsWithContext(context: Any?): List<DetectionSignal> {
        val list = collectSignals().toMutableList()
        val ctx = context as? Context
        if (ctx != null) {
            val pm = ctx.packageManager
            val pkgs = listOf(
                "com.topjohnwu.magisk",
                "eu.chainfire.supersu",
                "com.noshufou.android.su",
                "com.koushikdutta.superuser",
                "cc.madkite.freedom",
                "com.devadvance.rootcloak2",
                "com.kroothelper",
                "com.yellowes.su"
            )
            val found = pkgs.any { isInstalled(pm, it) }
            list += DetectionSignal("android.root.packages","Known root packages installed",found,3)
        }
        return list
    }

    private fun isInstalled(pm: PackageManager, pkg: String): Boolean {
        return try { pm.getPackageInfo(pkg, 0); true } catch (_: Throwable) { false }
    }

    private fun execCmd(cmd: Array<String>): String {
        return try {
            val p = Runtime.getRuntime().exec(cmd)
            p.waitFor(500, TimeUnit.MILLISECONDS)
            val out = BufferedReader(InputStreamReader(p.inputStream)).readText()
            val err = BufferedReader(InputStreamReader(p.errorStream)).readText()
            if (out.isNotBlank()) out else err
        } catch (_: Throwable) { "" }
    }

    private fun readGetProp(): Map<String, String> {
        return try {
            val p = Runtime.getRuntime().exec(arrayOf("sh","-c","getprop"))
            val text = p.inputStream.bufferedReader().use { it.readText() }
            val map = mutableMapOf<String,String>()
            val regex = Regex("\\[(.*?)\\]: \\[(.*?)\\]")
            regex.findAll(text).forEach { m ->
                map[m.groupValues[1]] = m.groupValues[2]
            }
            map
        } catch (_: Throwable) { emptyMap() }
    }

    private fun readFileSafe(path: String): String {
        return try {
            val f = File(path)
            if (f.exists() && f.canRead()) f.readText() else ""
        } catch (_: Throwable) { "" }
    }
}

