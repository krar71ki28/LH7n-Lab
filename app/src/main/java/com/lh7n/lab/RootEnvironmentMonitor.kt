package com.lh7n.lab

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class RootEnvironmentMonitor(private val context: Context) {

    private val managers = listOf(
        "KernelSU" to "me.weishu.kernelsu",
        "Magisk" to "com.topjohnwu.magisk"
    )

    private val rootPaths = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/system_ext/bin/su",
        "/product/bin/su",
        "/debug_ramdisk/su",
        "/data/adb/magisk",
        "/data/adb/ksu",
        "/sbin/.magisk"
    )

    private fun currentDate(): String =
        SimpleDateFormat(
            "yyyy-MM-dd HH:mm:ss",
            Locale.US
        ).format(Date())

    private fun getProp(name: String): String {
        return try {
            val process = Runtime.getRuntime().exec(
                arrayOf("getprop", name)
            )
            process.inputStream.bufferedReader().use {
                it.readText().trim()
            }
        } catch (_: Exception) {
            ""
        }
    }

    private fun packageExists(packageName: String): Boolean {
        return try {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        } catch (_: Exception) {
            false
        }
    }

    private fun visiblePaths(): List<String> {
        return rootPaths.filter { path ->
            try {
                File(path).exists()
            } catch (_: Exception) {
                false
            }
        }
    }

    fun report(): String {
        val installedManagers = managers.filter {
            packageExists(it.second)
        }

        val foundPaths = visiblePaths()
        val tags = Build.TAGS ?: ""

        val debuggable = getProp("ro.debuggable")
        val secure = getProp("ro.secure")
        val buildType = getProp("ro.build.type")

        val verifiedBoot = getProp("ro.boot.verifiedbootstate")
        val bootLocked = getProp("ro.boot.flash.locked")
        val vbmeta = getProp("ro.boot.vbmeta.device_state")

        val systemSignals = mutableListOf<String>()

        if (foundPaths.isNotEmpty()) {
            systemSignals.add("تم العثور على مسارات أو ملفات معروفة")
        }

        if (tags.contains("test-keys", ignoreCase = true)) {
            systemSignals.add("Build Tags تحتوي test-keys")
        }

        if (debuggable == "1") {
            systemSignals.add("ro.debuggable = 1")
        }

        if (secure == "0") {
            systemSignals.add("ro.secure = 0")
        }

        if (buildType.isNotBlank() && buildType != "user") {
            systemSignals.add("Build Type = $buildType")
        }

        val assessment = when {
            systemSignals.isNotEmpty() ->
                "ظهرت مؤشرات نظام تستحق التحقق، لكنها لا تثبت وجود Root"

            installedManagers.isNotEmpty() ->
                "تم العثور على تطبيق إدارة Root، والتكامل مع Kernel غير مؤكد"

            else ->
                "لم تظهر مؤشرات Root المعروفة ضمن نطاق الفحص، والحالة الفعلية غير معروفة"
        }

        val integrity = when {
            verifiedBoot == "green" &&
                bootLocked == "1" &&
                vbmeta == "locked" ->
                "مؤشرات سلامة الإقلاع متوافقة مع جهاز مقفل"

            verifiedBoot.isBlank() &&
                bootLocked.isBlank() &&
                vbmeta.isBlank() ->
                "بيانات سلامة الإقلاع غير متاحة"

            else ->
                "توجد حالة إقلاع تحتاج إلى مراجعة مستقلة"
        }

        return buildString {
            appendLine("LH7n LAB — ADVANCED ROOT ENVIRONMENT")
            appendLine("====================================")
            appendLine("Date: ${currentDate()}")
            appendLine()

            appendLine("[1] MANAGER DETECTION")
            appendLine("--------------------")

            managers.forEach { (name, _) ->
                val found = installedManagers.any { it.first == name }
                appendLine(
                    "$name: " +
                        if (found) "Detected" else "Not detected"
                )
            }

            appendLine()
            appendLine("[2] SYSTEM INDICATORS")
            appendLine("--------------------")

            if (foundPaths.isEmpty()) {
                appendLine("Known paths: None visible")
            } else {
                foundPaths.forEach {
                    appendLine("Visible path: $it")
                }
            }

            if (systemSignals.isEmpty()) {
                appendLine("Property indicators: None detected")
            } else {
                systemSignals.forEach {
                    appendLine("Signal: $it")
                }
            }

            appendLine()
            appendLine("[3] BUILD PROPERTIES")
            appendLine("--------------------")
            appendLine("Build Tags: ${tags.ifBlank { "Unavailable" }}")
            appendLine("Build Type: ${buildType.ifBlank { "Unavailable" }}")
            appendLine("ro.debuggable: ${debuggable.ifBlank { "Unavailable" }}")
            appendLine("ro.secure: ${secure.ifBlank { "Unavailable" }}")

            appendLine()
            appendLine("[4] BOOT INTEGRITY")
            appendLine("------------------")
            appendLine("Verified Boot: ${verifiedBoot.ifBlank { "Unavailable" }}")
            appendLine("Bootloader Locked: ${bootLocked.ifBlank { "Unavailable" }}")
            appendLine("VBMeta State: ${vbmeta.ifBlank { "Unavailable" }}")
            appendLine("Assessment: $integrity")

            appendLine()
            appendLine("[5] ENVIRONMENT ASSESSMENT")
            appendLine("-------------------------")
            appendLine(assessment)

            appendLine()
            appendLine("Kernel Integration: UNKNOWN")
            appendLine("Root Authorization: NOT TESTED")
            appendLine("Actual Root Status: UNKNOWN")

            appendLine()
            appendLine("SAFETY")
            appendLine("------")
            appendLine("- No su command executed")
            appendLine("- No elevated permission requested")
            appendLine("- No system partition modified")
            appendLine("- No bootloader or kernel modification")
            appendLine()
            appendLine("Limitations:")
            appendLine("- Protected paths may not be visible to this app.")
            appendLine("- Package detection does not prove KernelSU integration.")
            appendLine("- This scan cannot prove Root absence.")
        }
    }

    fun confidenceReport(): String {
        val installedManagers = managers.filter {
            packageExists(it.second)
        }

        val foundPaths = visiblePaths()
        val tags = Build.TAGS ?: ""

        val debuggable = getProp("ro.debuggable")
        val secure = getProp("ro.secure")
        val buildType = getProp("ro.build.type")

        val verifiedBoot = getProp("ro.boot.verifiedbootstate")
        val bootLocked = getProp("ro.boot.flash.locked")
        val vbmeta = getProp("ro.boot.vbmeta.device_state")

        val confirmed = mutableListOf<String>()
        val potential = mutableListOf<String>()
        val unavailable = mutableListOf<String>()

        installedManagers.forEach {
            confirmed.add("تم رصد تطبيق ${it.first} على الجهاز")
            potential.add(
                "وجود تطبيق ${it.first} لا يثبت تكامل Root"
            )
        }

        if (foundPaths.isNotEmpty()) {
            foundPaths.forEach {
                potential.add("مسار ظاهر يحتاج إلى تحقق مستقل: $it")
            }
        } else {
            unavailable.add(
                "لم تظهر مسارات Root المعروفة ضمن نطاق وصول التطبيق"
            )
        }

        if (tags.isNotBlank()) {
            confirmed.add("Build Tags: $tags")
            if (tags.contains("test-keys", ignoreCase = true)) {
                potential.add("Build Tags تحتوي test-keys")
            }
        } else {
            unavailable.add("Build Tags غير متاحة")
        }

        if (buildType.isNotBlank()) {
            confirmed.add("Build Type: $buildType")
            if (buildType != "user") {
                potential.add("نوع البناء ليس user")
            }
        } else {
            unavailable.add("Build Type غير متاح")
        }

        if (debuggable.isNotBlank()) {
            confirmed.add("ro.debuggable: $debuggable")
            if (debuggable == "1") {
                potential.add("ro.debuggable يساوي 1")
            }
        } else {
            unavailable.add("ro.debuggable غير متاح")
        }

        if (secure.isNotBlank()) {
            confirmed.add("ro.secure: $secure")
            if (secure == "0") {
                potential.add("ro.secure يساوي 0")
            }
        } else {
            unavailable.add("ro.secure غير متاح")
        }

        if (verifiedBoot.isNotBlank()) {
            confirmed.add("Verified Boot: $verifiedBoot")
        } else {
            unavailable.add("Verified Boot غير متاح")
        }

        if (bootLocked.isNotBlank()) {
            confirmed.add("Bootloader Locked: $bootLocked")
        } else {
            unavailable.add("حالة قفل Bootloader غير متاحة")
        }

        if (vbmeta.isNotBlank()) {
            confirmed.add("VBMeta State: $vbmeta")
        } else {
            unavailable.add("VBMeta State غير متاح")
        }

        return buildString {
            appendLine("LH7N LAB — ROOT CONFIDENCE ANALYZER")
            appendLine("===================================")
            appendLine("Date: ${currentDate()}")
            appendLine()

            appendLine("[1] ANALYSIS QUALITY")
            appendLine("-------------------")
            appendLine("Evidence completeness: LIMITED")
            appendLine("Root conclusion confidence: INSUFFICIENT")
            appendLine("Reason: Root authorization was not tested")
            appendLine()

            appendLine("[2] CONFIRMED OBSERVATIONS")
            appendLine("-------------------------")
            if (confirmed.isEmpty()) {
                appendLine("No confirmed observations available")
            } else {
                confirmed.forEach {
                    appendLine("- $it")
                }
            }

            appendLine()
            appendLine("[3] POTENTIAL INDICATORS")
            appendLine("-----------------------")
            if (potential.isEmpty()) {
                appendLine("No potential indicators detected")
            } else {
                potential.forEach {
                    appendLine("- $it")
                }
            }

            appendLine()
            appendLine("[4] UNAVAILABLE OR LIMITED")
            appendLine("--------------------------")
            if (unavailable.isEmpty()) {
                appendLine("No unavailable property values detected")
            } else {
                unavailable.forEach {
                    appendLine("- $it")
                }
            }

            appendLine()
            appendLine("[5] NOT TESTED")
            appendLine("--------------")
            appendLine("- Root authorization")
            appendLine("- Actual Root privilege")
            appendLine("- KernelSU kernel integration")
            appendLine()

            appendLine("[6] FINAL ASSESSMENT")
            appendLine("--------------------")
            appendLine("Root Status: UNKNOWN")
            appendLine("Kernel Integration: UNKNOWN")
            appendLine("Manager Detection: " +
                if (installedManagers.isEmpty()) "None detected"
                else installedManagers.joinToString { it.first })
            appendLine()
            appendLine("This report evaluates available evidence only.")
            appendLine("It does not prove Root presence or absence.")
            appendLine()
            appendLine("SAFETY")
            appendLine("------")
            appendLine("- No su command executed")
            appendLine("- No elevated permission requested")
            appendLine("- No system files modified")
        }
    }
}
