package com.lh7n.lab

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.time.LocalDate
import java.time.temporal.ChronoUnit
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class SecurityFinding(
    val title: String,
    val severity: String,
    val confidence: String,
    val evidence: String,
    val recommendation: String
)

data class SecurityScanResult(
    val timestamp: String,
    val score: Int,
    val device: String,
    val android: String,
    val findings: List<SecurityFinding>,
    val limitations: List<String>,
    val bulletinReport: String = ""
) {
    fun toReport(): String = buildString {
        appendLine("LH7n SECURITY AGENT")
        appendLine("===================")
        appendLine("Scan time: $timestamp")
        appendLine("Security posture indicator: $score/100")
        appendLine("Device: $device")
        appendLine("Android: $android")
        appendLine()
        appendLine("FINDINGS")
        appendLine("--------")

        findings.forEachIndexed { index, finding ->
            appendLine()
            appendLine("${index + 1}. ${finding.title}")
            appendLine("Severity: ${finding.severity}")
            appendLine("Confidence: ${finding.confidence}")
            appendLine("Evidence: ${finding.evidence}")
            appendLine("Recommendation: ${finding.recommendation}")
        }

        appendLine()
        appendLine("LIMITATIONS")
        appendLine("-----------")
        limitations.forEach { appendLine("- $it") }

        appendLine()
        if (bulletinReport.isNotBlank()) {
            appendLine()
            appendLine(bulletinReport)
        }

        appendLine()
        appendLine("SCANNER MODE: LOCAL READ-ONLY")
        appendLine("No exploit executed.")
        appendLine("No system files modified.")
        appendLine("No elevated permission requested.")
        appendLine()
        appendLine("Score is a heuristic indicator, not a security certification.")
    }
}

object SecurityAgent {

    private fun timestamp(): String =
        SimpleDateFormat(
            "yyyy-MM-dd HH:mm:ss",
            Locale.US
        ).format(Date())

    private fun getProp(name: String): String {
        return try {
            val process = ProcessBuilder("getprop", name)
                .redirectErrorStream(true)
                .start()

            process.inputStream.bufferedReader()
                .use { it.readText().trim() }
        } catch (_: Exception) {
            ""
        }
    }

    private fun packageInstalled(
        context: Context,
        packageName: String
    ): Boolean {
        return try {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (_: Exception) {
            false
        }
    }

    fun scan(context: Context): SecurityScanResult {
        val findings = mutableListOf<SecurityFinding>()

        fun add(
            title: String,
            severity: String,
            confidence: String,
            evidence: String,
            recommendation: String
        ) {
            findings.add(
                SecurityFinding(
                    title,
                    severity,
                    confidence,
                    evidence,
                    recommendation
                )
            )
        }

        val verifiedBoot = getProp("ro.boot.verifiedbootstate")
        val bootLocked = getProp("ro.boot.flash.locked")
        val vbmeta = getProp("ro.boot.vbmeta.device_state")

        val debuggable = getProp("ro.debuggable")
        val secure = getProp("ro.secure")
        val buildType = getProp("ro.build.type")
        val tags = Build.TAGS ?: ""

        // Boot integrity analysis
        when {
            verifiedBoot == "green" &&
                bootLocked == "1" &&
                vbmeta == "locked" -> {
                add(
                    "Boot integrity indicators",
                    "INFO",
                    "HIGH",
                    "Verified Boot=green, Bootloader Locked=1, VBMeta=locked",
                    "Keep the device updated and preserve its verified boot configuration."
                )
            }

            verifiedBoot in listOf("orange", "yellow", "red") ||
                bootLocked == "0" ||
                vbmeta == "unlocked" -> {
                add(
                    "Boot integrity requires review",
                    "HIGH",
                    "HIGH",
                    "Verified Boot=$verifiedBoot, Bootloader Locked=$bootLocked, VBMeta=$vbmeta",
                    "Review the device boot configuration with the manufacturer."
                )
            }

            else -> {
                add(
                    "Boot integrity incomplete",
                    "INFO",
                    "LOW",
                    "Some boot integrity properties are unavailable or unrecognized.",
                    "Treat boot integrity as unverified until reliable values are available."
                )
            }
        }

        // Android security patch age
        val patch = Build.VERSION.SECURITY_PATCH.orEmpty()

        if (patch.isBlank()) {
            add(
                "Security patch date unavailable",
                "INFO",
                "LOW",
                "Android did not provide a security patch date.",
                "Check the system update screen for the installed security patch."
            )
        } else {
            try {
                val patchDate = LocalDate.parse(patch.take(10))
                val ageDays = ChronoUnit.DAYS.between(
                    patchDate,
                    LocalDate.now()
                )

                when {
                    ageDays > 180 -> add(
                        "Android security patch is old",
                        "HIGH",
                        "HIGH",
                        "Patch=$patch, age=$ageDays days.",
                        "Check for an official system update from the device manufacturer."
                    )

                    ageDays > 90 -> add(
                        "Android security patch needs review",
                        "MEDIUM",
                        "HIGH",
                        "Patch=$patch, age=$ageDays days.",
                        "Check whether a newer official security update is available."
                    )

                    ageDays >= 0 -> add(
                        "Android security patch",
                        "INFO",
                        "HIGH",
                        "Patch=$patch, age=$ageDays days.",
                        "Continue installing official security updates."
                    )

                    else -> add(
                        "Security patch date is unusual",
                        "MEDIUM",
                        "MEDIUM",
                        "Reported patch date is in the future: $patch.",
                        "Verify the reported date in Android system settings."
                    )
                }
            } catch (_: Exception) {
                add(
                    "Security patch date could not be parsed",
                    "INFO",
                    "LOW",
                    "Reported value: $patch",
                    "Verify the security patch date in Android settings."
                )
            }
        }

        // Build configuration
        if (tags.contains("test-keys", ignoreCase = true)) {
            add(
                "Test build keys detected",
                "MEDIUM",
                "HIGH",
                "Build Tags=$tags",
                "Verify that this is an official build intended for this device."
            )
        }

        if (debuggable == "1") {
            add(
                "Debuggable system property enabled",
                "MEDIUM",
                "HIGH",
                "ro.debuggable=1",
                "Verify whether this build is intended for production use."
            )
        }

        if (secure == "0") {
            add(
                "Android secure property disabled",
                "HIGH",
                "HIGH",
                "ro.secure=0",
                "Verify the firmware configuration with the manufacturer."
            )
        }

        if (buildType.isNotBlank() && buildType != "user") {
            add(
                "Non-production build type",
                "MEDIUM",
                "HIGH",
                "ro.build.type=$buildType",
                "Confirm that this firmware is appropriate for normal device use."
            )
        }

        // Root manager detection: presence is not proof of active root.
        val managers = listOf(
            "KernelSU" to "me.weishu.kernelsu",
            "Magisk" to "com.topjohnwu.magisk"
        )

        managers.filter {
            packageInstalled(context, it.second)
        }.forEach {
            add(
                "${it.first} manager application detected",
                "INFO",
                "HIGH",
                "Visible installed package: ${it.second}",
                "Application presence alone does not prove kernel integration or root access."
            )
        }

        // Visible filesystem indicators only.
        val rootPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/vendor/bin/su",
            "/system_ext/bin/su",
            "/debug_ramdisk/su",
            "/data/adb/magisk",
            "/data/adb/ksu"
        )

        val visiblePaths = rootPaths.filter { path ->
            try {
                File(path).exists()
            } catch (_: Exception) {
                false
            }
        }

        if (visiblePaths.isNotEmpty()) {
            add(
                "Potential root filesystem indicators",
                "MEDIUM",
                "MEDIUM",
                visiblePaths.joinToString(),
                "Verify these indicators independently; visibility does not prove active root."
            )
        }

        // Audit permissions requested by LH7n Lab itself.
        try {
            @Suppress("DEPRECATION")
            val ownInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_PERMISSIONS
            )

            val requested = ownInfo.requestedPermissions
                ?.toList()
                .orEmpty()

            add(
                "LH7n Lab permission footprint",
                "INFO",
                "HIGH",
                if (requested.isEmpty()) {
                    "No manifest permissions declared by LH7n Lab."
                } else {
                    "Declared permissions: ${requested.joinToString()}"
                },
                "Keep application permissions limited to the features actually required."
            )
        } catch (_: Exception) {
            add(
                "Application permission audit incomplete",
                "INFO",
                "LOW",
                "Could not read this application's requested permissions.",
                "Review the application manifest."
            )
        }

        if (findings.isEmpty()) {
            add(
                "No findings generated",
                "INFO",
                "LOW",
                "The scanner did not produce any findings.",
                "Repeat the scan and review scanner limitations."
            )
        }

        val weights = mapOf(
            "CRITICAL" to 35,
            "HIGH" to 20,
            "MEDIUM" to 10,
            "LOW" to 4,
            "INFO" to 0
        )

        val score = (
            100 - findings.sumOf {
                weights[it.severity] ?: 0
            }
        ).coerceIn(0, 100)

        val bulletinResult = AndroidBulletinIntelligence.scan(
            installedPatch = patch,
            androidMajor = Build.VERSION.SDK_INT - 20
        )

        val mediatekResult = MediaTekBulletinIntelligence.scan()

        return SecurityScanResult(
            timestamp = timestamp(),
            score = score,
            device = "${Build.MANUFACTURER} ${Build.MODEL}",
            android = "${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT})",
            findings = findings,
            bulletinReport = bulletinResult.report + "\\n\\n" + mediatekResult.report,
            limitations = listOf(
                "Android package visibility can hide applications from this scanner.",
                "This version does not inspect every installed application's permissions.",
                "Root manager detection does not prove active root access.",
                "Filesystem visibility is restricted by Android application sandboxing.",
                "No exploit testing or OEM patch verification is performed.",
                "The score is a heuristic and must not be treated as a probability."
            )
        )
    }
}
