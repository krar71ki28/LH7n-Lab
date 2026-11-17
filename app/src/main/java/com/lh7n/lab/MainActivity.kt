package com.lh7n.lab

import android.app.Activity
import android.os.Bundle
import android.os.Build
import android.content.Intent
import android.graphics.Color
import android.widget.*
import android.net.Uri
import java.io.File
import java.security.MessageDigest
import java.util.Locale

class MainActivity : Activity() {

    private lateinit var report: TextView
    private lateinit var expectedHash: EditText

    private fun getProp(name: String): String {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", name))
            process.inputStream.bufferedReader().use {
                it.readText().trim().ifBlank { "غير متاح" }
            }
        } catch (_: Exception) {
            "غير متاح"
        }
    }

    private fun rootIndicators(): String {
        val paths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system_ext/bin/su",
            "/vendor/bin/su",
            "/debug_ramdisk/su",
            "/data/adb/magisk"
        )

        val found = paths.filter { path ->
            try {
                File(path).exists()
            } catch (_: Exception) {
                false
            }
        }

        val tags = Build.TAGS ?: ""
        val testKeys = tags.contains("test-keys", ignoreCase = true)

        val status = when {
            found.isNotEmpty() || testKeys ->
                "تم العثور على مؤشرات محتملة لـ Root"
            else ->
                "لم يتم العثور على مؤشرات Root معروفة"
        }

        return buildString {
            appendLine("Root Detection")
            appendLine("================")
            appendLine("النتيجة: $status")
            appendLine("Build Tags: ${tags.ifBlank { "غير متاح" }}")
            appendLine("مسارات مؤشرات Root الموجودة:")

            if (found.isEmpty()) {
                appendLine("لم يتم العثور على ملفات في المسارات المفحوصة")
            } else {
                found.forEach { appendLine(it) }
            }

            appendLine()
            appendLine("حالة صلاحية su الفعلية: لم يتم اختبارها")
            appendLine("هذه نتيجة فحص مؤشرات فقط، وليست إثباتاً")
            appendLine("لوجود Root أو عدم وجوده.")
            appendLine("لم يتم طلب صلاحيات مرتفعة أو تنفيذ su.")
        }
    }

    private fun deviceReport(): String {
        val kernel = System.getProperty("os.version") ?: "غير متاح"

        val branchMatch = Regex("android(\\d+)-(\\d+)")
            .find(kernel)

        val branch = branchMatch?.let {
            "android${it.groupValues[1]}-${it.groupValues[2]}"
        } ?: "لم يتم التعرف على فرع Android في إصدار Kernel"

        return """
            LH7n LAB — DEVICE REPORT
            ========================

            الشركة: ${Build.MANUFACTURER}
            الجهاز: ${Build.DEVICE}
            الموديل: ${Build.MODEL}
            المنتج: ${Build.PRODUCT}

            Android: ${Build.VERSION.RELEASE}
            SDK: ${Build.VERSION.SDK_INT}
            Build ID: ${Build.DISPLAY}

            Kernel:
            $kernel

            Kernel Branch Tag:
            $branch

            KMI:
            لا يمكن تأكيد KMI من رقم Kernel وحده.
            يحتاج إلى معلومات إضافية من النظام.

            ABI:
            ${Build.SUPPORTED_ABIS.joinToString()}

            Bootloader:
            ${Build.BOOTLOADER}

            Verified Boot:
            ${getProp("ro.boot.verifiedbootstate")}

            Bootloader Locked:
            ${getProp("ro.boot.flash.locked")}

            VBMeta State:
            ${getProp("ro.boot.vbmeta.device_state")}

            ${rootIndicators()}

            ملاحظة:
            هذه معلومات تشخيصية للقراءة فقط.
            بعض الخصائص قد تكون محجوبة عن التطبيقات.
        """.trimIndent()
    }

    private fun makeButton(label: String, action: () -> Unit): Button {
        return Button(this).apply {
            text = label
            isAllCaps = false
            setOnClickListener { action() }
        }
    }

    private fun addText(parent: LinearLayout, value: String, size: Float) {
        parent.addView(TextView(this).apply {
            text = value
            textSize = size
            setTextColor(Color.rgb(30, 35, 48))
            setPadding(12, 12, 12, 12)
        })
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.statusBarColor = Color.rgb(20, 25, 38)
        window.navigationBarColor = Color.rgb(20, 25, 38)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.rgb(245, 247, 251))
            setPadding(16, 16, 16, 24)
        }

        val scroll = ScrollView(this)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        addText(content, "LH7n Lab", 28f)
        addText(content, "Device Diagnostics & Compatibility", 14f)

        content.addView(makeButton("فحص معلومات الجهاز") {
            report.text = deviceReport()
        })

        content.addView(makeButton("فحص مؤشرات Root") {
            report.text = rootIndicators()
        })

        addText(content, "فحص SHA-256 للملفات", 20f)

        expectedHash = EditText(this).apply {
            hint = "الصق بصمة SHA-256 المتوقعة هنا"
            textSize = 13f
            isSingleLine = true
        }
        content.addView(expectedHash)

        content.addView(makeButton("اختيار ملف وفحص بصمته") {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }
            startActivityForResult(intent, 100)
        })

        content.addView(makeButton("نسخ تقرير الجهاز") {
            val clipboard = getSystemService(CLIPBOARD_SERVICE)
                as android.content.ClipboardManager
            clipboard.setPrimaryClip(
                android.content.ClipData.newPlainText(
                    "LH7n Lab Report",
                    report.text
                )
            )
            Toast.makeText(this, "تم نسخ التقرير", Toast.LENGTH_SHORT).show()
        })

        report = TextView(this).apply {
            text = "اختر فحص معلومات الجهاز أو فحص مؤشرات Root."
            textSize = 13f
            typeface = android.graphics.Typeface.MONOSPACE
            setTextColor(Color.rgb(25, 35, 50))
            setPadding(12, 20, 12, 20)
            setTextIsSelectable(true)
        }

        content.addView(report)
        scroll.addView(content)
        root.addView(scroll)
        setContentView(root)
    }

    @Deprecated("Legacy file picker callback")
    override fun onActivityResult(
        requestCode: Int,
        resultCode: Int,
        data: Intent?
    ) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode != 100 || resultCode != RESULT_OK) return

        val uri: Uri = data?.data ?: return

        try {
            val digest = MessageDigest.getInstance("SHA-256")
            val input = contentResolver.openInputStream(uri)
                ?: throw Exception("تعذر فتح الملف")

            val buffer = ByteArray(8192)
            input.use {
                while (true) {
                    val count = it.read(buffer)
                    if (count <= 0) break
                    digest.update(buffer, 0, count)
                }
            }

            val actual = digest.digest().joinToString("") {
                "%02x".format(Locale.US, it)
            }

            val expected = expectedHash.text.toString()
                .trim()
                .removePrefix("sha256:")
                .lowercase(Locale.US)

            val comparison = when {
                expected.isBlank() -> "لم تدخل بصمة للمقارنة."
                expected == actual -> "تطابق البصمة: نعم"
                else -> "تطابق البصمة: لا"
            }

            report.text = """
                SHA-256 FILE REPORT
                ===================

                البصمة المحسوبة:
                $actual

                $comparison

                ملاحظة:
                تطابق SHA-256 يثبت تطابق محتوى الملف
                مع البصمة المتوقعة، ولا يثبت سلامة
                البرنامج أو توافقه مع الجهاز.
            """.trimIndent()

        } catch (e: Exception) {
            report.text = "فشل الفحص: ${e.message}"
        }
    }
}
