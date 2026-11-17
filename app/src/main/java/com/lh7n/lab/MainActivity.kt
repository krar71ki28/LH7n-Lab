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
import java.util.Date
import java.text.SimpleDateFormat

class MainActivity : Activity() {

    private lateinit var report: TextView
    private lateinit var expectedHash: EditText
    private var pendingExport = ""

    private val preferences by lazy {
        getSharedPreferences("lh7n_lab_history", MODE_PRIVATE)
    }

    private fun timestamp(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())

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

    private fun recordHistory(label: String) {
        val entries = (preferences.getString("history", "") ?: "")
            .lines().filter { it.isNotBlank() }.toMutableList()

        entries.add(0, "${timestamp()} | $label")

        preferences.edit()
            .putString("history", entries.take(30).joinToString("\n"))
            .apply()
    }

    private fun showReport(label: String, content: String) {
        report.text = content
        recordHistory(label)
    }

    private fun historyReport(): String {
        val history = preferences.getString("history", "") ?: ""
        return """
            LH7n LAB — DIAGNOSTIC HISTORY
            =============================

            عدد السجلات:
            ${history.lines().count { it.isNotBlank() }}

            السجلات الأحدث أولاً:

            ${history.ifBlank { "لا توجد عمليات فحص محفوظة." }}

            التخزين: SharedPreferences
            الحد الأقصى: 30 سجل
        """.trimIndent()
    }

    private fun exportReport() {
        pendingExport = report.text.toString()
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "text/plain"
            putExtra(
                Intent.EXTRA_TITLE,
                "LH7n-Lab-${timestamp().replace(":", "-")}.txt"
            )
        }
        startActivityForResult(intent, 101)
    }

    private fun packageInstalled(packageName: String): Boolean {
        return try {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, 0)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun rootProviderReport(): String {
        val providers = listOf(
            "KernelSU" to "me.weishu.kernelsu",
            "Magisk" to "com.topjohnwu.magisk"
        )

        val results = providers.map { (name, packageName) ->
            val installed = packageInstalled(packageName)
            "$name: " + if (installed) "تم العثور على التطبيق" else "لم يتم العثور على التطبيق"
        }

        return buildString {
            appendLine("LH7n LAB — ROOT PROVIDER MONITOR")
            appendLine("================================")
            appendLine("تاريخ الفحص: ${timestamp()}")
            appendLine()
            results.forEach { appendLine(it) }
            appendLine()
            appendLine("حالة صلاحية Root: غير مختبرة")
            appendLine("حالة Root الفعلية: غير معروفة")
            appendLine()
            appendLine("ملاحظات:")
            appendLine("- وجود تطبيق المزوّد لا يثبت أن Root يعمل.")
            appendLine("- عدم العثور على التطبيق لا ينفي وجود مزوّد آخر.")
            appendLine("- لم يتم تنفيذ su أو طلب صلاحيات مرتفعة.")
            appendLine("- الفحص يقرأ أسماء الحزم فقط.")
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

        val status = if (found.isNotEmpty() || testKeys) {
            "تم العثور على مؤشرات محتملة لـ Root"
        } else {
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
            appendLine("هذه نتيجة فحص مؤشرات فقط وليست إثباتاً.")
            appendLine("لم يتم طلب صلاحيات مرتفعة أو تنفيذ su.")
        }
    }

    private fun deviceReport(): String {
        val kernel = System.getProperty("os.version") ?: "غير متاح"
        val branchMatch = Regex("android(\\d+)-(\\d+)").find(kernel)
        val branch = branchMatch?.let {
            "android${it.groupValues[1]}-${it.groupValues[2]}"
        } ?: "لم يتم التعرف على فرع Android في إصدار Kernel"

        return """
            LH7n LAB — DEVICE REPORT
            ========================

            تاريخ الفحص: ${timestamp()}

            الشركة: ${Build.MANUFACTURER}
            الجهاز: ${Build.DEVICE}
            الموديل: ${Build.MODEL}
            المنتج: ${Build.PRODUCT}

            Android: ${Build.VERSION.RELEASE}
            SDK: ${Build.VERSION.SDK_INT}
            Build ID: ${Build.DISPLAY}

            Kernel: $kernel
            Kernel Branch Tag: $branch

            KMI:
            لا يمكن تأكيد KMI من رقم Kernel وحده.

            ABI: ${Build.SUPPORTED_ABIS.joinToString()}
            Bootloader: ${Build.BOOTLOADER}
            Verified Boot: ${getProp("ro.boot.verifiedbootstate")}
            Bootloader Locked: ${getProp("ro.boot.flash.locked")}
            VBMeta State: ${getProp("ro.boot.vbmeta.device_state")}

            ${rootIndicators()}

            ملاحظة:
            هذه معلومات تشخيصية للقراءة فقط.
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
            showReport("Device Diagnostics", deviceReport())
        })

        content.addView(makeButton("فحص مؤشرات Root") {
            showReport("Root Detection", rootIndicators())
        })

        content.addView(makeButton("فحص مزوّد Root") {
            showReport("Root Provider Monitor", rootProviderReport())
        })

        content.addView(makeButton("عرض سجل الفحوصات") {
            report.text = historyReport()
        })

        content.addView(makeButton("تصدير التقرير TXT") {
            exportReport()
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

        content.addView(makeButton("نسخ التقرير") {
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
            text = "اختر عملية فحص لعرض نتائجها."
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
        if (resultCode != RESULT_OK) return

        val uri: Uri = data?.data ?: return

        if (requestCode == 101) {
            try {
                val output = contentResolver.openOutputStream(uri)
                    ?: throw Exception("تعذر إنشاء الملف")
                output.use {
                    it.write(pendingExport.toByteArray(Charsets.UTF_8))
                }
                Toast.makeText(
                    this,
                    "تم تصدير التقرير بنجاح",
                    Toast.LENGTH_SHORT
                ).show()
            } catch (e: Exception) {
                Toast.makeText(
                    this,
                    "فشل التصدير: ${e.message}",
                    Toast.LENGTH_LONG
                ).show()
            }
            return
        }

        if (requestCode != 100) return

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

            val result = """
                SHA-256 FILE REPORT
                ===================

                تاريخ الفحص: ${timestamp()}
                البصمة المحسوبة:
                $actual

                $comparison

                ملاحظة:
                تطابق SHA-256 يثبت تطابق محتوى الملف
                مع البصمة المتوقعة، ولا يثبت سلامة
                البرنامج أو توافقه مع الجهاز.
            """.trimIndent()

            showReport("SHA-256 File Check", result)
        } catch (e: Exception) {
            showReport("SHA-256 Error", "فشل الفحص: ${e.message}")
        }
    }
}
