package com.lh7n.lab

import android.app.Activity
import android.os.Bundle
import android.graphics.Color
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : Activity() {

    private lateinit var report: TextView
    private lateinit var scanButton: Button

    private val preferences by lazy {
        getSharedPreferences("lh7n_security_agent", MODE_PRIVATE)
    }

    private fun saveScan(result: SecurityScanResult) {
        val old = try {
            JSONArray(
                preferences.getString("scan_history", "[]")
            )
        } catch (_: Exception) {
            JSONArray()
        }

        val updated = JSONArray()

        updated.put(
            JSONObject()
                .put("timestamp", result.timestamp)
                .put("score", result.score)
                .put("report", result.toReport())
        )

        for (i in 0 until minOf(old.length(), 29)) {
            updated.put(old.getJSONObject(i))
        }

        preferences.edit()
            .putString("scan_history", updated.toString())
            .apply()
    }

    private fun renderResult(result: SecurityScanResult) {
        val history = try {
            JSONArray(
                preferences.getString("scan_history", "[]")
            )
        } catch (_: Exception) {
            JSONArray()
        }

        val historyText = buildString {
            appendLine()
            appendLine("UNIFIED SECURITY HISTORY")
            appendLine("========================")
            appendLine("Stored scans: ${history.length()}/30")

            for (i in 0 until minOf(history.length(), 5)) {
                val item = history.getJSONObject(i)
                appendLine(
                    "${i + 1}. ${item.optString("timestamp")} | " +
                        "Score ${item.optInt("score")}/100"
                )
            }
        }

        report.text = result.toReport() + historyText
    }

    private fun startScan() {
        scanButton.isEnabled = false
        scanButton.text = "Scanning..."
        report.text = "LH7n Security Agent\n\nCollecting local security evidence..."

        Thread {
            try {
                val result = SecurityAgent.scan(this)

                runOnUiThread {
                    saveScan(result)
                    renderResult(result)

                    scanButton.isEnabled = true
                    scanButton.text = "Start Security Scan"
                }
            } catch (e: Exception) {
                runOnUiThread {
                    report.text =
                        "Security scan failed:\n${e.message ?: "Unknown error"}"

                    scanButton.isEnabled = true
                    scanButton.text = "Start Security Scan"

                    Toast.makeText(
                        this,
                        "Scan failed",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }.start()
    }

    private fun makeText(
        value: String,
        size: Float,
        color: Int,
        bold: Boolean = false
    ): TextView {
        return TextView(this).apply {
            text = value
            textSize = size
            setTextColor(color)
            if (bold) {
                setTypeface(null, android.graphics.Typeface.BOLD)
            }
            setPadding(12, 12, 12, 12)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.statusBarColor = Color.rgb(12, 18, 30)
        window.navigationBarColor = Color.rgb(12, 18, 30)

        val background = Color.rgb(15, 22, 36)
        val foreground = Color.rgb(225, 233, 245)
        val muted = Color.rgb(145, 161, 184)
        val accent = Color.rgb(40, 190, 150)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(background)
            setPadding(16, 20, 16, 16)
        }

        val scroll = ScrollView(this)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        content.addView(
            makeText(
                "LH7n",
                32f,
                foreground,
                true
            )
        )

        content.addView(
            makeText(
                "SECURITY INTELLIGENCE AGENT",
                13f,
                accent,
                true
            )
        )

        content.addView(
            makeText(
                "Local Android security assessment",
                14f,
                muted
            )
        )

        scanButton = Button(this).apply {
            text = "Start Security Scan"
            isAllCaps = false
            setTextColor(Color.WHITE)
            setBackgroundColor(accent)
            setOnClickListener {
                startScan()
            }
        }

        content.addView(
            scanButton,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = 20
                bottomMargin = 16
            }
        )

        report = makeText(
            "Agent ready.\n\nStart a scan to collect and analyze device security evidence.",
            13f,
            foreground
        ).apply {
            typeface = android.graphics.Typeface.MONOSPACE
            setTextIsSelectable(true)
            setPadding(14, 18, 14, 24)
        }

        content.addView(report)
        scroll.addView(content)
        root.addView(scroll)
        setContentView(root)
    }
}
