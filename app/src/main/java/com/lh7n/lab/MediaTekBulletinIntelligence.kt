package com.lh7n.lab

import android.os.Build
import java.net.HttpURLConnection
import java.net.URL
import java.time.LocalDate
import java.time.format.TextStyle
import java.util.Locale

data class MediaTekCveRecord(
    val cve: String,
    val subcomponent: String,
    val severity: String,
    val affectedChipsets: String,
    val status: String,
    val source: String
)

data class MediaTekScanResult(
    val report: String,
    val records: List<MediaTekCveRecord>
)

object MediaTekBulletinIntelligence {

    private data class FetchResult(
        val html: String?,
        val status: String
    )

    private fun clean(value: String): String {
        return value
            .replace(Regex("(?is)<script\\b.*?</script>"), " ")
            .replace(Regex("(?is)<style\\b.*?</style>"), " ")
            .replace(Regex("(?i)<br\\s*/?>"), " ")
            .replace(Regex("<[^>]+>"), " ")
            .replace("&nbsp;", " ")
            .replace("&#160;", " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace(Regex("\\s+"), " ")
            .trim()
    }

    private fun deviceChipset(): String {
        val values = mutableListOf<String>()

        if (Build.VERSION.SDK_INT >= 31) {
            values.add(Build.SOC_MODEL.orEmpty())
        }

        values.add(Build.HARDWARE.orEmpty())
        values.add(Build.BOARD.orEmpty())
        values.add(Build.DEVICE.orEmpty())

        val pattern = Regex("""\bMT\d{4,5}\b""")

        for (value in values) {
            val match = pattern.find(value.uppercase(Locale.ROOT))
            if (match != null) return match.value
        }

        return ""
    }

    private fun fetch(url: String): FetchResult {
        var connection: HttpURLConnection? = null

        return try {
            connection = URL(url).openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 10000
            connection.readTimeout = 15000
            connection.instanceFollowRedirects = true
            connection.setRequestProperty(
                "User-Agent",
                "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36"
            )
            connection.setRequestProperty("Accept", "text/html")

            val code = connection.responseCode

            if (code != HttpURLConnection.HTTP_OK) {
                FetchResult(null, "HTTP_$code")
            } else {
                val html = connection.inputStream
                    .bufferedReader(Charsets.UTF_8)
                    .use { it.readText() }

                if (html.isBlank()) {
                    FetchResult(null, "EMPTY_RESPONSE")
                } else {
                    FetchResult(html, "HTTP_200")
                }
            }
        } catch (e: Exception) {
            FetchResult(
                null,
                "NETWORK_ERROR: ${e.javaClass.simpleName}"
            )
        } finally {
            connection?.disconnect()
        }
    }

    private fun normalizeKey(value: String): String {
        return clean(value)
            .lowercase(Locale.ROOT)
            .replace(Regex("[^a-z0-9]+"), " ")
            .trim()
    }

    private fun parse(
        html: String,
        chipset: String,
        source: String
    ): List<MediaTekCveRecord> {

        val records = mutableListOf<MediaTekCveRecord>()

        fun buildRecord(fields: Map<String, String>) {
            val cve = fields["cve"]
                ?.uppercase(Locale.ROOT)
                .orEmpty()

            if (!Regex("""^CVE-\d{4}-\d{4,}$""").matches(cve)) {
                return
            }

            val affected = fields["affected chipsets"].orEmpty()
            val component = fields["subcomponent"].orEmpty()
            val severity = fields["severity"].orEmpty()

            val listedChipsets = Regex(
                """\bMT\d{4,5}\b"""
            ).findAll(affected.uppercase(Locale.ROOT))
                .map { it.value }
                .toSet()

            val status = when {
                chipset.isBlank() -> "CHIPSET_UNKNOWN"
                listedChipsets.contains(chipset) ->
                    "CHIPSET_MATCH_PATCH_STATUS_UNKNOWN"
                affected.isBlank() ->
                    "AFFECTED_CHIPSETS_NOT_PROVIDED"
                else -> "CHIPSET_NOT_LISTED"
            }

            records.add(
                MediaTekCveRecord(
                    cve = cve,
                    subcomponent = component.ifBlank { "Not stated" },
                    severity = severity.ifBlank { "Not stated" },
                    affectedChipsets = affected.ifBlank {
                        "Not provided by source"
                    },
                    status = status,
                    source = source
                )
            )
        }

        val tables = Regex(
            """(?is)<table\b[^>]*>(.*?)</table>"""
        ).findAll(html)

        for (table in tables) {
            val fields = linkedMapOf<String, String>()

            val rows = Regex(
                """(?is)<tr\b[^>]*>(.*?)</tr>"""
            ).findAll(table.groupValues[1])

            for (row in rows) {
                val cells = Regex(
                    """(?is)<t[dh]\b[^>]*>(.*?)</t[dh]>"""
                ).findAll(row.groupValues[1])
                    .map { clean(it.groupValues[1]) }
                    .toList()

                if (cells.size < 2) continue

                val key = normalizeKey(cells.first())
                val value = cells.drop(1)
                    .filter { it.isNotBlank() }
                    .joinToString(" ")
                    .trim()

                if (key == "cve") {
                    if (fields.containsKey("cve")) {
                        buildRecord(fields)
                        fields.clear()
                    }
                }

                if (key.isNotBlank() && value.isNotBlank()) {
                    fields[key] = value
                }
            }

            buildRecord(fields)
        }

        return records.distinctBy { it.cve }
    }

    fun scan(): MediaTekScanResult {
        val chipset = deviceChipset()
        val now = LocalDate.now()

        val months = (0L..2L).map {
            now.withDayOfMonth(1).minusMonths(it)
        }

        val allRecords = mutableListOf<MediaTekCveRecord>()
        val diagnostics = mutableListOf<String>()
        var successfulPages = 0

        for (month in months) {
            val monthName = month.month.getDisplayName(
                TextStyle.FULL,
                Locale.ENGLISH
            )

            val slug = "$monthName-${month.year}"
            val source =
                "https://www.mediatek.com/product-security-bulletin/$slug"

            val fetched = fetch(source)

            if (fetched.html == null) {
                diagnostics.add("$slug: ${fetched.status}")
                continue
            }

            successfulPages++

            val parsed = parse(
                fetched.html,
                chipset,
                source
            )

            if (parsed.isEmpty()) {
                diagnostics.add("$slug: HTTP_200_NO_CVE_RECORDS_PARSED")
            } else {
                allRecords.addAll(parsed)
            }
        }

        val records = allRecords.distinctBy { it.cve }

        val matched = records.count {
            it.status == "CHIPSET_MATCH_PATCH_STATUS_UNKNOWN"
        }

        val notListed = records.count {
            it.status == "CHIPSET_NOT_LISTED"
        }

        val unknown = records.count {
            it.status == "CHIPSET_UNKNOWN"
        }

        val missing = records.count {
            it.status == "AFFECTED_CHIPSETS_NOT_PROVIDED"
        }

        val report = buildString {
            appendLine("MEDIATEK CHIPSET INTELLIGENCE")
            appendLine("=============================")
            appendLine("Detected chipset: ${chipset.ifBlank { "UNKNOWN" }}")
            appendLine("Bulletin months checked: ${months.size}")
            appendLine("HTTP successful pages: $successfulPages")
            appendLine("Unique MediaTek CVEs: ${records.size}")
            appendLine("CHIPSET MATCH / PATCH STATUS UNKNOWN: $matched")
            appendLine("CHIPSET NOT LISTED: $notListed")
            appendLine("CHIPSET UNKNOWN: $unknown")
            appendLine("AFFECTED CHIPSETS NOT PROVIDED: $missing")
            appendLine()
            appendLine("FETCH AND PARSER DIAGNOSTICS")

            if (diagnostics.isEmpty()) {
                appendLine("No fetch or parser failures reported.")
            } else {
                diagnostics.forEach { appendLine(it) }
            }

            appendLine()
            appendLine("MATCHED CHIPSET RECORDS")

            val matches = records.filter {
                it.status == "CHIPSET_MATCH_PATCH_STATUS_UNKNOWN"
            }

            if (matches.isEmpty()) {
                appendLine("No matching chipset records were confirmed.")
            }

            matches.take(30).forEachIndexed { index, item ->
                appendLine()
                appendLine("${index + 1}. ${item.cve}")
                appendLine("Subcomponent: ${item.subcomponent}")
                appendLine("Severity: ${item.severity}")
                appendLine("Status: ${item.status}")
                appendLine("Source: ${item.source}")
            }

            appendLine()
            appendLine("ASSESSMENT LIMITATIONS")
            appendLine("----------------------")
            appendLine(
                "A chipset match does not prove that this device is vulnerable."
            )
            appendLine(
                "OEM patch status remains unknown until independently verified."
            )
            appendLine(
                "Bulletin publication date is not the device patch installation date."
            )
            appendLine(
                "No exploit testing or system modification was performed."
            )
        }

        return MediaTekScanResult(
            report = report,
            records = records
        )
    }
}
