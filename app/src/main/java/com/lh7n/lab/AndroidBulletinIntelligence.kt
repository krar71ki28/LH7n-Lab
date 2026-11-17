package com.lh7n.lab

import java.net.HttpURLConnection
import java.net.URL
import java.time.LocalDate
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

data class BulletinCveRecord(
    val cve: String,
    val patchLevel: String,
    val component: String,
    val vulnerabilityType: String,
    val severity: String,
    val affectedVersions: String,
    val status: String,
    val source: String
)

data class BulletinIntelligenceResult(
    val report: String,
    val records: List<BulletinCveRecord>,
    val bulletinsChecked: Int,
    val successfulBulletins: Int
)

object AndroidBulletinIntelligence {

    private const val BASE =
        "https://source.android.com/docs/security/bulletin"

    private val cveRegex =
        Regex("""CVE-\d{4}-\d{4,}""", RegexOption.IGNORE_CASE)

    private val patchHeaderRegex = Regex(
        """(20\d{2}-\d{2}-0[15])\s+security patch level vulnerability details""",
        RegexOption.IGNORE_CASE
    )

    private fun fetch(url: String): String? {
        var connection: HttpURLConnection? = null

        return try {
            connection = URL(url).openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 5000
            connection.readTimeout = 7000
            connection.instanceFollowRedirects = true
            connection.setRequestProperty(
                "User-Agent",
                "LH7n-Lab-Security-Agent/1.0"
            )
            connection.setRequestProperty(
                "Accept",
                "text/html"
            )

            if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                return null
            }

            connection.inputStream.bufferedReader().use {
                it.readText()
            }
        } catch (_: Exception) {
            null
        } finally {
            connection?.disconnect()
        }
    }

    private fun monthList(
        start: LocalDate,
        end: LocalDate
    ): List<LocalDate> {
        val result = mutableListOf<LocalDate>()
        var current = start.withDayOfMonth(1)
        val last = end.withDayOfMonth(1)

        while (!current.isAfter(last) && result.size < 36) {
            result.add(current)
            current = current.plusMonths(1)
        }

        return result
    }

    private fun cleanHtml(html: String): String {
        return html
            .replace(Regex("(?i)<br\\s*/?>"), "\n")
            .replace(
                Regex("(?i)<h3[^>]*>"),
                "\n### "
            )
            .replace(
                Regex("(?i)</(td|th)>"),
                " | "
            )
            .replace(
                Regex("(?i)</(tr|h2|h3|h4|p|li|section|div)>"),
                "\n"
            )
            .replace(Regex("<[^>]+>"), " ")
            .replace("&nbsp;", " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("\r", "")
            .replace(Regex("[\\t ]+"), " ")
            .replace(Regex(" *\\n *"), "\n")
    }

    private fun parseBulletin(
        month: LocalDate,
        installedPatch: LocalDate,
        androidMajor: Int
    ): List<BulletinCveRecord> {

        val year = month.year
        val monthNumber = "%02d".format(month.monthValue)
        val bulletinDate = "$year-$monthNumber-01"
        val source = "$BASE/$bulletinDate"

        val html = fetch(source) ?: return emptyList()
        val records = mutableListOf<BulletinCveRecord>()

        val patchPattern = Regex(
            """(?is)<h2\b[^>]*>(.*?)</h2>"""
        )
        val headingMatches = patchPattern.findAll(html).toList()

        for ((index, heading) in headingMatches.withIndex()) {
            val headingText = heading.groupValues[1]
                .replace(Regex("<[^>]+>"), " ")
                .replace("&nbsp;", " ")
                .replace("&amp;", "&")
                .replace(Regex("\\s+"), " ")
                .trim()

            val patchMatch = patchHeaderRegex.find(headingText)
                ?: continue

            val patchLevel = patchMatch.groupValues[1]
            val patchDate = try {
                LocalDate.parse(patchLevel)
            } catch (_: Exception) {
                continue
            }

            if (!patchDate.isAfter(installedPatch)) continue

            val sectionEnd = headingMatches
                .getOrNull(index + 1)
                ?.range
                ?.first
                ?: html.length

            val section = html.substring(
                heading.range.last + 1,
                sectionEnd
            )

            var component = "Unspecified component"

            val blockPattern = Regex(
                """(?is)<h3\b[^>]*>(.*?)</h3>|<tr\b[^>]*>(.*?)</tr>"""
            )

            for (block in blockPattern.findAll(section)) {
                val componentHtml = block.groupValues[1]
                val rowHtml = block.groupValues[2]

                if (componentHtml.isNotBlank()) {
                    component = componentHtml
                        .replace(Regex("<[^>]+>"), " ")
                        .replace("&nbsp;", " ")
                        .replace("&amp;", "&")
                        .replace(Regex("\\s+"), " ")
                        .trim()
                    continue
                }

                if (rowHtml.isBlank()) continue

                val cells = Regex(
                    """(?is)<t[dh]\b[^>]*>(.*?)</t[dh]>"""
                ).findAll(rowHtml)
                    .map { cell ->
                        cell.groupValues[1]
                            .replace(Regex("<[^>]+>"), " ")
                            .replace("&nbsp;", " ")
                            .replace("&amp;", "&")
                            .replace("&lt;", "<")
                            .replace("&gt;", ">")
                            .replace("&quot;", "\"")
                            .replace("&#39;", "'")
                            .replace(Regex("\\s+"), " ")
                            .trim()
                    }
                    .toList()

                if (cells.size < 5) continue

                val cve = cells[0].uppercase()
                if (!Regex("""^CVE-\d{4}-\d{4,}$""").matches(cve)) {
                    continue
                }

                val type = cells[2]
                val severity = cells[3]
                val versions = cells[4]

                val validType = type in listOf("RCE", "EoP", "ID", "DoS")
                val validSeverity = severity in
                    listOf("Critical", "High", "Medium", "Low")

                val androidVersionListed = Regex(
                    """(?<!\d)$androidMajor(?!\d)"""
                ).containsMatchIn(versions)

                val status = when {
                    !validType || !validSeverity || versions.isBlank() ->
                        "APPLICABILITY_UNKNOWN"

                    androidVersionListed ->
                        "POTENTIALLY_RELEVANT"

                    else ->
                        "ANDROID_VERSION_NOT_LISTED"
                }

                records.add(
                    BulletinCveRecord(
                        cve = cve,
                        patchLevel = patchLevel,
                        component = component,
                        vulnerabilityType = if (validType) type else "Not stated",
                        severity = if (validSeverity) severity else "Not stated",
                        affectedVersions = versions,
                        status = status,
                        source = source
                    )
                )
            }
        }

        return records
    }

    fun scan(
        installedPatch: String,
        androidMajor: Int
    ): BulletinIntelligenceResult {

        val patchDate = try {
            LocalDate.parse(installedPatch.take(10))
        } catch (_: Exception) {
            return BulletinIntelligenceResult(
                report = """
ANDROID BULLETIN INTELLIGENCE
Status: NOT RUN
Reason: Invalid Android security patch date.
""".trimIndent(),
                records = emptyList(),
                bulletinsChecked = 0,
                successfulBulletins = 0
            )
        }

        val months = monthList(
            patchDate,
            LocalDate.now()
        )

        val executor = Executors.newFixedThreadPool(4)

        val futures = months.map { month ->
            executor.submit(
                Callable {
                    parseBulletin(
                        month,
                        patchDate,
                        androidMajor
                    )
                }
            )
        }

        val allRecords = mutableListOf<BulletinCveRecord>()
        var successful = 0

        try {
            futures.forEach { future ->
                try {
                    val result = future.get(45, TimeUnit.SECONDS)
                    if (result.isNotEmpty()) {
                        successful++
                        allRecords.addAll(result)
                    }
                } catch (_: Exception) {
                    future.cancel(true)
                }
            }
        } finally {
            executor.shutdownNow()
        }

        val uniqueRecords = allRecords
            .distinctBy { "${it.cve}:${it.patchLevel}" }
            .sortedWith(
                compareByDescending<BulletinCveRecord> {
                    when (it.severity) {
                        "Critical" -> 4
                        "High" -> 3
                        "Medium" -> 2
                        "Low" -> 1
                        else -> 0
                    }
                }.thenBy { it.cve }
            )

        val potentiallyRelevant = uniqueRecords.count {
            it.status == "POTENTIALLY_RELEVANT"
        }

        val unknown = uniqueRecords.count {
            it.status == "APPLICABILITY_UNKNOWN"
        }

        val notListed = uniqueRecords.count {
            it.status == "ANDROID_VERSION_NOT_LISTED"
        }

        val report = buildString {
            appendLine("ANDROID BULLETIN INTELLIGENCE")
            appendLine("============================")
            appendLine("Installed patch: $installedPatch")
            appendLine("Android major version: $androidMajor")
            appendLine("Bulletin months checked: ${months.size}")
            appendLine("Bulletins with parsed CVEs: $successful")
            appendLine("Unique CVE entries: ${uniqueRecords.size}")
            appendLine()
            appendLine("POTENTIALLY RELEVANT: $potentiallyRelevant")
            appendLine("APPLICABILITY UNKNOWN: $unknown")
            appendLine("ANDROID VERSION NOT LISTED: $notListed")
            appendLine()
            appendLine("CVE RESULTS")
            appendLine("-----------")

            if (uniqueRecords.isEmpty()) {
                appendLine(
                    "No CVE records were parsed. " +
                    "This does not mean the device has no vulnerabilities."
                )
            }

            uniqueRecords.take(40).forEachIndexed { index, item ->
                appendLine()
                appendLine("${index + 1}. ${item.cve}")
                appendLine("Patch level: ${item.patchLevel}")
                appendLine("Component: ${item.component}")
                appendLine("Type: ${item.vulnerabilityType}")
                appendLine("Severity: ${item.severity}")
                appendLine("AOSP versions: ${item.affectedVersions}")
                appendLine("Assessment: ${item.status}")
                appendLine("Source: ${item.source}")
            }

            if (uniqueRecords.size > 40) {
                appendLine()
                appendLine(
                    "Additional entries omitted: ${uniqueRecords.size - 40}"
                )
            }

            appendLine()
            appendLine("ASSESSMENT LIMITATIONS")
            appendLine("----------------------")
            appendLine(
                "AOSP version matching does not prove that an OEM firmware is vulnerable."
            )
            appendLine(
                "A missing patch level does not prove that a vendor patch was not backported."
            )
            appendLine(
                "MediaTek and TECNO-specific bulletins require separate verification."
            )
            appendLine(
                "No exploit or device modification was performed."
            )
            appendLine(
                "Potentially relevant means patch and version indicators match; " +
                "it is not a confirmed vulnerability."
            )
        }

        return BulletinIntelligenceResult(
            report = report,
            records = uniqueRecords,
            bulletinsChecked = months.size,
            successfulBulletins = successful
        )
    }
}
