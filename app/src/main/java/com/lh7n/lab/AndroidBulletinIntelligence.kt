package com.lh7n.lab

import java.net.HttpURLConnection
import java.net.URL
import java.time.LocalDate
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.Locale

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

    private val patchHeaderRegex = Regex(
        """(20\d{2}-\d{2}-0[15])\s+security patch level vulnerability details""",
        RegexOption.IGNORE_CASE
    )

    private data class FetchResult(
        val html: String?,
        val status: String
    )

    private data class MonthResult(
        val records: List<BulletinCveRecord>,
        val fetchStatus: String,
        val headings: Int,
        val patchSections: Int
    )

    private fun fetch(url: String): FetchResult {
        var connection: HttpURLConnection? = null

        return try {
            connection = URL(url).openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 10000
            connection.readTimeout = 12000
            connection.instanceFollowRedirects = true

            connection.setRequestProperty(
                "User-Agent",
                "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36"
            )
            connection.setRequestProperty("Accept", "text/html")
            connection.setRequestProperty("Accept-Encoding", "identity")

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
                "NETWORK_ERROR: ${e.javaClass.simpleName}: ${e.message ?: "unknown"}"
            )
        } finally {
            connection?.disconnect()
        }
    }

    private fun clean(value: String): String {
        return value
            .replace(Regex("(?is)<script\\b.*?</script>"), " ")
            .replace(Regex("(?is)<style\\b.*?</style>"), " ")
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

    private fun parseBulletin(
        month: LocalDate,
        installedPatch: LocalDate,
        androidMajor: Int
    ): MonthResult {

        val date = "%04d-%02d-01".format(
            Locale.ROOT,
            month.year,
            month.monthValue
        )

        val source = if (month.year >= 2026) {
            "$BASE/${month.year}/$date"
        } else {
            "$BASE/$date"
        }

        val downloaded = fetch(source)
        val html = downloaded.html
            ?: return MonthResult(emptyList(), downloaded.status, 0, 0)

        val headings = Regex(
            """(?is)<h2\b[^>]*>(.*?)</h2>"""
        ).findAll(html).toList()

        if (headings.isEmpty()) {
            return MonthResult(emptyList(), "HTTP_200_NO_H2_HEADINGS", 0, 0)
        }

        val records = mutableListOf<BulletinCveRecord>()
        var patchSections = 0

        for ((index, heading) in headings.withIndex()) {
            val headingText = clean(heading.groupValues[1])
            val patchMatch = patchHeaderRegex.find(headingText) ?: continue
            val patchLevel = patchMatch.groupValues[1]

            val patchDate = try {
                LocalDate.parse(patchLevel)
            } catch (_: Exception) {
                continue
            }

            if (!patchDate.isAfter(installedPatch)) continue
            patchSections++

            val sectionEnd = headings.getOrNull(index + 1)
                ?.range?.first ?: html.length

            val section = html.substring(heading.range.last + 1, sectionEnd)
            var component = "Unspecified component"

            val blocks = Regex(
                """(?is)<h3\b[^>]*>(.*?)</h3>|<table\b[^>]*>(.*?)</table>"""
            )

            for (block in blocks.findAll(section)) {
                val componentHtml = block.groupValues[1]
                val tableHtml = block.groupValues[2]

                if (componentHtml.isNotBlank()) {
                    component = clean(componentHtml)
                    continue
                }

                if (tableHtml.isBlank()) continue

                val rows = Regex(
                    """(?is)<tr\b[^>]*>(.*?)</tr>"""
                ).findAll(tableHtml).map {
                    it.groupValues[1]
                }.toList()

                if (rows.size < 2) continue

                fun cellsFrom(rowHtml: String): List<String> {
                    return Regex(
                        """(?is)<t[dh]\b[^>]*>(.*?)</t[dh]>"""
                    ).findAll(rowHtml).map {
                        clean(it.groupValues[1])
                    }.toList()
                }

                val headers = cellsFrom(rows.first()).map {
                    it.lowercase(Locale.ROOT)
                        .replace(Regex("[^a-z0-9]+"), " ")
                        .trim()
                }

                val cveColumn = headers.indexOfFirst {
                    it == "cve" || it.startsWith("cve ")
                }
                val typeColumn = headers.indexOfFirst { it == "type" }
                val severityColumn = headers.indexOfFirst { it == "severity" }
                val aospVersionsColumn = headers.indexOfFirst {
                    it.contains("aosp") && it.contains("version")
                }
                val subcomponentColumn = headers.indexOfFirst {
                    it == "subcomponent"
                }

                if (cveColumn < 0 || severityColumn < 0) continue

                for (rowHtml in rows.drop(1)) {
                    val cells = cellsFrom(rowHtml)
                    val cve = cells.getOrNull(cveColumn)
                        ?.uppercase(Locale.ROOT)
                        .orEmpty()

                    if (!Regex("""^CVE-\d{4}-\d{4,}$""").matches(cve)) {
                        continue
                    }

                    val type = cells.getOrNull(typeColumn)
                        ?.takeIf { it.isNotBlank() }
                        ?: "Not stated by source"

                    val severity = cells.getOrNull(severityColumn)
                        ?.takeIf { it.isNotBlank() }
                        ?: "Not stated"

                    val aospVersions = cells.getOrNull(aospVersionsColumn)
                        ?.takeIf { it.isNotBlank() }

                    val vendorSubcomponent = cells.getOrNull(subcomponentColumn)
                        ?.takeIf { it.isNotBlank() }

                    val androidVersionListed = aospVersions
                        ?.split(Regex("[,;\\s]+"))
                        ?.any { token ->
                            token.trim().matches(
                                Regex(
                                    """${androidMajor}(?:-qpr\d+)?""",
                                    RegexOption.IGNORE_CASE
                                )
                            )
                        } == true

                    val status = when {
                        aospVersions == null -> "APPLICABILITY_UNKNOWN"
                        androidVersionListed -> "POTENTIALLY_RELEVANT"
                        else -> "ANDROID_VERSION_NOT_LISTED"
                    }

                    val affectedVersions = when {
                        aospVersions != null -> aospVersions
                        vendorSubcomponent != null ->
                            "Vendor subcomponent: $vendorSubcomponent"
                        else -> "Not provided by source"
                    }

                    records.add(
                        BulletinCveRecord(
                            cve = cve,
                            patchLevel = patchLevel,
                            component = component,
                            vulnerabilityType = type,
                            severity = severity,
                            affectedVersions = affectedVersions,
                            status = status,
                            source = source
                        )
                    )
                }
            }
        }

        val status = when {
            patchSections == 0 -> "HTTP_200_NO_PATCH_SECTIONS"
            records.isEmpty() -> "HTTP_200_NO_CVE_ROWS"
            else -> "HTTP_200_PARSED"
        }

        return MonthResult(records, status, headings.size, patchSections)
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

        val months = monthList(patchDate, LocalDate.now())
        val executor = Executors.newFixedThreadPool(4)

        val futures = months.map { month ->
            month to executor.submit(
                Callable {
                    parseBulletin(month, patchDate, androidMajor)
                }
            )
        }

        val allRecords = mutableListOf<BulletinCveRecord>()
        val diagnostics = mutableListOf<String>()

        var httpSuccess = 0
        var parsedBulletins = 0
        var patchSections = 0
        var headingCount = 0
        var failures = 0

        try {
            for ((month, future) in futures) {
                val result = try {
                    future.get(45, TimeUnit.SECONDS)
                } catch (e: Exception) {
                    future.cancel(true)
                    failures++

                    diagnostics.add(
                        "%04d-%02d: TIMEOUT_OR_TASK_ERROR (%s)".format(
                            Locale.ROOT,
                            month.year,
                            month.monthValue,
                            e.javaClass.simpleName
                        )
                    )
                    continue
                }

                if (result.fetchStatus.startsWith("HTTP_200")) {
                    httpSuccess++
                }

                if (result.fetchStatus == "HTTP_200_PARSED") {
                    parsedBulletins++
                }

                patchSections += result.patchSections
                headingCount += result.headings
                allRecords.addAll(result.records)

                if (result.fetchStatus != "HTTP_200_PARSED") {
                    diagnostics.add(
                        "%04d-%02d: %s".format(
                            Locale.ROOT,
                            month.year,
                            month.monthValue,
                            result.fetchStatus
                        )
                    )
                }
            }
        } finally {
            executor.shutdownNow()
        }

        val uniqueRecords = allRecords
            .distinctBy { "${it.cve}:${it.patchLevel}" }
            .sortedWith(
                compareByDescending<BulletinCveRecord> {
                    when (it.severity.lowercase()) {
                        "critical" -> 4
                        "high" -> 3
                        "medium" -> 2
                        "low" -> 1
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
            appendLine("HTTP successful pages: $httpSuccess")
            appendLine("Bulletins with parsed CVEs: $parsedBulletins")
            appendLine("Patch sections detected: $patchSections")
            appendLine("HTML headings detected: $headingCount")
            appendLine("Unique CVE entries: ${uniqueRecords.size}")
            appendLine("Network/task failures: $failures")
            appendLine()

            appendLine("POTENTIALLY RELEVANT: $potentiallyRelevant")
            appendLine("APPLICABILITY UNKNOWN: $unknown")
            appendLine("ANDROID VERSION NOT LISTED: $notListed")
            appendLine(
                "VENDOR COMPONENTS (APPLICABILITY UNKNOWN): " +
                    uniqueRecords.count {
                        it.affectedVersions.startsWith("Vendor subcomponent:")
                    }
            )
            appendLine()

            appendLine("FETCH AND PARSER DIAGNOSTICS")
            appendLine("----------------------------")

            if (diagnostics.isEmpty()) {
                appendLine("No fetch or parser failures reported.")
            } else {
                diagnostics.take(12).forEach {
                    appendLine(it)
                }

                if (diagnostics.size > 12) {
                    appendLine("Additional diagnostic entries: ${diagnostics.size - 12}")
                }
            }

            appendLine()
            appendLine("CVE RESULTS")
            appendLine("-----------")

            if (uniqueRecords.isEmpty()) {
                appendLine(
                    "No CVE records were parsed. " +
                    "This is not evidence that the device has no vulnerabilities."
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
                "Potentially relevant is not a confirmed vulnerability."
            )
        }

        return BulletinIntelligenceResult(
            report = report,
            records = uniqueRecords,
            bulletinsChecked = months.size,
            successfulBulletins = parsedBulletins
        )
    }
}
