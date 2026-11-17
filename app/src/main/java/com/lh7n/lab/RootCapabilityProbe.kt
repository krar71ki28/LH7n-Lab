package com.lh7n.lab

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

data class RootProbeResult(
    val status: String,
    val output: String,
    val exitCode: Int?,
    val timestamp: String
) {
    fun toReport(): String = """
        LH7n LAB — ROOT CAPABILITY DIAGNOSTICS
        =====================================
        Date: $timestamp

        Status: $status
        Exit Code: ${exitCode ?: "N/A"}

        Command: su -c id

        Output:
        ${output.ifBlank { "No output" }}

        Interpretation:
        ${when (status) {
            "ROOT_CONFIRMED" -> "UID 0 confirmed for this app process."
            "SU_NOT_AVAILABLE" -> "The su executable could not be started."
            "REQUEST_DENIED_OR_FAILED" -> "The request failed or was denied."
            "TIMEOUT" -> "The request exceeded the time limit."
            else -> "Root status could not be determined."
        }}

        System modifications: NONE
    """.trimIndent()
}

object RootCapabilityProbe {

    private fun timestamp(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())

    fun run(): RootProbeResult {
        val now = timestamp()

        val process = try {
            ProcessBuilder("su", "-c", "id")
                .redirectErrorStream(true)
                .start()
        } catch (e: Exception) {
            return RootProbeResult(
                "SU_NOT_AVAILABLE",
                e.message ?: "Cannot start su",
                null,
                now
            )
        }

        return try {
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                return RootProbeResult("TIMEOUT", "Process timed out", null, now)
            }

            val output = process.inputStream.bufferedReader()
                .use { it.readText().trim() }

            val code = process.exitValue()
            val uidZero = Regex("""(?:^|\s)uid=0(?:\(|\s|,)""")
                .containsMatchIn(output)

            val status = when {
                code == 0 && uidZero -> "ROOT_CONFIRMED"
                code == 0 -> "ROOT_NOT_CONFIRMED"
                else -> "REQUEST_DENIED_OR_FAILED"
            }

            RootProbeResult(status, output, code, now)
        } catch (e: Exception) {
            process.destroyForcibly()
            RootProbeResult(
                "PROBE_ERROR",
                e.message ?: "Unknown error",
                null,
                now
            )
        }
    }
}
