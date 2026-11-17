package com.lh7n.lab

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

object RootCapabilityProbe {

    fun run(): String {
        val date = SimpleDateFormat(
            "yyyy-MM-dd HH:mm:ss",
            Locale.US
        ).format(Date())

        val process = try {
            ProcessBuilder("su", "-c", "id")
                .redirectErrorStream(true)
                .start()
        } catch (e: Exception) {
            return """
                LH7n LAB — ROOT CAPABILITY TEST
                ==============================
                Date: $date

                Result: SU_NOT_AVAILABLE
                Details: ${e.message ?: "Cannot start su"}

                Root privilege: NOT CONFIRMED
                System changes: NONE
            """.trimIndent()
        }

        return try {
            val finished = process.waitFor(10, TimeUnit.SECONDS)

            if (!finished) {
                process.destroyForcibly()
                return """
                    LH7n LAB — ROOT CAPABILITY TEST
                    ==============================
                    Date: $date

                    Result: TIMEOUT
                    Root privilege: UNKNOWN
                    System changes: NONE
                """.trimIndent()
            }

            val output = process.inputStream
                .bufferedReader()
                .use { it.readText().trim() }

            val exitCode = process.exitValue()
            val hasRootUid = Regex(
                """(?:^|\s)uid=0(?:\(|\s|,)"""
            ).containsMatchIn(output)

            val result = when {
                exitCode == 0 && hasRootUid -> "ROOT_CONFIRMED"
                exitCode == 0 -> "ROOT_NOT_CONFIRMED"
                else -> "REQUEST_DENIED_OR_FAILED"
            }

            """
                LH7n LAB — ROOT CAPABILITY TEST
                ==============================
                Date: $date

                Result: $result
                Exit Code: $exitCode

                Command: su -c id
                Output:
                ${output.ifBlank { "No output" }}

                Root UID 0: ${if (hasRootUid) "CONFIRMED" else "NOT CONFIRMED"}
                System changes: NONE
                Files modified: NONE
            """.trimIndent()

        } catch (e: Exception) {
            process.destroyForcibly()
            "Root test failed: ${e.message ?: "Unknown error"}"
        }
    }
}
