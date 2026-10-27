package br.com.guardiaomobile.memory

import android.app.ActivityManager
import android.content.Context

data class SystemRamSnapshot(
    val totalBytes: Long,
    val availableBytes: Long,
    val usedBytes: Long,
    val usagePercentage: Int,
    val isLowMemory: Boolean,
    val thresholdBytes: Long,
    val appHeapUsedBytes: Long,
    val timestampEpochMillis: Long,
    val educationalNote: String = "O Android gerencia a memória RAM automaticamente. " +
        "Encerrar aplicativos à força pode aumentar o consumo de bateria e tornar a reabertura mais lenta."
)

class RamDiagnosticsProvider(private val context: Context) {

    fun captureSnapshot(): SystemRamSnapshot {
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memoryInfo = ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(memoryInfo)

        val total = memoryInfo.totalMem.coerceAtLeast(1L)
        val avail = memoryInfo.availMem.coerceAtLeast(0L)
        val used = (total - avail).coerceAtLeast(0L)
        val percent = ((used.toDouble() / total.toDouble()) * 100.0).toInt().coerceIn(0, 100)

        val runtime = Runtime.getRuntime()
        val appUsed = runtime.totalMemory() - runtime.freeMemory()

        return SystemRamSnapshot(
            totalBytes = total,
            availableBytes = avail,
            usedBytes = used,
            usagePercentage = percent,
            isLowMemory = memoryInfo.lowMemory,
            thresholdBytes = memoryInfo.threshold,
            appHeapUsedBytes = appUsed,
            timestampEpochMillis = System.currentTimeMillis()
        )
    }
}