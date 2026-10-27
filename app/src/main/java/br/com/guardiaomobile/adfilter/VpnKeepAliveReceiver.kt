package br.com.guardiaomobile.adfilter

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

class VpnBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action == Intent.ACTION_BOOT_COMPLETED ||
            action == Intent.ACTION_MY_PACKAGE_REPLACED ||
            action == "br.com.guardiaomobile.RESTART_VPN"
        ) {
            val prefs = context.getSharedPreferences("guardiao_prefs", Context.MODE_PRIVATE)
            val shouldBeActive = prefs.getBoolean(LocalAdBlockerVpnService.PREF_VPN_ENABLED, false)
            if (shouldBeActive && VpnService.prepare(context) == null) {
                LocalAdBlockerVpnService.startServiceCompat(context)
                VpnWatchdogWorker.schedule(context)
            }
        }
    }
}

class VpnWatchdogWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : Worker(appContext, workerParams) {

    override fun doWork(): Result {
        val prefs = applicationContext.getSharedPreferences("guardiao_prefs", Context.MODE_PRIVATE)
        val shouldBeActive = prefs.getBoolean(LocalAdBlockerVpnService.PREF_VPN_ENABLED, false)
        if (shouldBeActive && !LocalAdBlockerVpnService.isRunning.value) {
            if (VpnService.prepare(applicationContext) == null) {
                LocalAdBlockerVpnService.startServiceCompat(applicationContext)
            }
        }
        return Result.success()
    }

    companion object {
        private const val WORK_NAME = "guardiao_vpn_watchdog_24h"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<VpnWatchdogWorker>(15, TimeUnit.MINUTES)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        }
    }
}