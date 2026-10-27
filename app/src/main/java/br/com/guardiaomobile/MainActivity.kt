package br.com.guardiaomobile

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.OpenableColumns
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.core.content.ContextCompat
import androidx.documentfile.provider.DocumentFile
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import br.com.guardiaomobile.adfilter.LocalAdBlockerVpnService
import br.com.guardiaomobile.adfilter.VpnWatchdogWorker
import br.com.guardiaomobile.memory.RamDiagnosticsProvider
import br.com.guardiaomobile.ui.GuardiaoRootScreen
import br.com.guardiaomobile.ui.GuardiaoViewModel

class MainActivity : ComponentActivity() {

    private val viewModel: GuardiaoViewModel by lazy {
        ViewModelProvider(
            this,
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    val prefs = applicationContext.getSharedPreferences("guardiao_prefs", Context.MODE_PRIVATE)
                    return GuardiaoViewModel(
                        context = applicationContext,
                        ramProvider = RamDiagnosticsProvider(applicationContext),
                        preferences = prefs
                    ) as T
                }
            }
        )[GuardiaoViewModel::class.java]
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermissionIfNeeded()
        ensureVpn24hRunningIfEnabled()
        checkAndHandleShareIntent(intent)

        setContent {
            MaterialTheme {
                Surface {
                    val uiState by viewModel.uiState.collectAsState()

                    val vpnLauncher = rememberLauncherForActivityResult(
                        contract = ActivityResultContracts.StartActivityForResult()
                    ) { result ->
                        if (result.resultCode == Activity.RESULT_OK) {
                            requestIgnoreBatteryOptimizationsIfNeeded()
                            LocalAdBlockerVpnService.startServiceCompat(this, uiState.selectedVpnCountry)
                            VpnWatchdogWorker.schedule(this)
                            viewModel.setVpnActive(true)
                        } else {
                            viewModel.setVpnActive(false)
                        }
                    }

                    val pickFileToVerifyLauncher = rememberLauncherForActivityResult(
                        contract = ActivityResultContracts.OpenDocument()
                    ) { fileUri: Uri? ->
                        if (fileUri != null) {
                            val name = resolveDisplayName(fileUri)
                            viewModel.analyzeSelectedFile(contentResolver, fileUri, name)
                        }
                    }

                    GuardiaoRootScreen(
                        uiState = uiState,
                        onNavigate = viewModel::navigateTo,
                        onUrlChange = viewModel::onUrlInputChange,
                        onSelectCategory = viewModel::onSelectMediaCategory,
                        onConfirmShareCategory = { category ->
                            viewModel.confirmShareFormatAndStart(category)
                            Toast.makeText(
                                this,
                                "Download iniciado na subpasta de ${category.displayName}!",
                                Toast.LENGTH_SHORT
                            ).show()
                        },
                        onDismissShareDialog = viewModel::dismissShareFormatDialog,
                        onToggleAutoDownloadOnShare = viewModel::onToggleAutoDownloadOnShare,
                        onToggleVpn = { enable ->
                            if (enable) {
                                val prepareIntent = VpnService.prepare(this)
                                if (prepareIntent != null) {
                                    vpnLauncher.launch(prepareIntent)
                                } else {
                                    requestIgnoreBatteryOptimizationsIfNeeded()
                                    LocalAdBlockerVpnService.startServiceCompat(this, uiState.selectedVpnCountry)
                                    VpnWatchdogWorker.schedule(this)
                                    viewModel.setVpnActive(true)
                                }
                            } else {
                                startService(
                                    Intent(this, LocalAdBlockerVpnService::class.java).apply {
                                        action = LocalAdBlockerVpnService.ACTION_STOP
                                    }
                                )
                                viewModel.setVpnActive(false)
                            }
                        },
                        onSelectVpnCountry = { country ->
                            viewModel.selectVpnCountry(country)
                            Toast.makeText(
                                this,
                                "Região VPN alterada para ${country.displayName} (${country.simulatedPublicIp})",
                                Toast.LENGTH_SHORT
                            ).show()
                        },
                        onStartAutomaticDownload = {
                            val started = viewModel.startAutomaticMediaDownload()
                            if (started) {
                                Toast.makeText(
                                    this,
                                    "Salvando automaticamente em Download/GuardiaoMobile...",
                                    Toast.LENGTH_SHORT
                                ).show()
                            }
                        },
                        onCancelDownload = viewModel::cancelDownload,
                        onPickFileToVerify = {
                            pickFileToVerifyLauncher.launch(arrayOf("*/*"))
                        },
                        onRunFullAntivirusScan = viewModel::runFullDeviceAntivirusScan,
                        onInspectSpecificPackage = { pkgName ->
                            openAppDetailsScreen(pkgName)
                        },
                        onUninstallSpecificPackage = { pkgName ->
                            uninstallPackage(pkgName)
                        },
                        onKillBackgroundPackage = { pkgName ->
                            viewModel.killBackgroundAppProcesses(pkgName)
                            Toast.makeText(
                                this,
                                "Processos em 2º plano de $pkgName encerrados.",
                                Toast.LENGTH_SHORT
                            ).show()
                        },
                        onDeleteSuspiciousDownload = { filePath ->
                            viewModel.deleteSuspiciousDownloadPath(filePath)
                            Toast.makeText(
                                this,
                                "Arquivo suspeito removido dos Downloads.",
                                Toast.LENGTH_SHORT
                            ).show()
                        },
                        onClearNetworkAlerts = viewModel::clearNetworkAlerts,
                        onExtractAudioFromVideo = {
                            viewModel.extractAudioFromAnalyzedVideo(contentResolver) { _, msg ->
                                Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
                            }
                        },
                        onConfirmDeleteSelectedFile = {
                            val targetUri = uiState.selectedFileUri
                            if (targetUri != null) {
                                val doc = DocumentFile.fromSingleUri(this, targetUri)
                                viewModel.deleteAnalyzedFile(doc) { deleted ->
                                    val msg = if (deleted) {
                                        "Arquivo removido com sucesso."
                                    } else {
                                        "O provedor de armazenamento não permitiu a exclusão direta."
                                    }
                                    Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
                                }
                            }
                        },
                        onRefreshRam = viewModel::refreshRamMetrics,
                        onOpenManageAppsSettings = {
                            openSystemIntent(Settings.ACTION_MANAGE_ALL_APPLICATIONS_SETTINGS)
                        },
                        onOpenBatteryUsageSettings = {
                            openSystemIntent(Intent.ACTION_POWER_USAGE_SUMMARY)
                        },
                        onOpenOwnAppDetails = {
                            openAppDetailsScreen(packageName)
                        },
                        onOpenWirelessSettings = {
                            openSystemIntent(Settings.ACTION_WIRELESS_SETTINGS)
                        }
                    )
                }
            }
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
                PackageManager.PERMISSION_GRANTED
            ) {
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2001)
            }
        }
    }

    private fun openAppDetailsScreen(targetPackage: String) {
        try {
            startActivity(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                    data = Uri.fromParts("package", targetPackage, null)
                }
            )
        } catch (e: Exception) {
            openSystemIntent(Settings.ACTION_MANAGE_ALL_APPLICATIONS_SETTINGS)
        }
    }

    private fun uninstallPackage(targetPackage: String) {
        try {
            val intent = Intent(Intent.ACTION_DELETE).apply {
                data = Uri.parse("package:$targetPackage")
            }
            startActivity(intent)
        } catch (e: Exception) {
            openAppDetailsScreen(targetPackage)
        }
    }

    private fun ensureVpn24hRunningIfEnabled() {
        val prefs = getSharedPreferences("guardiao_prefs", Context.MODE_PRIVATE)
        val shouldBeActive = prefs.getBoolean(LocalAdBlockerVpnService.PREF_VPN_ENABLED, false)
        if (shouldBeActive && !LocalAdBlockerVpnService.isRunning.value) {
            if (VpnService.prepare(this) == null) {
                LocalAdBlockerVpnService.startServiceCompat(this)
                VpnWatchdogWorker.schedule(this)
            }
        }
    }

    private fun requestIgnoreBatteryOptimizationsIfNeeded() {
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
                startActivity(intent)
            }
        } catch (e: Exception) {
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        checkAndHandleShareIntent(intent)
    }

    private fun checkAndHandleShareIntent(incomingIntent: Intent?) {
        if (incomingIntent?.action == Intent.ACTION_SEND && incomingIntent.type == "text/plain") {
            val sharedText = incomingIntent.getStringExtra(Intent.EXTRA_TEXT)
            if (!sharedText.isNullOrBlank()) {
                incomingIntent.removeExtra(Intent.EXTRA_TEXT)
                viewModel.handleIncomingSharedText(sharedText)
            }
        }
    }

    private fun openSystemIntent(action: String) {
        try {
            startActivity(Intent(action))
        } catch (e: Exception) {
            startActivity(Intent(Settings.ACTION_SETTINGS))
        }
    }

    private fun resolveDisplayName(uri: Uri): String {
        var displayName = "arquivo_selecionado"
        val cursor: Cursor? = contentResolver.query(uri, null, null, null, null)
        cursor?.use {
            if (it.moveToFirst()) {
                val index = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (index >= 0) {
                    displayName = it.getString(index) ?: displayName
                }
            }
        }
        return displayName
    }
}