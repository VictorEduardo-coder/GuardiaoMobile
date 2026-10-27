package br.com.guardiaomobile.security

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import java.io.File

enum class ThreatSeverity {
    SEGURO,
    ATENCAO,
    ALTO_RISCO,
    CRITICO
}

data class SuspiciousAppFinding(
    val appName: String,
    val packageName: String,
    val isSystemApp: Boolean,
    val originTypeLabel: String,
    val severity: ThreatSeverity,
    val reasons: List<String>,
    val isSideloaded: Boolean,
    val dangerousPermissionsCount: Int
)

data class DownloadedFileFinding(
    val fileName: String,
    val absolutePath: String,
    val sizeBytes: Long,
    val status: SecurityStatus,
    val details: String
)

data class BackgroundRamAppItem(
    val appName: String,
    val packageName: String,
    val isSystemApp: Boolean,
    val originTypeLabel: String,
    val activeServicesCount: Int,
    val estimatedRamMb: Int,
    val runsAtBoot: Boolean,
    val recommendation: String
)

data class FullAntivirusScanReport(
    val scannedAppsCount: Int,
    val systemAppsCount: Int = 0,
    val userAppsCount: Int = 0,
    val scannedDownloadsCount: Int,
    val suspiciousApps: List<SuspiciousAppFinding>,
    val suspiciousDownloads: List<DownloadedFileFinding>,
    val heavyBackgroundApps: List<BackgroundRamAppItem>,
    val timestampMillis: Long
)

class DeviceAntivirusScanner(
    private val context: Context,
    private val fileAnalyzer: FileSecurityAnalyzer = FileSecurityAnalyzer()
) {

    private val highRiskPermissions = setOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.READ_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
    )

    private val trustedInstallers = setOf(
        "com.android.vending",
        "com.google.android.feedback",
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.sec.android.app.samsungapps",
        "com.samsung.android.mateagent",
        "com.xiaomi.mipicks",
        "com.xiaomi.discover",
        "com.miui.packageinstaller"
    )

    private val coreProtectedSystemPackages = setOf(
        "android",
        "com.android.systemui",
        "com.android.settings",
        "com.android.phone",
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.sec.android.emergencymode.service",
        "com.miui.securitycenter"
    )

    fun isGenuineSystemApplication(appInfo: ApplicationInfo): Boolean {
        val hasSystemFlag = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val hasUpdatedSystemFlag = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        val sourceDir = appInfo.sourceDir ?: ""
        val isInSystemPartition = sourceDir.startsWith("/system/") ||
            sourceDir.startsWith("/product/") ||
            sourceDir.startsWith("/vendor/") ||
            sourceDir.startsWith("/system_ext/") ||
            sourceDir.startsWith("/apex/") ||
            sourceDir.startsWith("/oem/")
        return hasSystemFlag || hasUpdatedSystemFlag || isInSystemPartition
    }

    private fun resolveAppOriginLabel(
        isSystemApp: Boolean,
        isUpdatedSystemApp: Boolean,
        isSideloaded: Boolean
    ): String {
        return when {
            isSystemApp && isUpdatedSystemApp -> "App do Sistema (Atualizado)"
            isSystemApp -> "App Oficial do Sistema"
            isSideloaded -> "App de Usuário (APK Externo)"
            else -> "App de Usuário (Loja Oficial)"
        }
    }

    fun runFullSecurityScan(): FullAntivirusScanReport {
        val pm = context.packageManager
        val installedPackages = getInstalledPackagesCompat(pm)

        val suspiciousApps = mutableListOf<SuspiciousAppFinding>()
        val backgroundRamApps = mutableListOf<BackgroundRamAppItem>()
        var systemCount = 0
        var userCount = 0

        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val runningProcesses = activityManager.runningAppProcesses?.associateBy { it.processName } ?: emptyMap()

        for (pkg in installedPackages) {
            val appInfo = pkg.applicationInfo ?: continue
            if (pkg.packageName == context.packageName) continue

            val isGenuineSystem = isGenuineSystemApplication(appInfo)
            val isUpdatedSystem = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

            if (isGenuineSystem) {
                systemCount++
            } else {
                userCount++
            }

            val appLabel = try {
                pm.getApplicationLabel(appInfo).toString()
            } catch (e: Exception) {
                pkg.packageName
            }

            val requestedPerms = pkg.requestedPermissions?.toSet() ?: emptySet()
            val dangerousFound = requestedPerms.intersect(highRiskPermissions)
            val installer = getInstallerPackageCompat(pm, pkg.packageName)
            val isSideloaded = !isGenuineSystem && (installer == null || installer !in trustedInstallers)
            val originLabel = resolveAppOriginLabel(isGenuineSystem, isUpdatedSystem, isSideloaded)
            val hasLauncherIcon = hasLauncherActivity(pm, pkg.packageName)

            val reasons = mutableListOf<String>()
            var riskPoints = 0

            if (isGenuineSystem) {
                if (isUpdatedSystem && installer != null && installer !in trustedInstallers) {
                    reasons.add("App do sistema atualizado por um instalador externo não reconhecido ($installer)")
                    riskPoints += 2
                }
            } else {
                val impersonatesSystemPackage = pkg.packageName.startsWith("com.android.") ||
                    pkg.packageName.startsWith("com.sec.android.") ||
                    pkg.packageName.startsWith("com.miui.") ||
                    pkg.packageName.startsWith("android.system")

                val impersonatesSystemName = appLabel.equals("Sistema Android", ignoreCase = true) ||
                    appLabel.equals("Android System", ignoreCase = true) ||
                    appLabel.equals("Atualização do Sistema", ignoreCase = true) ||
                    appLabel.equals("System Update", ignoreCase = true) ||
                    appLabel.equals("Configurações", ignoreCase = true)

                if (impersonatesSystemPackage || (impersonatesSystemName && isSideloaded)) {
                    reasons.add("Falso App do Sistema: tenta se passar pelo sistema Android, mas está instalado na partição de usuário")
                    riskPoints += 5
                }

                if (!hasLauncherIcon) {
                    reasons.add("App de usuário oculto (não possui ícone na gaveta de aplicativos)")
                    riskPoints += 3
                }

                if (isSideloaded) {
                    reasons.add("Instalado manualmente fora da loja oficial (APK externo)")
                    riskPoints += 1
                }

                if ("android.permission.BIND_ACCESSIBILITY_SERVICE" in requestedPerms &&
                    "android.permission.SYSTEM_ALERT_WINDOW" in requestedPerms
                ) {
                    reasons.add("Combinação crítica: Controle de Acessibilidade + Sobreposição de Tela")
                    riskPoints += 3
                }

                if ("android.permission.BIND_DEVICE_ADMIN" in requestedPerms && isSideloaded) {
                    reasons.add("Solicita privilégios de Administrador do Dispositivo sendo um APK externo")
                    riskPoints += 3
                }

                if (("android.permission.READ_SMS" in requestedPerms || "android.permission.RECEIVE_SMS" in requestedPerms) &&
                    isSideloaded
                ) {
                    reasons.add("Acesso a mensagens SMS em aplicativo instalado por fora da loja")
                    riskPoints += 3
                }

                if ("android.permission.REQUEST_INSTALL_PACKAGES" in requestedPerms && isSideloaded) {
                    reasons.add("Permissão para instalar outros APKs silenciosamente")
                    riskPoints += 2
                }

                if ("android.permission.RECORD_AUDIO" in requestedPerms &&
                    "android.permission.CAMERA" in requestedPerms &&
                    "android.permission.RECEIVE_BOOT_COMPLETED" in requestedPerms &&
                    isSideloaded
                ) {
                    reasons.add("Acesso a câmera e microfone com início automático no boot")
                    riskPoints += 2
                }
            }

            if (riskPoints >= 2) {
                val severity = when {
                    riskPoints >= 5 -> ThreatSeverity.CRITICO
                    riskPoints >= 3 -> ThreatSeverity.ALTO_RISCO
                    else -> ThreatSeverity.ATENCAO
                }
                suspiciousApps.add(
                    SuspiciousAppFinding(
                        appName = appLabel,
                        packageName = pkg.packageName,
                        isSystemApp = isGenuineSystem,
                        originTypeLabel = originLabel,
                        severity = severity,
                        reasons = reasons,
                        isSideloaded = isSideloaded,
                        dangerousPermissionsCount = dangerousFound.size
                    )
                )
            }

            if (pkg.packageName in coreProtectedSystemPackages) continue

            val servicesCount = pkg.services?.size ?: 0
            val receiversCount = pkg.receivers?.size ?: 0
            val runsAtBoot = "android.permission.RECEIVE_BOOT_COMPLETED" in requestedPerms
            val isStopped = (appInfo.flags and ApplicationInfo.FLAG_STOPPED) != 0
            val runningProc = runningProcesses[pkg.packageName]

            val shouldIncludeRamAudit = if (isGenuineSystem) {
                !isStopped && (runningProc != null || (isUpdatedSystem && servicesCount >= 8))
            } else {
                !isStopped && (runningProc != null || servicesCount >= 2 || (runsAtBoot && servicesCount > 0))
            }

            if (shouldIncludeRamAudit) {
                val estimatedMb = estimateAppRamConsumptionMb(
                    am = activityManager,
                    pid = runningProc?.pid,
                    servicesCount = servicesCount,
                    receiversCount = receiversCount,
                    runsAtBoot = runsAtBoot
                )
                val thresholdMb = if (isGenuineSystem) 90 else 40
                if (estimatedMb >= thresholdMb) {
                    val rec = if (isGenuineSystem) {
                        "Componente do sistema com $servicesCount serviços ativos. Limpe a RAM apenas se não estiver em uso."
                    } else if (runsAtBoot) {
                        "App de usuário que inicia junto com o celular e mantém $servicesCount serviços em 2º plano."
                    } else {
                        "App de usuário mantendo $servicesCount serviços em 2º plano."
                    }
                    backgroundRamApps.add(
                        BackgroundRamAppItem(
                            appName = appLabel,
                            packageName = pkg.packageName,
                            isSystemApp = isGenuineSystem,
                            originTypeLabel = originLabel,
                            activeServicesCount = servicesCount,
                            estimatedRamMb = estimatedMb,
                            runsAtBoot = runsAtBoot,
                            recommendation = rec
                        )
                    )
                }
            }
        }

        val sortedRamApps = backgroundRamApps.sortedWith(
            compareBy<BackgroundRamAppItem> { it.isSystemApp }.thenByDescending { it.estimatedRamMb }
        ).take(25)

        val downloadScanResult = scanDownloadedFiles(pm)

        return FullAntivirusScanReport(
            scannedAppsCount = installedPackages.size,
            systemAppsCount = systemCount,
            userAppsCount = userCount,
            scannedDownloadsCount = downloadScanResult.first,
            suspiciousApps = suspiciousApps.sortedByDescending { it.severity.ordinal },
            suspiciousDownloads = downloadScanResult.second,
            heavyBackgroundApps = sortedRamApps,
            timestampMillis = System.currentTimeMillis()
        )
    }

    private fun estimateAppRamConsumptionMb(
        am: ActivityManager,
        pid: Int?,
        servicesCount: Int,
        receiversCount: Int,
        runsAtBoot: Boolean
    ): Int {
        if (pid != null && pid > 0) {
            try {
                val memInfo = am.getProcessMemoryInfo(intArrayOf(pid))
                if (memInfo.isNotEmpty() && memInfo[0].totalPss > 0) {
                    return (memInfo[0].totalPss / 1024).coerceAtLeast(35)
                }
            } catch (e: Exception) {
            }
        }
        val base = 30
        val serviceWeight = servicesCount * 10
        val receiverWeight = receiversCount * 3
        val bootBonus = if (runsAtBoot) 20 else 0
        return (base + serviceWeight + receiverWeight + bootBonus).coerceIn(30, 480)
    }

    private fun scanDownloadedFiles(pm: PackageManager): Pair<Int, List<DownloadedFileFinding>> {
        val findings = mutableListOf<DownloadedFileFinding>()
        var totalScanned = 0

        val directoriesToScan = mutableListOf<File>()
        try {
            val publicDownloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            if (publicDownloads != null && publicDownloads.exists()) {
                directoriesToScan.add(publicDownloads)
                File(publicDownloads, "GuardiaoMobile").takeIf { it.exists() }?.let { directoriesToScan.add(it) }
            }
        } catch (e: Exception) {
        }

        context.getExternalFilesDir(null)?.let { extDir ->
            if (extDir.exists()) directoriesToScan.add(extDir)
        }

        val visitedPaths = HashSet<String>()
        val candidateFiles = mutableListOf<File>()

        for (dir in directoriesToScan) {
            dir.walkTopDown().maxDepth(3).forEach { file ->
                if (file.isFile && visitedPaths.add(file.absolutePath)) {
                    candidateFiles.add(file)
                }
            }
        }

        for (file in candidateFiles.take(80)) {
            totalScanned++
            val ext = file.extension.lowercase()

            if (ext == "apk" || ext == "xapk" || ext == "dex" || ext == "sh" || ext == "bin" || ext == "exe" || ext == "bat") {
                val apkDetails = if (ext == "apk") inspectUninstalledApkFile(pm, file) else null
                findings.add(
                    DownloadedFileFinding(
                        fileName = file.name,
                        absolutePath = file.absolutePath,
                        sizeBytes = file.length(),
                        status = SecurityStatus.SUSPEITO,
                        details = apkDetails
                            ?: "Instalador ou executável potencialmente perigoso (.$ext) encontrado na pasta de Downloads."
                    )
                )
                continue
            }

            try {
                file.inputStream().use { stream ->
                    val report = fileAnalyzer.analyzeStream(stream, ext, file.length())
                    if (report.status == SecurityStatus.SUSPEITO || report.status == SecurityStatus.AMEACA_DETECTADA) {
                        findings.add(
                            DownloadedFileFinding(
                                fileName = file.name,
                                absolutePath = file.absolutePath,
                                sizeBytes = file.length(),
                                status = report.status,
                                details = report.explanation
                            )
                        )
                    }
                }
            } catch (e: Exception) {
            }
        }

        return Pair(totalScanned, findings)
    }

    private fun inspectUninstalledApkFile(pm: PackageManager, apkFile: File): String {
        return try {
            val archiveInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageArchiveInfo(
                    apkFile.absolutePath,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageArchiveInfo(apkFile.absolutePath, PackageManager.GET_PERMISSIONS)
            }
            val perms = archiveInfo?.requestedPermissions?.toSet() ?: emptySet()
            val dangerous = perms.intersect(highRiskPermissions)
            if (dangerous.isNotEmpty()) {
                "APK na pasta Downloads solicita ${dangerous.size} permissões críticas (${dangerous.joinToString { it.substringAfterLast('.') }})."
            } else {
                "Arquivo instalador APK (${archiveInfo?.packageName ?: "desconhecido"}) armazenado nos Downloads."
            }
        } catch (e: Exception) {
            "Instalador APK não verificado encontrado nos Downloads."
        }
    }

    private fun getInstalledPackagesCompat(pm: PackageManager): List<PackageInfo> {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(flags)
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun getInstallerPackageCompat(pm: PackageManager, packageName: String): String? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun hasLauncherActivity(pm: PackageManager, packageName: String): Boolean {
        return try {
            val intent = Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_LAUNCHER)
                setPackage(packageName)
            }
            val activities = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.queryIntentActivities(intent, 0)
            }
            activities.isNotEmpty()
        } catch (e: Exception) {
            true
        }
    }
}