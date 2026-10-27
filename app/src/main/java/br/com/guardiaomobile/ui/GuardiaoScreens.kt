package br.com.guardiaomobile.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.AudioFile
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.HourglassEmpty
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.ShieldMoon
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.VideoFile
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import br.com.guardiaomobile.adfilter.NetworkThreatAlert
import br.com.guardiaomobile.adfilter.VpnCountry
import br.com.guardiaomobile.downloads.MediaCategory
import br.com.guardiaomobile.memory.SystemRamSnapshot
import br.com.guardiaomobile.security.BackgroundRamAppItem
import br.com.guardiaomobile.security.DownloadedFileFinding
import br.com.guardiaomobile.security.FileAnalysisReport
import br.com.guardiaomobile.security.FullAntivirusScanReport
import br.com.guardiaomobile.security.SecurityStatus
import br.com.guardiaomobile.security.SuspiciousAppFinding
import br.com.guardiaomobile.security.ThreatSeverity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val GuardianGreen = Color(0xFF00B981)
private val GuardianNavy = Color(0xFF102A43)
private val GuardianBackground = Color(0xFFF5F8FA)
private val GuardianMuted = Color(0xFF627D98)
private val GuardianIndigo = Color(0xFF6366F1)
private val GuardianWarning = Color(0xFFF59E0B)
private val GuardianDanger = Color(0xFFEF4444)

private data class FeatureItem(
    val title: String,
    val description: String,
    val icon: ImageVector,
    val accentColor: Color,
    val targetScreen: AppScreen
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GuardiaoRootScreen(
    uiState: GuardiaoUiState,
    onNavigate: (AppScreen) -> Unit,
    onUrlChange: (String) -> Unit,
    onSelectCategory: (MediaCategory) -> Unit,
    onConfirmShareCategory: (MediaCategory) -> Unit,
    onDismissShareDialog: () -> Unit,
    onToggleAutoDownloadOnShare: (Boolean) -> Unit,
    onToggleVpn: (Boolean) -> Unit,
    onSelectVpnCountry: (VpnCountry) -> Unit,
    onStartAutomaticDownload: () -> Unit,
    onCancelDownload: (String) -> Unit,
    onPickFileToVerify: () -> Unit,
    onRunFullAntivirusScan: () -> Unit,
    onInspectSpecificPackage: (String) -> Unit,
    onUninstallSpecificPackage: (String) -> Unit,
    onKillBackgroundPackage: (String) -> Unit,
    onDeleteSuspiciousDownload: (String) -> Unit,
    onClearNetworkAlerts: () -> Unit,
    onExtractAudioFromVideo: () -> Unit,
    onConfirmDeleteSelectedFile: () -> Unit,
    onOpenWirelessSettings: () -> Unit = {},
    onRefreshRam: () -> Unit,
    onOpenManageAppsSettings: () -> Unit,
    onOpenBatteryUsageSettings: () -> Unit,
    onOpenOwnAppDetails: () -> Unit
) {
    var showPermissionsDialog by remember { mutableStateOf(false) }

    Scaffold(
        containerColor = GuardianBackground,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(containerColor = GuardianBackground),
                navigationIcon = {
                    if (uiState.currentScreen != AppScreen.HOME) {
                        IconButton(onClick = { onNavigate(AppScreen.HOME) }) {
                            Icon(
                                imageVector = Icons.Default.ArrowBack,
                                contentDescription = "Voltar",
                                tint = GuardianNavy
                            )
                        }
                    }
                },
                title = {
                    if (uiState.currentScreen == AppScreen.HOME) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Surface(
                                color = GuardianGreen.copy(alpha = 0.14f),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.size(42.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Shield,
                                    contentDescription = null,
                                    tint = GuardianGreen,
                                    modifier = Modifier.padding(9.dp)
                                )
                            }
                            Column(Modifier.padding(start = 12.dp)) {
                                Text(
                                    text = "Guardião Mobile",
                                    fontWeight = FontWeight.Bold,
                                    color = GuardianNavy,
                                    style = MaterialTheme.typography.titleMedium
                                )
                                Text(
                                    text = "Antivírus, Firewall VPN e Downloads",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = GuardianMuted
                                )
                            }
                        }
                    } else {
                        Text(
                            text = when (uiState.currentScreen) {
                                AppScreen.HOME -> "Guardião Mobile"
                                AppScreen.DOWNLOADS -> "Downloads Automáticos"
                                AppScreen.VERIFY_FILE -> "Antivírus e Varredura"
                                AppScreen.WEB_PROTECTION -> "Firewall VPN e País de IP"
                                AppScreen.RAM_DIAGNOSTICS -> "Memória e 2º Plano"
                                AppScreen.SETTINGS -> "Configurações"
                            },
                            fontWeight = FontWeight.Bold,
                            color = GuardianNavy
                        )
                    }
                },
                actions = {
                    IconButton(onClick = { showPermissionsDialog = true }) {
                        Icon(
                            imageVector = Icons.Default.Info,
                            contentDescription = "Sobre e permissões",
                            tint = GuardianNavy
                        )
                    }
                }
            )
        },
        bottomBar = {
            NavigationBar(containerColor = Color.White) {
                val navItems = listOf(
                    Triple("Início", Icons.Default.Shield, AppScreen.HOME),
                    Triple("Downloads", Icons.Default.Download, AppScreen.DOWNLOADS),
                    Triple("Antivírus", Icons.Default.Security, AppScreen.VERIFY_FILE),
                    Triple("Memória", Icons.Default.Memory, AppScreen.RAM_DIAGNOSTICS),
                    Triple("Mais", Icons.Default.Settings, AppScreen.SETTINGS)
                )
                navItems.forEach { (label, icon, screen) ->
                    val isSelected = uiState.currentScreen == screen ||
                        (uiState.currentScreen == AppScreen.WEB_PROTECTION && screen == AppScreen.SETTINGS)
                    NavigationBarItem(
                        selected = isSelected,
                        onClick = { onNavigate(screen) },
                        icon = { Icon(icon, contentDescription = label) },
                        label = { Text(label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = GuardianGreen,
                            selectedTextColor = GuardianGreen,
                            indicatorColor = GuardianGreen.copy(alpha = 0.14f),
                            unselectedIconColor = GuardianMuted,
                            unselectedTextColor = GuardianMuted
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .background(GuardianBackground)
        ) {
            when (uiState.currentScreen) {
                AppScreen.HOME -> HomeScreen(
                    uiState = uiState,
                    onSelectScreen = onNavigate
                )
                AppScreen.DOWNLOADS -> DownloadsScreen(
                    urlInput = uiState.urlInput,
                    selectedCategory = uiState.selectedCategory,
                    autoDownloadOnShare = uiState.autoDownloadOnShare,
                    validationError = uiState.urlValidationError,
                    downloads = uiState.downloads,
                    onUrlChange = onUrlChange,
                    onSelectCategory = onSelectCategory,
                    onToggleAutoDownloadOnShare = onToggleAutoDownloadOnShare,
                    onStartDownloadClick = onStartAutomaticDownload,
                    onCancelDownload = onCancelDownload
                )
                AppScreen.VERIFY_FILE -> FileVerificationScreen(
                    isAnalyzing = uiState.isAnalyzingFile,
                    isRunningFullScan = uiState.isRunningFullAntivirusScan,
                    scanReport = uiState.antivirusScanReport,
                    networkAlerts = uiState.networkThreatAlerts,
                    isExtractingAudio = uiState.isExtractingLocalAudio,
                    audioExtractionMessage = uiState.localAudioExtractionMessage,
                    selectedFileName = uiState.selectedFileName,
                    report = uiState.latestFileReport,
                    onRunFullScan = onRunFullAntivirusScan,
                    onPickFile = onPickFileToVerify,
                    onInspectPackage = onInspectSpecificPackage,
                    onUninstallPackage = onUninstallSpecificPackage,
                    onKillBackgroundPackage = onKillBackgroundPackage,
                    onDeleteSuspiciousDownload = onDeleteSuspiciousDownload,
                    onClearNetworkAlerts = onClearNetworkAlerts,
                    onExtractAudioClick = onExtractAudioFromVideo,
                    onConfirmDeleteFile = onConfirmDeleteSelectedFile
                )
                AppScreen.WEB_PROTECTION -> WebProtectionScreen(
                    isVpnActive = uiState.isVpnActive,
                    selectedCountry = uiState.selectedVpnCountry,
                    blockedAdsCount = uiState.vpnBlockedAdsCount,
                    threatAlerts = uiState.networkThreatAlerts,
                    onToggleVpn = onToggleVpn,
                    onSelectCountry = onSelectVpnCountry,
                    onClearAlerts = onClearNetworkAlerts
                )
                AppScreen.RAM_DIAGNOSTICS -> RamDiagnosticsScreen(
                    snapshot = uiState.ramSnapshot,
                    heavyBackgroundApps = uiState.antivirusScanReport?.heavyBackgroundApps ?: emptyList(),
                    onRefresh = {
                        onRefreshRam()
                        onRunFullAntivirusScan()
                    },
                    onKillBackgroundApp = onKillBackgroundPackage,
                    onInspectApp = onInspectSpecificPackage,
                    onOpenManageApps = onOpenManageAppsSettings,
                    onOpenBatterySettings = onOpenBatteryUsageSettings,
                    onOpenOwnAppDetails = onOpenOwnAppDetails
                )
                AppScreen.SETTINGS -> SettingsOverviewScreen(
                    autoDownloadOnShare = uiState.autoDownloadOnShare,
                    isVpnActive = uiState.isVpnActive,
                    onToggleAutoDownloadOnShare = onToggleAutoDownloadOnShare,
                    onToggleVpn = onToggleVpn,
                    onNavigate = onNavigate,
                    onShowAboutDialog = { showPermissionsDialog = true }
                )
            }
        }
    }

    if (uiState.showShareFormatDialog) {
        ShareFormatSelectionDialog(
            sharedUrl = uiState.urlInput,
            onSelectFormat = onConfirmShareCategory,
            onDismiss = onDismissShareDialog
        )
    }

    if (showPermissionsDialog) {
        AlertDialog(
            onDismissRequest = { showPermissionsDialog = false },
            title = { Text("Sobre o Antivírus e Firewall VPN", fontWeight = FontWeight.Bold, color = GuardianNavy) },
            text = {
                Text(
                    "• Verificação de Sistema vs Usuário: identifica se o aplicativo pertence às partições oficiais do Android (/system, /product, /vendor) ou se foi instalado pelo usuário.\n\n" +
                        "• Detecção de Falsos Apps do Sistema: bloqueia malwares que imitam pacotes do Android fora da partição oficial.\n\n" +
                        "• Firewall Anti-Malvertising: bloqueia vírus em anúncios e alerta sobre conexões suspeitas.",
                    color = GuardianNavy
                )
            },
            confirmButton = {
                TextButton(onClick = { showPermissionsDialog = false }) {
                    Text("Entendi", color = GuardianGreen, fontWeight = FontWeight.Bold)
                }
            }
        )
    }
}

@Composable
private fun ShareFormatSelectionDialog(
    sharedUrl: String,
    onSelectFormat: (MediaCategory) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Escolha o formato de download",
                fontWeight = FontWeight.Bold,
                color = GuardianNavy
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "Salva automaticamente na subpasta correspondente:\n$sharedUrl",
                    style = MaterialTheme.typography.bodySmall,
                    color = GuardianMuted,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(Modifier.height(4.dp))

                Button(
                    onClick = { onSelectFormat(MediaCategory.VIDEO) },
                    colors = ButtonDefaults.buttonColors(containerColor = GuardianGreen),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                ) {
                    Icon(Icons.Default.VideoFile, contentDescription = null, tint = Color.White)
                    Spacer(Modifier.width(8.dp))
                    Text("Vídeo (.mp4) -> Pasta Videos", fontWeight = FontWeight.Bold, color = Color.White)
                }

                Button(
                    onClick = { onSelectFormat(MediaCategory.AUDIO) },
                    colors = ButtonDefaults.buttonColors(containerColor = GuardianIndigo),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                ) {
                    Icon(Icons.Default.AudioFile, contentDescription = null, tint = Color.White)
                    Spacer(Modifier.width(8.dp))
                    Text("Áudio (.mp3) -> Pasta Audios", fontWeight = FontWeight.Bold, color = Color.White)
                }

                Button(
                    onClick = { onSelectFormat(MediaCategory.IMAGE) },
                    colors = ButtonDefaults.buttonColors(containerColor = GuardianNavy),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                ) {
                    Icon(Icons.Default.Image, contentDescription = null, tint = Color.White)
                    Spacer(Modifier.width(8.dp))
                    Text("Foto (.jpg) -> Pasta Fotos", fontWeight = FontWeight.Bold, color = Color.White)
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancelar", color = GuardianMuted)
            }
        }
    )
}

@Composable
fun HomeScreen(
    uiState: GuardiaoUiState,
    onSelectScreen: (AppScreen) -> Unit
) {
    val suspiciousCount = (uiState.antivirusScanReport?.suspiciousApps?.size ?: 0) +
        (uiState.antivirusScanReport?.suspiciousDownloads?.size ?: 0)

    val antivirusSubtitle = if (suspiciousCount > 0) {
        "Alerta: $suspiciousCount ameaça(s) detectada(s)"
    } else if (uiState.antivirusScanReport != null) {
        "${uiState.antivirusScanReport.systemAppsCount} apps do sistema • ${uiState.antivirusScanReport.userAppsCount} apps do usuário"
    } else {
        "Diferencia apps do sistema, apps de usuário e downloads"
    }

    val ramSubtitle = uiState.ramSnapshot?.let {
        "Em uso: ${it.usagePercentage}% (${uiState.antivirusScanReport?.heavyBackgroundApps?.size ?: 0} apps em 2º plano)"
    } ?: "Monitore e feche apps pesados em 2º plano"

    val vpnSubtitle = if (uiState.isVpnActive) {
        "Ativa (${uiState.selectedVpnCountry.displayName} • ${uiState.vpnBlockedAdsCount} bloqueios • ${uiState.networkThreatAlerts.size} alertas)"
    } else {
        "Proteção contra vírus em anúncios e conexões estranhas"
    }

    val features = listOf(
        FeatureItem(
            title = "Antivírus (Sistema vs Usuário)",
            description = antivirusSubtitle,
            icon = Icons.Default.VerifiedUser,
            accentColor = if (suspiciousCount > 0) GuardianDanger else Color(0xFF8B5CF6),
            targetScreen = AppScreen.VERIFY_FILE
        ),
        FeatureItem(
            title = "Firewall VPN e Anti-Malvertising",
            description = vpnSubtitle,
            icon = Icons.Default.ShieldMoon,
            accentColor = if (uiState.isVpnActive) GuardianGreen else GuardianDanger,
            targetScreen = AppScreen.WEB_PROTECTION
        ),
        FeatureItem(
            title = "Memória RAM e Apps em 2º Plano",
            description = ramSubtitle,
            icon = Icons.Default.Memory,
            accentColor = GuardianGreen,
            targetScreen = AppScreen.RAM_DIAGNOSTICS
        ),
        FeatureItem(
            title = "Downloads Diretos em Pastas",
            description = "Salva em GuardiaoMobile/Videos, Fotos e Audios (${uiState.downloads.size} itens)",
            icon = Icons.Default.Download,
            accentColor = GuardianIndigo,
            targetScreen = AppScreen.DOWNLOADS
        )
    )

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = when {
                        suspiciousCount > 0 -> GuardianDanger
                        uiState.isVpnActive -> GuardianGreen
                        else -> GuardianNavy
                    }
                ),
                shape = RoundedCornerShape(24.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(20.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            text = when {
                                suspiciousCount > 0 -> "$suspiciousCount Alerta(s) de Segurança"
                                uiState.isVpnActive -> "Proteção Máxima Ativa (${uiState.selectedVpnCountry.displayName})"
                                else -> "Proteção Antivírus Local"
                            },
                            color = Color.White,
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = "Sistema: ${uiState.antivirusScanReport?.systemAppsCount ?: 0} apps • Usuário: ${uiState.antivirusScanReport?.userAppsCount ?: 0} apps • Downloads: ${uiState.antivirusScanReport?.scannedDownloadsCount ?: 0}",
                            color = Color.White.copy(alpha = 0.92f),
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(56.dp)
                    )
                }
            }
        }

        item {
            Text(
                text = "Central de Proteção",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = GuardianNavy
            )
        }

        items(features) { feature ->
            FeatureCard(
                feature = feature,
                onClick = { onSelectScreen(feature.targetScreen) }
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FeatureCard(
    feature: FeatureItem,
    onClick: () -> Unit
) {
    Card(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 76.dp),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(
                color = feature.accentColor.copy(alpha = 0.12f),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.size(48.dp)
            ) {
                Icon(
                    imageVector = feature.icon,
                    contentDescription = null,
                    tint = feature.accentColor,
                    modifier = Modifier.padding(12.dp)
                )
            }
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(start = 14.dp, end = 8.dp)
            ) {
                Text(
                    text = feature.title,
                    fontWeight = FontWeight.SemiBold,
                    color = GuardianNavy,
                    style = MaterialTheme.typography.bodyLarge
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = feature.description,
                    style = MaterialTheme.typography.bodySmall,
                    color = GuardianMuted
                )
            }
            Text(
                text = ">",
                style = MaterialTheme.typography.titleLarge,
                color = GuardianMuted
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DownloadsScreen(
    urlInput: String,
    selectedCategory: MediaCategory,
    autoDownloadOnShare: Boolean,
    validationError: String?,
    downloads: List<DownloadTaskItem>,
    onUrlChange: (String) -> Unit,
    onSelectCategory: (MediaCategory) -> Unit,
    onToggleAutoDownloadOnShare: (Boolean) -> Unit,
    onStartDownloadClick: () -> Unit,
    onCancelDownload: (String) -> Unit
) {
    val targetSubFolder = when (selectedCategory) {
        MediaCategory.VIDEO -> "Download/GuardiaoMobile/Videos"
        MediaCategory.IMAGE -> "Download/GuardiaoMobile/Fotos"
        MediaCategory.AUDIO -> "Download/GuardiaoMobile/Audios"
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = Color.White),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    OutlinedTextField(
                        value = urlInput,
                        onValueChange = onUrlChange,
                        leadingIcon = {
                            Icon(Icons.Default.Link, contentDescription = null, tint = GuardianMuted)
                        },
                        label = { Text("Cole a URL de vídeo, música ou foto aqui") },
                        placeholder = { Text("https://...") },
                        singleLine = true,
                        isError = validationError != null,
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    )

                    if (validationError != null) {
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = validationError,
                            color = GuardianDanger,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        MediaCategory.values().forEach { category ->
                            FilterChip(
                                selected = selectedCategory == category,
                                onClick = { onSelectCategory(category) },
                                label = { Text("${category.displayName} (.${category.defaultExtension})") },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = GuardianGreen.copy(alpha = 0.15f),
                                    selectedLabelColor = GuardianNavy
                                )
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(6.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Folder,
                            contentDescription = null,
                            tint = GuardianIndigo,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(Modifier.width(6.dp))
                        Text(
                            text = "Pasta automática: $targetSubFolder",
                            style = MaterialTheme.typography.labelSmall,
                            color = GuardianMuted
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Button(
                        onClick = onStartDownloadClick,
                        colors = ButtonDefaults.buttonColors(containerColor = GuardianGreen),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 50.dp)
                    ) {
                        Text(
                            text = "Baixar ${selectedCategory.displayName} Direto na Pasta",
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                    }
                }
            }
        }

        item {
            Text(
                text = "Downloads e Histórico",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = GuardianNavy
            )
        }

        if (downloads.isEmpty()) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    shape = RoundedCornerShape(20.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "Pastas Prontas",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = GuardianNavy
                        )
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = "• Vídeos -> Download/GuardiaoMobile/Videos\n• Fotos -> Download/GuardiaoMobile/Fotos\n• Áudios -> Download/GuardiaoMobile/Audios",
                            style = MaterialTheme.typography.bodySmall,
                            color = GuardianMuted
                        )
                    }
                }
            }
        } else {
            items(downloads, key = { it.id }) { item ->
                DownloadHistoryCard(
                    item = item,
                    onCancelDownload = onCancelDownload
                )
            }
        }
    }
}

@Composable
private fun DownloadHistoryCard(
    item: DownloadTaskItem,
    onCancelDownload: (String) -> Unit
) {
    val badgeColor = when (item.securityStatus) {
        SecurityStatus.SEM_AMEACA_DETECTADA -> GuardianGreen
        SecurityStatus.AGUARDANDO_ANALISE -> GuardianWarning
        SecurityStatus.ANALISE_INCOMPLETA -> GuardianMuted
        SecurityStatus.SUSPEITO -> GuardianWarning
        SecurityStatus.AMEACA_DETECTADA -> GuardianDanger
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(
                    color = GuardianIndigo.copy(alpha = 0.12f),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.size(44.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Download,
                        contentDescription = null,
                        tint = GuardianIndigo,
                        modifier = Modifier.padding(10.dp)
                    )
                }
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .padding(start = 12.dp)
                ) {
                    Text(
                        text = item.fileName,
                        fontWeight = FontWeight.Bold,
                        color = GuardianNavy,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "Pasta: ${item.savedFolderPath}",
                        style = MaterialTheme.typography.bodySmall,
                        color = GuardianIndigo
                    )
                }
            }

            if (item.status == DownloadStatus.BAIXANDO) {
                Spacer(modifier = Modifier.height(10.dp))
                if (item.progressPercent in 1..100) {
                    LinearProgressIndicator(
                        progress = { (item.progressPercent / 100f).coerceIn(0f, 1f) },
                        color = GuardianGreen,
                        trackColor = GuardianBackground,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(8.dp)
                    )
                } else {
                    LinearProgressIndicator(
                        color = GuardianGreen,
                        trackColor = GuardianBackground,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(8.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
            val detailsText = if (item.knownSizeBytes > 0) {
                "${item.status} • ${formatBytes(item.downloadedBytes)} / ${formatBytes(item.knownSizeBytes)} (${item.progressPercent}%)"
            } else {
                "${item.status} • Progresso: ${item.progressPercent}%"
            }
            Text(
                text = detailsText,
                style = MaterialTheme.typography.bodySmall,
                color = GuardianMuted
            )

            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Antivírus: ${formatSecurityStatus(item.securityStatus)}",
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.SemiBold,
                color = badgeColor
            )

            if (item.errorMessage != null) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = item.errorMessage,
                    color = GuardianDanger,
                    style = MaterialTheme.typography.bodySmall
                )
            }

            if (item.status == DownloadStatus.BAIXANDO) {
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedButton(
                    onClick = { onCancelDownload(item.id) },
                    modifier = Modifier.heightIn(min = 44.dp)
                ) {
                    Text("Cancelar download", color = GuardianDanger)
                }
            }
        }
    }
}

@Composable
fun FileVerificationScreen(
    isAnalyzing: Boolean,
    isRunningFullScan: Boolean,
    scanReport: FullAntivirusScanReport?,
    networkAlerts: List<NetworkThreatAlert>,
    isExtractingAudio: Boolean,
    audioExtractionMessage: String?,
    selectedFileName: String?,
    report: FileAnalysisReport?,
    onRunFullScan: () -> Unit,
    onPickFile: () -> Unit,
    onInspectPackage: (String) -> Unit,
    onUninstallPackage: (String) -> Unit,
    onKillBackgroundPackage: (String) -> Unit,
    onDeleteSuspiciousDownload: (String) -> Unit,
    onClearNetworkAlerts: () -> Unit,
    onExtractAudioClick: () -> Unit,
    onConfirmDeleteFile: () -> Unit
) {
    var showDeleteConfirmation by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = GuardianNavy),
                shape = RoundedCornerShape(20.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null,
                            tint = GuardianGreen,
                            modifier = Modifier.size(36.dp)
                        )
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(
                                text = "Scanner Antivírus (Sistema vs Usuário)",
                                color = Color.White,
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = if (scanReport != null) {
                                    "Sistema: ${scanReport.systemAppsCount} apps • Usuário: ${scanReport.userAppsCount} apps • Downloads: ${scanReport.scannedDownloadsCount}"
                                } else {
                                    "Verifica partições do sistema, apps do usuário e downloads"
                                },
                                color = Color.White.copy(alpha = 0.85f),
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }

                    Spacer(Modifier.height(14.dp))

                    Button(
                        onClick = onRunFullScan,
                        enabled = !isRunningFullScan,
                        colors = ButtonDefaults.buttonColors(containerColor = GuardianGreen),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp)
                    ) {
                        if (isRunningFullScan) {
                            CircularProgressIndicator(
                                color = Color.White,
                                strokeWidth = 2.dp,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(Modifier.width(10.dp))
                            Text("Verificando Sistema, Apps e Downloads...", color = Color.White, fontWeight = FontWeight.Bold)
                        } else {
                            Icon(Icons.Default.Refresh, contentDescription = null, tint = Color.White)
                            Spacer(Modifier.width(8.dp))
                            Text("Executar Varredura Antivírus Completa", color = Color.White, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }

        item {
            OutlinedButton(
                onClick = onPickFile,
                enabled = !isAnalyzing && !isExtractingAudio,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
            ) {
                Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = GuardianNavy)
                Spacer(Modifier.width(8.dp))
                Text("Inspecionar Arquivo Individual ou Extrair Áudio MP3", fontWeight = FontWeight.Bold, color = GuardianNavy)
            }
        }

        if (selectedFileName != null || report != null) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    shape = RoundedCornerShape(18.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = selectedFileName ?: "Arquivo",
                            fontWeight = FontWeight.Bold,
                            color = GuardianNavy
                        )
                        Text(
                            text = "${formatBytes(report?.sizeBytes ?: 0L)} • Formato: ${report?.detectedFormat ?: "Verificando"}",
                            style = MaterialTheme.typography.bodySmall,
                            color = GuardianMuted
                        )
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = report?.explanation ?: "",
                            style = MaterialTheme.typography.bodySmall,
                            color = GuardianNavy
                        )

                        if (report?.isVideoFile == true) {
                            Spacer(Modifier.height(12.dp))
                            Button(
                                onClick = onExtractAudioClick,
                                enabled = !isExtractingAudio && !isAnalyzing,
                                colors = ButtonDefaults.buttonColors(containerColor = GuardianIndigo),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .heightIn(min = 46.dp)
                            ) {
                                Icon(Icons.Default.AudioFile, contentDescription = null, tint = Color.White)
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    text = if (isExtractingAudio) "Extraindo Áudio (.mp3)..." else "Separar Áudio Direto para Pasta Audios",
                                    fontWeight = FontWeight.Bold,
                                    color = Color.White
                                )
                            }
                        }

                        if (audioExtractionMessage != null) {
                            Spacer(Modifier.height(8.dp))
                            Text(
                                text = audioExtractionMessage,
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.SemiBold,
                                color = GuardianGreen
                            )
                        }

                        if (report?.status == SecurityStatus.SUSPEITO || report?.status == SecurityStatus.AMEACA_DETECTADA) {
                            Spacer(Modifier.height(10.dp))
                            Button(
                                onClick = { showDeleteConfirmation = true },
                                colors = ButtonDefaults.buttonColors(containerColor = GuardianDanger),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Icon(Icons.Default.Delete, contentDescription = null, tint = Color.White)
                                Spacer(Modifier.width(8.dp))
                                Text("Excluir Arquivo Suspeito", color = Color.White, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }

        if (scanReport != null) {
            item {
                Text(
                    text = "1. Aplicativos Suspeitos (${scanReport.suspiciousApps.size})",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = GuardianNavy
                )
            }

            if (scanReport.suspiciousApps.isEmpty()) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = GuardianGreen.copy(alpha = 0.12f)),
                        shape = RoundedCornerShape(16.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = GuardianGreen)
                            Spacer(Modifier.width(10.dp))
                            Text(
                                text = "Todos os ${scanReport.systemAppsCount} apps do sistema são autênticos e nenhum dos ${scanReport.userAppsCount} apps de usuário apresentou comportamento malicioso.",
                                style = MaterialTheme.typography.bodySmall,
                                color = GuardianNavy
                            )
                        }
                    }
                }
            } else {
                items(scanReport.suspiciousApps, key = { it.packageName }) { app ->
                    SuspiciousAppCard(
                        finding = app,
                        onInspect = { onInspectPackage(app.packageName) },
                        onUninstall = { onUninstallPackage(app.packageName) }
                    )
                }
            }

            item {
                Text(
                    text = "2. Arquivos Suspeitos na Pasta Downloads (${scanReport.suspiciousDownloads.size})",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = GuardianNavy
                )
            }

            if (scanReport.suspiciousDownloads.isEmpty()) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        shape = RoundedCornerShape(16.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = "Nenhum APK perigoso ou executável disfarçado encontrado nos Downloads.",
                            style = MaterialTheme.typography.bodySmall,
                            color = GuardianMuted,
                            modifier = Modifier.padding(16.dp)
                        )
                    }
                }
            } else {
                items(scanReport.suspiciousDownloads, key = { it.absolutePath }) { fileFinding ->
                    SuspiciousDownloadCard(
                        finding = fileFinding,
                        onDelete = { onDeleteSuspiciousDownload(fileFinding.absolutePath) }
                    )
                }
            }

            item {
                Text(
                    text = "3. Apps Consumindo RAM em 2º Plano (${scanReport.heavyBackgroundApps.size})",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = GuardianNavy
                )
            }

            items(scanReport.heavyBackgroundApps.take(10), key = { "sec_ram_${it.packageName}" }) { bgApp ->
                BackgroundRamAppCard(
                    item = bgApp,
                    onKillProcess = { onKillBackgroundPackage(bgApp.packageName) },
                    onOpenAppSettings = { onInspectPackage(bgApp.packageName) }
                )
            }
        }

        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "4. Alertas de Conexões e Anúncios Maliciosos (${networkAlerts.size})",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = GuardianNavy
                )
                if (networkAlerts.isNotEmpty()) {
                    TextButton(onClick = onClearNetworkAlerts) {
                        Text("Limpar", color = GuardianDanger)
                    }
                }
            }
        }

        if (networkAlerts.isEmpty()) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = "Nenhuma tentativa de conexão suspeita ou anúncio com vírus detectado até o momento.",
                        style = MaterialTheme.typography.bodySmall,
                        color = GuardianMuted,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }
        } else {
            items(networkAlerts, key = { it.id }) { alert ->
                NetworkAlertCard(alert = alert)
            }
        }
    }

    if (showDeleteConfirmation) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirmation = false },
            title = { Text("Confirmar exclusão", fontWeight = FontWeight.Bold, color = GuardianNavy) },
            text = {
                Text(
                    "Deseja excluir permanentemente o arquivo '${selectedFileName ?: ""}'?",
                    color = GuardianNavy
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showDeleteConfirmation = false
                        onConfirmDeleteFile()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = GuardianDanger)
                ) {
                    Text("Confirmar Exclusão", color = Color.White)
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirmation = false }) {
                    Text("Cancelar", color = GuardianMuted)
                }
            }
        )
    }
}

@Composable
private fun AppOriginBadge(isSystemApp: Boolean, label: String) {
    val bgColor = if (isSystemApp) GuardianIndigo.copy(alpha = 0.14f) else GuardianWarning.copy(alpha = 0.16f)
    val textColor = if (isSystemApp) GuardianIndigo else GuardianNavy
    Surface(
        color = bgColor,
        shape = RoundedCornerShape(6.dp)
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            color = textColor,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
        )
    }
}

@Composable
private fun SuspiciousAppCard(
    finding: SuspiciousAppFinding,
    onInspect: () -> Unit,
    onUninstall: () -> Unit
) {
    val badgeColor = when (finding.severity) {
        ThreatSeverity.CRITICO, ThreatSeverity.ALTO_RISCO -> GuardianDanger
        ThreatSeverity.ATENCAO -> GuardianWarning
        ThreatSeverity.SEGURO -> GuardianGreen
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.BugReport, contentDescription = null, tint = badgeColor)
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(finding.appName, fontWeight = FontWeight.Bold, color = GuardianNavy)
                    Text(finding.packageName, style = MaterialTheme.typography.labelSmall, color = GuardianMuted)
                }
                Text(
                    text = finding.severity.name,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = badgeColor
                )
            }
            Spacer(Modifier.height(6.dp))
            AppOriginBadge(isSystemApp = finding.isSystemApp, label = finding.originTypeLabel)
            Spacer(Modifier.height(8.dp))
            finding.reasons.forEach { reason ->
                Text("• $reason", style = MaterialTheme.typography.bodySmall, color = GuardianNavy)
            }
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onInspect, modifier = Modifier.weight(1f)) {
                    Text("Permissões / Parar", color = GuardianNavy)
                }
                if (!finding.isSystemApp) {
                    Button(
                        onClick = onUninstall,
                        colors = ButtonDefaults.buttonColors(containerColor = GuardianDanger),
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Desinstalar", color = Color.White)
                    }
                }
            }
        }
    }
}

@Composable
private fun SuspiciousDownloadCard(
    finding: DownloadedFileFinding,
    onDelete: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Warning, contentDescription = null, tint = GuardianDanger)
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(finding.fileName, fontWeight = FontWeight.Bold, color = GuardianNavy)
                    Text(formatBytes(finding.sizeBytes), style = MaterialTheme.typography.labelSmall, color = GuardianMuted)
                }
            }
            Spacer(Modifier.height(6.dp))
            Text(finding.details, style = MaterialTheme.typography.bodySmall, color = GuardianNavy)
            Spacer(Modifier.height(10.dp))
            Button(
                onClick = onDelete,
                colors = ButtonDefaults.buttonColors(containerColor = GuardianDanger),
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.Delete, contentDescription = null, tint = Color.White)
                Spacer(Modifier.width(6.dp))
                Text("Excluir Arquivo dos Downloads", color = Color.White, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun BackgroundRamAppCard(
    item: BackgroundRamAppItem,
    onKillProcess: () -> Unit,
    onOpenAppSettings: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text(item.appName, fontWeight = FontWeight.Bold, color = GuardianNavy)
                    Text(
                        text = "Consumo estimado: ~${item.estimatedRamMb} MB • ${item.activeServicesCount} serviços",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.SemiBold,
                        color = GuardianWarning
                    )
                }
                AppOriginBadge(
                    isSystemApp = item.isSystemApp,
                    label = if (item.isSystemApp) "SISTEMA" else "USUÁRIO"
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(item.recommendation, style = MaterialTheme.typography.bodySmall, color = GuardianMuted)
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = onKillProcess,
                    colors = ButtonDefaults.buttonColors(containerColor = GuardianGreen),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Limpar RAM", color = Color.White)
                }
                OutlinedButton(
                    onClick = onOpenAppSettings,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Forçar Parada", color = GuardianNavy)
                }
            }
        }
    }
}

@Composable
private fun NetworkAlertCard(alert: NetworkThreatAlert) {
    Card(
        colors = CardDefaults.cardColors(containerColor = GuardianDanger.copy(alpha = 0.08f)),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(alert.category, fontWeight = FontWeight.Bold, color = GuardianDanger)
                Text(alert.timeFormatted, style = MaterialTheme.typography.labelSmall, color = GuardianMuted)
            }
            Spacer(Modifier.height(4.dp))
            Text("Alvo bloqueado: ${alert.targetHostOrIp}", fontWeight = FontWeight.SemiBold, color = GuardianNavy)
            Spacer(Modifier.height(2.dp))
            Text(alert.description, style = MaterialTheme.typography.bodySmall, color = GuardianNavy)
        }
    }
}

@Composable
fun RamDiagnosticsScreen(
    snapshot: SystemRamSnapshot?,
    heavyBackgroundApps: List<BackgroundRamAppItem>,
    onRefresh: () -> Unit,
    onKillBackgroundApp: (String) -> Unit,
    onInspectApp: (String) -> Unit,
    onOpenManageApps: () -> Unit,
    onOpenBatterySettings: () -> Unit,
    onOpenOwnAppDetails: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        if (snapshot == null) {
            item {
                CircularProgressIndicator(color = GuardianGreen)
            }
        } else {
            item {
                val timeFormatted = remember(snapshot.timestampEpochMillis) {
                    SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(snapshot.timestampEpochMillis))
                }

                Card(
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    shape = RoundedCornerShape(22.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Box(
                                contentAlignment = Alignment.Center,
                                modifier = Modifier.size(110.dp)
                            ) {
                                CircularProgressIndicator(
                                    progress = { 1f },
                                    modifier = Modifier.size(110.dp),
                                    color = GuardianBackground,
                                    strokeWidth = 10.dp
                                )
                                CircularProgressIndicator(
                                    progress = { (snapshot.usagePercentage / 100f).coerceIn(0f, 1f) },
                                    modifier = Modifier.size(110.dp),
                                    color = if (snapshot.isLowMemory) GuardianDanger else GuardianGreen,
                                    strokeWidth = 10.dp,
                                    strokeCap = StrokeCap.Round
                                )
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Text(
                                        text = "${snapshot.usagePercentage}%",
                                        style = MaterialTheme.typography.titleLarge,
                                        fontWeight = FontWeight.Bold,
                                        color = GuardianNavy
                                    )
                                    Text(
                                        text = "Em uso",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = GuardianMuted
                                    )
                                }
                            }

                            Spacer(Modifier.width(20.dp))

                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "Memória do Sistema",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = GuardianNavy
                                )
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    text = "${formatBytes(snapshot.usedBytes)} / ${formatBytes(snapshot.totalBytes)}",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = GuardianMuted,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Spacer(Modifier.height(6.dp))
                                Text(
                                    text = "Livre: ${formatBytes(snapshot.availableBytes)} ($timeFormatted)",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = GuardianGreen,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }

                            IconButton(onClick = onRefresh) {
                                Icon(Icons.Default.Refresh, contentDescription = "Atualizar", tint = GuardianNavy)
                            }
                        }
                    }
                }
            }

            item {
                Text(
                    text = "Apps em 2º Plano — Usuário e Sistema (${heavyBackgroundApps.size})",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = GuardianNavy
                )
            }

            items(heavyBackgroundApps, key = { "ram_tab_${it.packageName}" }) { bgApp ->
                BackgroundRamAppCard(
                    item = bgApp,
                    onKillProcess = { onKillBackgroundApp(bgApp.packageName) },
                    onOpenAppSettings = { onInspectApp(bgApp.packageName) }
                )
            }

            item {
                Button(
                    onClick = onOpenManageApps,
                    colors = ButtonDefaults.buttonColors(containerColor = GuardianNavy),
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 50.dp)
                ) {
                    Text("Ver Todos os Aplicativos no Sistema", color = Color.White, fontWeight = FontWeight.Bold)
                }
            }

            item {
                OutlinedButton(
                    onClick = onOpenBatterySettings,
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 50.dp)
                ) {
                    Text("Restringir Uso de Bateria em Segundo Plano", color = GuardianNavy)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun WebProtectionScreen(
    isVpnActive: Boolean,
    selectedCountry: VpnCountry,
    blockedAdsCount: Int,
    threatAlerts: List<NetworkThreatAlert>,
    onToggleVpn: (Boolean) -> Unit,
    onSelectCountry: (VpnCountry) -> Unit,
    onClearAlerts: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = Color.White),
            shape = RoundedCornerShape(18.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Firewall VPN 24h & Anti-Malvertising",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = GuardianNavy
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = if (isVpnActive) {
                                "ATIVO • Região: ${selectedCountry.displayName} (${selectedCountry.simulatedPublicIp})"
                            } else {
                                "DESATIVADO"
                            },
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                            color = if (isVpnActive) GuardianGreen else GuardianDanger
                        )
                    }
                    Switch(
                        checked = isVpnActive,
                        onCheckedChange = onToggleVpn,
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White,
                            checkedTrackColor = GuardianGreen
                        )
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "Anúncios, vírus em banners e conexões barradas: $blockedAdsCount",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = GuardianNavy
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "IP do Túnel: ${selectedCountry.virtualIp} • Sub-rede Geográfica: ${selectedCountry.simulatedPublicIp}",
                    style = MaterialTheme.typography.bodySmall,
                    color = GuardianMuted
                )

                Spacer(modifier = Modifier.height(14.dp))

                Button(
                    onClick = { onToggleVpn(!isVpnActive) },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (isVpnActive) GuardianDanger else GuardianGreen
                    ),
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 50.dp)
                ) {
                    Text(
                        text = if (isVpnActive) "Desativar Firewall VPN" else "Ativar Firewall VPN 24h",
                        color = Color.White,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }

        Card(
            colors = CardDefaults.cardColors(containerColor = Color.White),
            shape = RoundedCornerShape(18.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Public, contentDescription = null, tint = GuardianIndigo)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = "Selecionar País de Roteamento / IP",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = GuardianNavy
                    )
                }
                Spacer(modifier = Modifier.height(10.dp))

                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    VpnCountry.values().forEach { country ->
                        FilterChip(
                            selected = selectedCountry == country,
                            onClick = { onSelectCountry(country) },
                            label = {
                                Text("${country.displayName} (${country.simulatedPublicIp})")
                            },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = GuardianGreen.copy(alpha = 0.18f),
                                selectedLabelColor = GuardianNavy
                            )
                        )
                    }
                }
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Pedidos Estranhos e Vírus em Anúncios (${threatAlerts.size})",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = GuardianNavy
            )
            if (threatAlerts.isNotEmpty()) {
                TextButton(onClick = onClearAlerts) {
                    Text("Limpar", color = GuardianDanger)
                }
            }
        }

        threatAlerts.forEach { alert ->
            NetworkAlertCard(alert = alert)
        }
    }
}

@Composable
fun SettingsOverviewScreen(
    autoDownloadOnShare: Boolean,
    isVpnActive: Boolean,
    onToggleAutoDownloadOnShare: (Boolean) -> Unit,
    onToggleVpn: (Boolean) -> Unit,
    onNavigate: (AppScreen) -> Unit,
    onShowAboutDialog: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = Color.White),
            shape = RoundedCornerShape(18.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Firewall VPN 24h & Anti-Malvertising",
                        fontWeight = FontWeight.SemiBold,
                        color = GuardianNavy
                    )
                    Text(
                        text = if (isVpnActive) "Ativo continuamente" else "Desativado",
                        style = MaterialTheme.typography.bodySmall,
                        color = if (isVpnActive) GuardianGreen else GuardianMuted
                    )
                }
                Switch(
                    checked = isVpnActive,
                    onCheckedChange = onToggleVpn,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = GuardianGreen
                    )
                )
            }
        }

        OutlinedButton(
            onClick = onShowAboutDialog,
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 50.dp)
        ) {
            Text("Sobre o Antivírus, Firewall e Pastas", color = GuardianNavy)
        }
    }
}

private data class Quadruple<A, B, C, D>(
    val first: A,
    val second: B,
    val third: C,
    val fourth: D
)

private fun formatSecurityStatus(status: SecurityStatus): String {
    return when (status) {
        SecurityStatus.AGUARDANDO_ANALISE -> "Aguardando análise"
        SecurityStatus.SEM_AMEACA_DETECTADA -> "Sem ameaça detectada"
        SecurityStatus.SUSPEITO -> "Suspeito"
        SecurityStatus.AMEACA_DETECTADA -> "Ameaça detectada"
        SecurityStatus.ANALISE_INCOMPLETA -> "Análise incompleta"
    }
}

private fun formatBytes(bytes: Long): String {
    if (bytes <= 0L) return "0 B"
    val kb = 1024.0
    val mb = kb * 1024.0
    val gb = mb * 1024.0
    return when {
        bytes >= gb -> String.format(Locale.getDefault(), "%.2f GB", bytes / gb)
        bytes >= mb -> String.format(Locale.getDefault(), "%.2f MB", bytes / mb)
        bytes >= kb -> String.format(Locale.getDefault(), "%.1f KB", bytes / kb)
        else -> "$bytes B"
    }
}