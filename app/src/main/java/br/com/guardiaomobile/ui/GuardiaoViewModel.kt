package br.com.guardiaomobile.ui

import android.app.ActivityManager
import android.content.ContentResolver
import android.content.ContentValues
import android.content.Context
import android.content.SharedPreferences
import android.media.MediaScannerConnection
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.documentfile.provider.DocumentFile
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import br.com.guardiaomobile.adfilter.LocalAdBlockerVpnService
import br.com.guardiaomobile.adfilter.NetworkThreatAlert
import br.com.guardiaomobile.adfilter.VpnCountry
import br.com.guardiaomobile.downloads.MediaCategory
import br.com.guardiaomobile.downloads.UrlValidationResult
import br.com.guardiaomobile.downloads.UrlValidator
import br.com.guardiaomobile.memory.RamDiagnosticsProvider
import br.com.guardiaomobile.memory.SystemRamSnapshot
import br.com.guardiaomobile.security.DeviceAntivirusScanner
import br.com.guardiaomobile.security.FileAnalysisReport
import br.com.guardiaomobile.security.FileSecurityAnalyzer
import br.com.guardiaomobile.security.FullAntivirusScanReport
import br.com.guardiaomobile.security.SecurityStatus
import com.yausername.ffmpeg.FFmpeg
import com.yausername.youtubedl_android.YoutubeDL
import com.yausername.youtubedl_android.YoutubeDLRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.net.URLEncoder
import java.util.UUID
import java.util.concurrent.TimeUnit

enum class AppScreen {
    HOME,
    DOWNLOADS,
    VERIFY_FILE,
    WEB_PROTECTION,
    RAM_DIAGNOSTICS,
    SETTINGS
}

enum class DownloadStatus {
    VALIDANDO,
    BAIXANDO,
    PAUSADO,
    AGUARDANDO_ANALISE,
    CONCLUIDO,
    CANCELADO,
    ERRO
}

data class DownloadTaskItem(
    val id: String,
    val url: String,
    val host: String,
    val fileName: String,
    val category: MediaCategory,
    val savedFolderPath: String,
    val knownSizeBytes: Long,
    val downloadedBytes: Long,
    val progressPercent: Int,
    val speedBytesPerSec: Long,
    val status: DownloadStatus,
    val securityStatus: SecurityStatus,
    val sha256: String? = null,
    val errorMessage: String? = null
)

data class GuardiaoUiState(
    val currentScreen: AppScreen = AppScreen.HOME,
    val urlInput: String = "",
    val selectedCategory: MediaCategory = MediaCategory.VIDEO,
    val autoDownloadOnShare: Boolean = true,
    val showShareFormatDialog: Boolean = false,
    val isVpnActive: Boolean = false,
    val selectedVpnCountry: VpnCountry = VpnCountry.BRASIL,
    val vpnBlockedAdsCount: Int = 0,
    val networkThreatAlerts: List<NetworkThreatAlert> = emptyList(),
    val urlValidationError: String? = null,
    val downloads: List<DownloadTaskItem> = emptyList(),
    val isAnalyzingFile: Boolean = false,
    val isRunningFullAntivirusScan: Boolean = false,
    val antivirusScanReport: FullAntivirusScanReport? = null,
    val isExtractingLocalAudio: Boolean = false,
    val localAudioExtractionMessage: String? = null,
    val selectedFileName: String? = null,
    val selectedFileUri: Uri? = null,
    val latestFileReport: FileAnalysisReport? = null,
    val ramSnapshot: SystemRamSnapshot? = null
)

class GuardiaoViewModel(
    private val context: Context,
    private val urlValidator: UrlValidator = UrlValidator(),
    private val securityAnalyzer: FileSecurityAnalyzer = FileSecurityAnalyzer(),
    private val antivirusScanner: DeviceAntivirusScanner = DeviceAntivirusScanner(context, securityAnalyzer),
    private val ramProvider: RamDiagnosticsProvider,
    private val preferences: SharedPreferences
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        GuardiaoUiState(
            autoDownloadOnShare = preferences.getBoolean(KEY_AUTO_DOWNLOAD_ON_SHARE, true),
            isVpnActive = LocalAdBlockerVpnService.isRunning.value ||
                preferences.getBoolean(LocalAdBlockerVpnService.PREF_VPN_ENABLED, false),
            selectedVpnCountry = VpnCountry.fromCode(
                preferences.getString(LocalAdBlockerVpnService.PREF_VPN_COUNTRY, VpnCountry.BRASIL.code)
            ),
            vpnBlockedAdsCount = LocalAdBlockerVpnService.blockedCount.value,
            networkThreatAlerts = LocalAdBlockerVpnService.threatAlerts.value
        )
    )
    val uiState: StateFlow<GuardiaoUiState> = _uiState.asStateFlow()

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(25, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    private val activeJobs = mutableMapOf<String, Job>()
    private val engineMutex = Mutex()

    @Volatile
    private var isEngineInitialized = false

    @Volatile
    private var isEngineUpdated = false

    init {
        ensureLocalSubfoldersExist()
        refreshRamMetrics()
        observeVpnState()
        runFullDeviceAntivirusScan()
        viewModelScope.launch(Dispatchers.IO) {
            ensureEngineReady(forceUpdateIfFirstTime = true)
        }
    }

    fun runFullDeviceAntivirusScan() {
        if (_uiState.value.isRunningFullAntivirusScan) return
        _uiState.update { it.copy(isRunningFullAntivirusScan = true) }
        viewModelScope.launch(Dispatchers.IO) {
            val report = antivirusScanner.runFullSecurityScan()
            val ramSnap = ramProvider.captureSnapshot()
            _uiState.update {
                it.copy(
                    isRunningFullAntivirusScan = false,
                    antivirusScanReport = report,
                    ramSnapshot = ramSnap
                )
            }
        }
    }

    fun killBackgroundAppProcesses(packageName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
                am.killBackgroundProcesses(packageName)
            } catch (e: Exception) {
            }
            refreshRamMetrics()
        }
    }

    fun deleteSuspiciousDownloadPath(path: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                File(path).delete()
            } catch (e: Exception) {
            }
            runFullDeviceAntivirusScan()
        }
    }

    fun clearNetworkAlerts() {
        LocalAdBlockerVpnService.clearThreatAlerts()
    }

    private fun ensureLocalSubfoldersExist() {
        val subFolders = listOf("Videos", "Fotos", "Audios")
        val appExternalBase = File(context.getExternalFilesDir(null), ROOT_FOLDER_NAME)
        subFolders.forEach { sub ->
            File(appExternalBase, sub).mkdirs()
        }
        try {
            val publicDownloadBase = File(
                Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                ROOT_FOLDER_NAME
            )
            subFolders.forEach { sub ->
                File(publicDownloadBase, sub).mkdirs()
            }
        } catch (e: Exception) {
        }
    }

    private fun getSubfolderName(category: MediaCategory): String {
        return when (category) {
            MediaCategory.VIDEO -> "Videos"
            MediaCategory.IMAGE -> "Fotos"
            MediaCategory.AUDIO -> "Audios"
        }
    }

    private fun getMimeTypeForExtension(ext: String, category: MediaCategory): String {
        return when (ext.lowercase()) {
            "mp4" -> "video/mp4"
            "mkv" -> "video/x-matroska"
            "webm" -> "video/webm"
            "mp3" -> "audio/mpeg"
            "m4a" -> "audio/mp4"
            "wav" -> "audio/wav"
            "ogg" -> "audio/ogg"
            "jpg", "jpeg" -> "image/jpeg"
            "png" -> "image/png"
            "webp" -> "image/webp"
            else -> category.defaultMimeType
        }
    }

    private fun saveFileToCategoryFolder(
        sourceFile: File,
        fileName: String,
        category: MediaCategory,
        extension: String
    ): File {
        val subFolder = getSubfolderName(category)
        val appLocalDir = File(context.getExternalFilesDir(null), "$ROOT_FOLDER_NAME/$subFolder").apply { mkdirs() }
        val localCopy = File(appLocalDir, fileName)
        sourceFile.inputStream().use { input ->
            localCopy.outputStream().use { output ->
                input.copyTo(output)
            }
        }

        val mimeType = getMimeTypeForExtension(extension, category)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                val resolver = context.contentResolver
                val values = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                    put(MediaStore.MediaColumns.MIME_TYPE, mimeType)
                    put(MediaStore.MediaColumns.RELATIVE_PATH, "${Environment.DIRECTORY_DOWNLOADS}/$ROOT_FOLDER_NAME/$subFolder")
                    put(MediaStore.MediaColumns.IS_PENDING, 1)
                }
                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                if (uri != null) {
                    resolver.openOutputStream(uri)?.use { out ->
                        localCopy.inputStream().use { input ->
                            input.copyTo(out)
                        }
                    }
                    values.clear()
                    values.put(MediaStore.MediaColumns.IS_PENDING, 0)
                    resolver.update(uri, values, null, null)
                }
            } catch (e: Exception) {
            }
        } else {
            try {
                val publicDir = File(
                    Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                    "$ROOT_FOLDER_NAME/$subFolder"
                ).apply { mkdirs() }
                val publicFile = File(publicDir, fileName)
                localCopy.inputStream().use { input ->
                    publicFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                MediaScannerConnection.scanFile(
                    context,
                    arrayOf(publicFile.absolutePath),
                    arrayOf(mimeType),
                    null
                )
            } catch (e: Exception) {
            }
        }

        return localCopy
    }

    private fun observeVpnState() {
        viewModelScope.launch {
            LocalAdBlockerVpnService.isRunning.collect { active ->
                val prefEnabled = preferences.getBoolean(LocalAdBlockerVpnService.PREF_VPN_ENABLED, false)
                _uiState.update { it.copy(isVpnActive = active || prefEnabled) }
            }
        }
        viewModelScope.launch {
            LocalAdBlockerVpnService.blockedCount.collect { count ->
                _uiState.update { it.copy(vpnBlockedAdsCount = count) }
            }
        }
        viewModelScope.launch {
            LocalAdBlockerVpnService.activeCountry.collect { country ->
                _uiState.update { it.copy(selectedVpnCountry = country) }
            }
        }
        viewModelScope.launch {
            LocalAdBlockerVpnService.threatAlerts.collect { alerts ->
                _uiState.update { it.copy(networkThreatAlerts = alerts) }
            }
        }
    }

    private suspend fun ensureEngineReady(forceUpdateIfFirstTime: Boolean = false) {
        engineMutex.withLock {
            if (!isEngineInitialized) {
                try {
                    YoutubeDL.getInstance().init(context)
                    FFmpeg.getInstance().init(context)
                    isEngineInitialized = true
                } catch (e: Throwable) {
                }
            }
            if (forceUpdateIfFirstTime && !isEngineUpdated && isEngineInitialized) {
                try {
                    YoutubeDL.getInstance().updateYoutubeDL(context, YoutubeDL.UpdateChannel.NIGHTLY)
                    isEngineUpdated = true
                } catch (e: Throwable) {
                    try {
                        YoutubeDL.getInstance().updateYoutubeDL(context, YoutubeDL.UpdateChannel.STABLE)
                        isEngineUpdated = true
                    } catch (ignored: Throwable) {
                    }
                }
            }
        }
    }

    fun navigateTo(screen: AppScreen) {
        if (screen == AppScreen.RAM_DIAGNOSTICS || screen == AppScreen.HOME) {
            refreshRamMetrics()
        }
        _uiState.update { it.copy(currentScreen = screen) }
    }

    fun setVpnActive(isActive: Boolean) {
        preferences.edit().putBoolean(LocalAdBlockerVpnService.PREF_VPN_ENABLED, isActive).apply()
        _uiState.update { it.copy(isVpnActive = isActive) }
    }

    fun selectVpnCountry(country: VpnCountry) {
        preferences.edit().putString(LocalAdBlockerVpnService.PREF_VPN_COUNTRY, country.code).apply()
        _uiState.update { it.copy(selectedVpnCountry = country) }
        if (_uiState.value.isVpnActive) {
            LocalAdBlockerVpnService.startServiceCompat(context, country)
        }
    }

    fun onUrlInputChange(newValue: String) {
        val detectedCategory = urlValidator.detectCategoryByExtension(newValue)
        _uiState.update {
            it.copy(
                urlInput = newValue,
                selectedCategory = detectedCategory ?: it.selectedCategory,
                urlValidationError = null
            )
        }
    }

    fun onSelectMediaCategory(category: MediaCategory) {
        _uiState.update {
            it.copy(
                selectedCategory = category,
                urlValidationError = null
            )
        }
    }

    fun onToggleAutoDownloadOnShare(enabled: Boolean) {
        preferences.edit().putBoolean(KEY_AUTO_DOWNLOAD_ON_SHARE, enabled).apply()
        _uiState.update { it.copy(autoDownloadOnShare = enabled) }
    }

    fun handleIncomingSharedText(sharedText: String) {
        val extractedUrl = urlValidator.extractUrlFromSharedText(sharedText) ?: sharedText.trim()
        val detectedCategory = urlValidator.detectCategoryByExtension(extractedUrl) ?: _uiState.value.selectedCategory

        _uiState.update {
            it.copy(
                currentScreen = AppScreen.DOWNLOADS,
                urlInput = extractedUrl,
                selectedCategory = detectedCategory,
                showShareFormatDialog = true,
                urlValidationError = null
            )
        }
    }

    fun dismissShareFormatDialog() {
        _uiState.update { it.copy(showShareFormatDialog = false) }
    }

    fun confirmShareFormatAndStart(chosenCategory: MediaCategory) {
        _uiState.update {
            it.copy(
                selectedCategory = chosenCategory,
                showShareFormatDialog = false,
                urlValidationError = null
            )
        }
        startAutomaticMediaDownload()
    }

    fun startAutomaticMediaDownload(): Boolean {
        val state = _uiState.value
        val result = urlValidator.validateMediaUrl(state.urlInput, state.selectedCategory)
        val validUrl = when (result) {
            is UrlValidationResult.Invalid -> {
                _uiState.update { it.copy(urlValidationError = result.reason) }
                return false
            }
            is UrlValidationResult.Valid -> {
                _uiState.update {
                    it.copy(
                        urlValidationError = null,
                        selectedCategory = result.category
                    )
                }
                result
            }
        }

        val taskId = UUID.randomUUID().toString()
        val subFolder = getSubfolderName(validUrl.category)
        val relativeFolderDisplay = "Download/$ROOT_FOLDER_NAME/$subFolder"

        val initialItem = DownloadTaskItem(
            id = taskId,
            url = validUrl.normalizedUrl,
            host = validUrl.host,
            fileName = validUrl.suggestedFileName,
            category = validUrl.category,
            savedFolderPath = relativeFolderDisplay,
            knownSizeBytes = -1L,
            downloadedBytes = 0L,
            progressPercent = 0,
            speedBytesPerSec = 0L,
            status = DownloadStatus.BAIXANDO,
            securityStatus = SecurityStatus.AGUARDANDO_ANALISE
        )

        _uiState.update {
            it.copy(
                urlInput = "",
                downloads = listOf(initialItem) + it.downloads
            )
        }

        val job = viewModelScope.launch(Dispatchers.IO) {
            executeDownloadAndVerify(taskId = taskId, validUrl = validUrl)
        }
        activeJobs[taskId] = job
        return true
    }

    private suspend fun executeDownloadAndVerify(
        taskId: String,
        validUrl: UrlValidationResult.Valid
    ) {
        val lowerUrl = validUrl.normalizedUrl.lowercase()
        val isSocialOrMusicPlatform = urlValidator.detectPlatform(lowerUrl) ||
            urlValidator.isSpotifyUrl(lowerUrl) ||
            lowerUrl.contains("spotify") ||
            lowerUrl.contains("youtube") ||
            lowerUrl.contains("youtu.be")

        if (isSocialOrMusicPlatform) {
            val extractedSuccess = downloadFromSocialPlatform(taskId, validUrl)
            if (!extractedSuccess) {
                val currentStatus = _uiState.value.downloads.find { it.id == taskId }?.status
                if (currentStatus == DownloadStatus.BAIXANDO) {
                    updateDownloadItem(taskId) {
                        it.copy(
                            status = DownloadStatus.ERRO,
                            errorMessage = "Não foi possível extrair esta mídia. Verifique sua conexão ou se o link é público."
                        )
                    }
                }
            }
            activeJobs.remove(taskId)
            return
        }

        val ok = downloadDirectStreamToFolder(
            taskId = taskId,
            directUrl = validUrl.normalizedUrl,
            targetCategory = validUrl.category,
            suggestedFileName = validUrl.suggestedFileName,
            extension = validUrl.extension
        )

        if (!ok) {
            val fallbackSuccess = downloadFromSocialPlatform(taskId, validUrl)
            if (!fallbackSuccess) {
                val currentStatus = _uiState.value.downloads.find { it.id == taskId }?.status
                if (currentStatus == DownloadStatus.BAIXANDO) {
                    updateDownloadItem(taskId) {
                        it.copy(
                            status = DownloadStatus.ERRO,
                            errorMessage = "Não foi possível baixar ou converter a mídia deste link."
                        )
                    }
                }
            }
        }
        activeJobs.remove(taskId)
    }

    private suspend fun downloadFromSocialPlatform(
        taskId: String,
        validUrl: UrlValidationResult.Valid
    ): Boolean {
        val canonicalUrl = resolveRedirectedUrl(validUrl.normalizedUrl)
        val lowerUrl = canonicalUrl.lowercase()

        if (urlValidator.isSpotifyUrl(canonicalUrl) || lowerUrl.contains("spotify")) {
            return downloadSpotifyTrack(taskId, canonicalUrl)
        }

        if (lowerUrl.contains("instagram.com") || lowerUrl.contains("tiktok.com")) {
            val fastDirectUrl = resolveSocialFallbackDirectUrl(canonicalUrl, validUrl.category)
            if (fastDirectUrl != null) {
                val ok = downloadDirectStreamToFolder(
                    taskId = taskId,
                    directUrl = fastDirectUrl,
                    targetCategory = validUrl.category,
                    suggestedFileName = validUrl.suggestedFileName,
                    extension = validUrl.extension
                )
                if (ok) return true
            }
        }

        ensureEngineReady(forceUpdateIfFirstTime = true)
        val tempDir = File(context.cacheDir, "dl_$taskId").apply { mkdirs() }
        try {
            val producedFile = executeYtDlpExtraction(taskId, canonicalUrl, validUrl.category, tempDir)
            if (producedFile != null && producedFile.exists()) {
                val actualExt = producedFile.extension.ifBlank { validUrl.extension }
                val finalFileName = validUrl.suggestedFileName.substringBeforeLast('.') + ".$actualExt"
                val savedFile = saveFileToCategoryFolder(producedFile, finalFileName, validUrl.category, actualExt)
                finalizeAndVerifyDownload(taskId, savedFile, actualExt)
                return true
            }
        } catch (firstError: Exception) {
            val fallbackDirectUrl = resolveSocialFallbackDirectUrl(canonicalUrl, validUrl.category)
            if (fallbackDirectUrl != null) {
                val ok = downloadDirectStreamToFolder(
                    taskId = taskId,
                    directUrl = fallbackDirectUrl,
                    targetCategory = validUrl.category,
                    suggestedFileName = validUrl.suggestedFileName,
                    extension = validUrl.extension
                )
                if (ok) return true
            }

            try {
                engineMutex.withLock {
                    YoutubeDL.getInstance().updateYoutubeDL(context, YoutubeDL.UpdateChannel.NIGHTLY)
                    isEngineUpdated = true
                }
                tempDir.listFiles()?.forEach { it.delete() }
                val retryFile = executeYtDlpExtraction(taskId, canonicalUrl, validUrl.category, tempDir)
                if (retryFile != null && retryFile.exists()) {
                    val actualExt = retryFile.extension.ifBlank { validUrl.extension }
                    val finalFileName = validUrl.suggestedFileName.substringBeforeLast('.') + ".$actualExt"
                    val savedFile = saveFileToCategoryFolder(retryFile, finalFileName, validUrl.category, actualExt)
                    finalizeAndVerifyDownload(taskId, savedFile, actualExt)
                    return true
                }
            } catch (secondError: Exception) {
            }

            val rawError = firstError.message ?: ""
            val lastNonBlankLine = rawError.lines().map { it.trim() }.lastOrNull { it.isNotEmpty() } ?: "acesso negado pela plataforma"
            val friendlyMessage = if (rawError.contains("login required", ignoreCase = true) ||
                rawError.contains("rate-limit", ignoreCase = true) ||
                rawError.contains("Sign in to confirm", ignoreCase = true)
            ) {
                "A plataforma bloqueou temporariamente o acesso anônimo a este link."
            } else {
                "Não foi possível extrair a mídia: $lastNonBlankLine"
            }

            val currentStatus = _uiState.value.downloads.find { it.id == taskId }?.status
            if (currentStatus != DownloadStatus.CANCELADO) {
                updateDownloadItem(taskId) {
                    it.copy(status = DownloadStatus.ERRO, errorMessage = friendlyMessage)
                }
            }
            return false
        } finally {
            tempDir.deleteRecursively()
        }
        return false
    }

    private suspend fun downloadSpotifyTrack(
        taskId: String,
        spotifyUrl: String
    ): Boolean {
        val searchQuery = resolveSpotifyTrackToSearchQuery(spotifyUrl)
        if (searchQuery.isNullOrBlank()) {
            updateDownloadItem(taskId) {
                it.copy(
                    status = DownloadStatus.ERRO,
                    errorMessage = "Não foi possível ler o título da música no link do Spotify."
                )
            }
            return false
        }

        val cleanFileName = searchQuery.replace(Regex("[^a-zA-Z0-9_-]"), "_").take(50) + ".mp3"
        updateDownloadItem(taskId) {
            it.copy(
                fileName = cleanFileName,
                category = MediaCategory.AUDIO,
                savedFolderPath = "Download/$ROOT_FOLDER_NAME/Audios",
                progressPercent = 15
            )
        }

        val pipedAudioStreamUrl = searchPipedAudioStreamUrl("$searchQuery official audio")
        if (pipedAudioStreamUrl != null) {
            val ok = downloadDirectStreamToFolder(
                taskId = taskId,
                directUrl = pipedAudioStreamUrl,
                targetCategory = MediaCategory.AUDIO,
                suggestedFileName = cleanFileName,
                extension = "mp3"
            )
            if (ok) return true
        }

        ensureEngineReady(forceUpdateIfFirstTime = true)
        val tempDir = File(context.cacheDir, "dl_sp_$taskId").apply { mkdirs() }
        try {
            val ytSearchQuery = "ytsearch1:$searchQuery"
            val producedFile = executeYtDlpExtraction(taskId, ytSearchQuery, MediaCategory.AUDIO, tempDir)
            if (producedFile != null && producedFile.exists()) {
                val actualExt = producedFile.extension.ifBlank { "mp3" }
                val savedFile = saveFileToCategoryFolder(producedFile, cleanFileName, MediaCategory.AUDIO, actualExt)
                finalizeAndVerifyDownload(taskId, savedFile, actualExt)
                return true
            }
        } catch (e: Exception) {
            val msg = e.message?.lines()?.lastOrNull { it.isNotBlank() } ?: "erro na extração de áudio"
            updateDownloadItem(taskId) {
                it.copy(status = DownloadStatus.ERRO, errorMessage = "Falha ao baixar música ($searchQuery): $msg")
            }
            return false
        } finally {
            tempDir.deleteRecursively()
        }
        return false
    }

    private fun searchPipedAudioStreamUrl(query: String): String? {
        val encodedQuery = try {
            URLEncoder.encode(query, "UTF-8")
        } catch (e: Exception) {
            return null
        }
        val pipedInstances = listOf(
            "https://pipedapi.kavin.rocks",
            "https://pipedapi.tokhmi.xyz",
            "https://pipedapi.moomoo.me",
            "https://pipedapi.syncpundit.io"
        )
        for (instance in pipedInstances) {
            try {
                val searchReq = Request.Builder()
                    .url("$instance/search?q=$encodedQuery&filter=music_songs")
                    .header("User-Agent", DESKTOP_USER_AGENT)
                    .get()
                    .build()
                var videoId: String? = null
                httpClient.newCall(searchReq).execute().use { resp ->
                    if (resp.isSuccessful) {
                        val json = JSONObject(resp.body?.string() ?: "")
                        val items = json.optJSONArray("items")
                        if (items != null && items.length() > 0) {
                            val urlPath = items.getJSONObject(0).optString("url")
                            videoId = urlPath.substringAfter("v=", "").substringBefore("&").ifBlank { null }
                        }
                    }
                }
                if (videoId != null) {
                    val streamUrl = fetchPipedStreamByVideoId(instance, videoId!!, MediaCategory.AUDIO)
                    if (streamUrl != null) return streamUrl
                }
            } catch (e: Exception) {
            }
        }
        return null
    }

    private fun resolveSpotifyTrackToSearchQuery(spotifyUrl: String): String? {
        try {
            val cleanUrl = spotifyUrl.substringBefore('?')
            val encoded = URLEncoder.encode(cleanUrl, "UTF-8")
            val oembedUrl = "https://open.spotify.com/oembed?url=$encoded"
            val req = Request.Builder()
                .url(oembedUrl)
                .header("User-Agent", DESKTOP_USER_AGENT)
                .get()
                .build()
            httpClient.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) {
                    val bodyStr = resp.body?.string() ?: ""
                    val json = JSONObject(bodyStr)
                    val title = json.optString("title").trim()
                    if (title.isNotEmpty()) {
                        val author = extractSpotifyArtistFromHtml(cleanUrl)
                        return if (!author.isNullOrBlank() && !title.contains(author, ignoreCase = true)) {
                            "$author - $title"
                        } else {
                            title
                        }
                    }
                }
            }
        } catch (e: Exception) {
        }
        return extractSpotifyTitleAndArtistFromHtml(spotifyUrl)
    }

    private fun extractSpotifyArtistFromHtml(spotifyUrl: String): String? {
        return try {
            val req = Request.Builder()
                .url(spotifyUrl)
                .header("User-Agent", DESKTOP_USER_AGENT)
                .get()
                .build()
            httpClient.newCall(req).execute().use { resp ->
                val html = resp.body?.string() ?: return null
                val descMatch = Regex("""<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)["']""", RegexOption.IGNORE_CASE).find(html)
                val desc = descMatch?.groupValues?.getOrNull(1) ?: return null
                desc.substringBefore("·").substringBefore("-").trim().takeIf { it.isNotEmpty() }
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun extractSpotifyTitleAndArtistFromHtml(spotifyUrl: String): String? {
        return try {
            val req = Request.Builder()
                .url(spotifyUrl)
                .header("User-Agent", DESKTOP_USER_AGENT)
                .get()
                .build()
            httpClient.newCall(req).execute().use { resp ->
                val html = resp.body?.string() ?: return null
                val titleMatch = Regex("""<title>([^<]+)</title>""", RegexOption.IGNORE_CASE).find(html)
                val rawTitle = titleMatch?.groupValues?.getOrNull(1)
                    ?.replace("| Spotify", "")
                    ?.replace("- song and lyrics by", "-")
                    ?.replace("- música e letra de", "-")
                    ?.trim()
                rawTitle?.takeIf { it.isNotEmpty() && !it.equals("Spotify", ignoreCase = true) }
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun executeYtDlpExtraction(
        taskId: String,
        targetUrl: String,
        category: MediaCategory,
        tempDir: File
    ): File? {
        val ytRequest = YoutubeDLRequest(targetUrl)
        ytRequest.addOption("-o", "${tempDir.absolutePath}/media.%(ext)s")
        ytRequest.addOption("--no-mtime")
        ytRequest.addOption("--no-check-certificates")
        ytRequest.addOption("--geo-bypass")
        ytRequest.addOption("--no-playlist")
        ytRequest.addOption("--extractor-args", "youtube:player_client=android,web")

        when (category) {
            MediaCategory.AUDIO -> {
                ytRequest.addOption("-f", "bestaudio[ext=m4a]/bestaudio/best")
                ytRequest.addOption("-x")
                ytRequest.addOption("--audio-format", "mp3")
                ytRequest.addOption("--audio-quality", "0")
            }
            MediaCategory.IMAGE -> {
                ytRequest.addOption("--write-thumbnail")
                ytRequest.addOption("--skip-download")
                ytRequest.addOption("--convert-thumbnails", "jpg")
            }
            MediaCategory.VIDEO -> {
                ytRequest.addOption("-f", "best[ext=mp4]/bestvideo[ext=mp4]+bestaudio[ext=m4a]/best")
                ytRequest.addOption("--merge-output-format", "mp4")
            }
        }

        YoutubeDL.getInstance().execute(ytRequest, taskId) { progress, _, _ ->
            val pct = progress.toInt().coerceIn(0, 100)
            updateDownloadItem(taskId) {
                it.copy(progressPercent = pct)
            }
        }

        return tempDir.listFiles()
            ?.filter { it.isFile && it.length() > 0L && !it.name.endsWith(".part") && !it.name.endsWith(".ytdl") }
            ?.maxByOrNull { it.length() }
    }

    private fun resolveRedirectedUrl(rawUrl: String): String {
        return try {
            val req = Request.Builder()
                .url(rawUrl)
                .header("User-Agent", DESKTOP_USER_AGENT)
                .get()
                .build()
            httpClient.newCall(req).execute().use { resp ->
                resp.request.url.toString()
            }
        } catch (e: Exception) {
            rawUrl
        }
    }

    private fun resolveSocialFallbackDirectUrl(rawUrl: String, category: MediaCategory): String? {
        val lower = rawUrl.lowercase()
        if (lower.contains("instagram.com")) {
            return resolveInstagramFallbackUrl(rawUrl, category)
        }
        if (lower.contains("tiktok.com")) {
            return resolveTikTokFallbackUrl(rawUrl, category)
        }
        if (lower.contains("youtube.com") || lower.contains("youtu.be")) {
            return resolveYouTubeFallbackUrl(rawUrl, category)
        }
        return null
    }

    private fun resolveYouTubeFallbackUrl(rawUrl: String, category: MediaCategory): String? {
        val videoId = extractYouTubeVideoId(rawUrl) ?: return null
        val pipedInstances = listOf(
            "https://pipedapi.kavin.rocks",
            "https://pipedapi.tokhmi.xyz",
            "https://pipedapi.moomoo.me",
            "https://pipedapi.syncpundit.io"
        )
        for (instance in pipedInstances) {
            val url = fetchPipedStreamByVideoId(instance, videoId, category)
            if (url != null) return url
        }
        return null
    }

    private fun fetchPipedStreamByVideoId(instance: String, videoId: String, category: MediaCategory): String? {
        try {
            val req = Request.Builder()
                .url("$instance/streams/$videoId")
                .header("User-Agent", DESKTOP_USER_AGENT)
                .get()
                .build()
            httpClient.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return null
                val bodyStr = resp.body?.string() ?: return null
                val json = JSONObject(bodyStr)
                if (category == MediaCategory.IMAGE) {
                    val thumb = json.optString("thumbnailUrl")
                    if (thumb.startsWith("http")) return thumb
                } else if (category == MediaCategory.AUDIO) {
                    val audioStreams = json.optJSONArray("audioStreams")
                    if (audioStreams != null && audioStreams.length() > 0) {
                        val streamUrl = audioStreams.getJSONObject(0).optString("url")
                        if (streamUrl.startsWith("http")) return streamUrl
                    }
                } else {
                    val videoStreams = json.optJSONArray("videoStreams")
                    if (videoStreams != null) {
                        for (i in 0 until videoStreams.length()) {
                            val obj = videoStreams.getJSONObject(i)
                            val videoOnly = obj.optBoolean("videoOnly", true)
                            val url = obj.optString("url")
                            if (!videoOnly && url.startsWith("http")) {
                                return url
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
        }
        return null
    }

    private fun extractYouTubeVideoId(rawUrl: String): String? {
        val patterns = listOf(
            Regex("""[?&]v=([a-zA-Z0-9_-]{11})"""),
            Regex("""youtu\.be/([a-zA-Z0-9_-]{11})"""),
            Regex("""youtube\.com/shorts/([a-zA-Z0-9_-]{11})""")
        )
        for (regex in patterns) {
            val match = regex.find(rawUrl)
            if (match != null) return match.groupValues[1]
        }
        return null
    }

    private fun resolveInstagramFallbackUrl(rawUrl: String, category: MediaCategory): String? {
        val shortcodeMatch = Regex("/(p|reel|reels|tv)/([A-Za-z0-9_-]+)").find(rawUrl)
        val shortcode = shortcodeMatch?.groupValues?.getOrNull(2) ?: return null

        val graphqlDocIds = listOf("10015901848480474", "8845758582119845")
        for (docId in graphqlDocIds) {
            try {
                val variablesJson = """{"shortcode":"$shortcode","fetch_comment_count":2,"fetch_related_profile_media_count":0,"parent_comment_count":0,"child_comment_count":0,"fetch_like_count":10,"fetch_tagged_user_count":null,"fetch_preview_comment_count":2,"has_threaded_comments":true,"hoisted_comment_id":null,"hoisted_reply_id":null}"""
                val formBody = FormBody.Builder()
                    .add("av", "0")
                    .add("__d", "www")
                    .add("__user", "0")
                    .add("__a", "1")
                    .add("__req", "3")
                    .add("lsd", "AVqbxe3J_YA")
                    .add("fb_api_caller_class", "RelayModern")
                    .add("fb_api_req_friendly_name", "PolarisPostActionLoadPostQueryQuery")
                    .add("variables", variablesJson)
                    .add("server_timestamps", "true")
                    .add("doc_id", docId)
                    .build()

                val req = Request.Builder()
                    .url("https://www.instagram.com/graphql/query")
                    .header("User-Agent", DESKTOP_USER_AGENT)
                    .header("X-IG-App-ID", "936619743392459")
                    .header("X-FB-LSD", "AVqbxe3J_YA")
                    .header("X-ASBD-ID", "129477")
                    .header("Origin", "https://www.instagram.com")
                    .header("Referer", "https://www.instagram.com/p/$shortcode/")
                    .post(formBody)
                    .build()

                httpClient.newCall(req).execute().use { resp ->
                    val bodyText = resp.body?.string() ?: ""
                    val targetKey = if (category == MediaCategory.IMAGE) "display_url" else "video_url"
                    val match = Regex("""\\?"$targetKey\\?"\s*:\s*\\?"([^"\\]+(?:\\.[^"\\]*)*)\\?"""").find(bodyText)
                    if (match != null) {
                        val candidate = unescapeJsonUrl(match.groupValues[1])
                        if (candidate.startsWith("https://")) return candidate
                    }
                }
            } catch (e: Exception) {
            }
        }

        val embedUrls = listOf(
            "https://www.instagram.com/p/$shortcode/embed/captioned/",
            "https://www.instagram.com/reel/$shortcode/embed/captioned/",
            "https://www.instagram.com/p/$shortcode/embed/"
        )
        for (embedUrl in embedUrls) {
            try {
                val req = Request.Builder()
                    .url(embedUrl)
                    .header("User-Agent", DESKTOP_USER_AGENT)
                    .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                    .header("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8")
                    .get()
                    .build()
                httpClient.newCall(req).execute().use { resp ->
                    val html = resp.body?.string() ?: ""
                    val targetKey = if (category == MediaCategory.IMAGE) "display_url" else "video_url"
                    val regex = Regex("""\\?"$targetKey\\?"\s*:\s*\\?"([^"\\]+(?:\\.[^"\\]*)*)\\?"""")
                    val match = regex.find(html)
                    if (match != null) {
                        val candidate = unescapeJsonUrl(match.groupValues[1])
                        if (candidate.startsWith("https://")) return candidate
                    }
                }
            } catch (e: Exception) {
            }
        }

        val proxyHosts = listOf("api.vxinstagram.com", "www.vxinstagram.com", "www.eeinstagram.com", "www.kkinstagram.com")
        for (proxy in proxyHosts) {
            try {
                val proxyUrl = "https://$proxy/p/$shortcode"
                val req = Request.Builder()
                    .url(proxyUrl)
                    .header("User-Agent", "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)")
                    .get()
                    .build()
                httpClient.newCall(req).execute().use { resp ->
                    val contentType = resp.header("Content-Type")?.lowercase() ?: ""
                    if (contentType.contains("application/json")) {
                        val jsonStr = resp.body?.string() ?: ""
                        val urlMatch = Regex(""""url"\s*:\s*"(https:[^"]+)"""").find(jsonStr)
                        if (urlMatch != null) {
                            return unescapeJsonUrl(urlMatch.groupValues[1])
                        }
                    } else {
                        val html = resp.body?.string() ?: ""
                        val metaTag = if (category == MediaCategory.IMAGE) "og:image" else "og:video"
                        val regex = Regex("""<meta[^>]+property=["']$metaTag(?::secure_url)?["'][^>]+content=["']([^"']+)["']""", RegexOption.IGNORE_CASE)
                        val match = regex.find(html)
                        if (match != null) {
                            val candidate = unescapeJsonUrl(match.groupValues[1])
                            if (candidate.startsWith("http")) return candidate
                        }
                    }
                }
            } catch (e: Exception) {
            }
        }
        return null
    }

    private fun resolveTikTokFallbackUrl(rawUrl: String, category: MediaCategory): String? {
        return try {
            val encoded = URLEncoder.encode(rawUrl, "UTF-8")
            val apiUrl = "https://www.tikwm.com/api/?url=$encoded"
            val req = Request.Builder()
                .url(apiUrl)
                .header("User-Agent", DESKTOP_USER_AGENT)
                .get()
                .build()
            httpClient.newCall(req).execute().use { resp ->
                val bodyStr = resp.body?.string() ?: return null
                val json = JSONObject(bodyStr)
                val data = json.optJSONObject("data") ?: return null
                when (category) {
                    MediaCategory.AUDIO -> data.optString("music").takeIf { it.startsWith("http") }
                        ?: data.optString("play").takeIf { it.startsWith("http") }
                    MediaCategory.IMAGE -> data.optString("cover").takeIf { it.startsWith("http") }
                    MediaCategory.VIDEO -> data.optString("play").takeIf { it.startsWith("http") }
                        ?: data.optString("wmplay").takeIf { it.startsWith("http") }
                }
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun unescapeJsonUrl(escaped: String): String {
        return escaped
            .replace("\\\\/", "/")
            .replace("\\/", "/")
            .replace("\\\\u0026", "&")
            .replace("\\u0026", "&")
            .replace("\\u0025", "%")
            .replace("&amp;", "&")
            .trim('"', '\\')
    }

    private suspend fun downloadDirectStreamToFolder(
        taskId: String,
        directUrl: String,
        targetCategory: MediaCategory,
        suggestedFileName: String,
        extension: String
    ): Boolean {
        val tempInputFile = File(context.cacheDir, "raw_stream_$taskId.tmp")
        val tempOutputAudio = File(context.cacheDir, "conv_audio_$taskId.mp3")
        return try {
            val req = Request.Builder()
                .url(directUrl)
                .header("User-Agent", DESKTOP_USER_AGENT)
                .get()
                .build()
            httpClient.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return false
                val body = resp.body ?: return false
                val contentType = resp.header("Content-Type")?.lowercase() ?: ""
                if (contentType.contains("text/html")) return false

                val totalBytes = body.contentLength()
                updateDownloadItem(taskId) { it.copy(knownSizeBytes = totalBytes) }

                var downloaded = 0L
                val startTime = System.currentTimeMillis()

                tempInputFile.outputStream().use { output ->
                    body.byteStream().use { input ->
                        val buffer = ByteArray(8192)
                        var read: Int
                        while (input.read(buffer).also { read = it } != -1) {
                            if (!currentCoroutineContext().isActive) return false
                            output.write(buffer, 0, read)
                            downloaded += read
                            val elapsedSec = ((System.currentTimeMillis() - startTime) / 1000L).coerceAtLeast(1L)
                            val speed = downloaded / elapsedSec
                            val pct = if (totalBytes > 0) ((downloaded * 100L) / totalBytes).toInt().coerceIn(0, 95) else 50
                            updateDownloadItem(taskId) {
                                it.copy(
                                    downloadedBytes = downloaded,
                                    progressPercent = pct,
                                    speedBytesPerSec = speed
                                )
                            }
                        }
                        output.flush()
                    }
                }

                if (downloaded <= 0L) return false

                val needsAudioConversion = targetCategory == MediaCategory.AUDIO && !contentType.contains("audio/mpeg")
                val finalSourceFile = if (needsAudioConversion && convertMediaFileToMp3(tempInputFile, tempOutputAudio)) {
                    tempOutputAudio
                } else {
                    tempInputFile
                }

                val savedFile = saveFileToCategoryFolder(
                    sourceFile = finalSourceFile,
                    fileName = suggestedFileName,
                    category = targetCategory,
                    extension = extension
                )

                finalizeAndVerifyDownload(taskId, savedFile, extension)
                true
            }
        } catch (e: Exception) {
            false
        } finally {
            tempInputFile.delete()
            tempOutputAudio.delete()
        }
    }

    private suspend fun convertMediaFileToMp3(inputFile: File, outputMp3File: File): Boolean {
        ensureEngineReady()
        return try {
            val ytReq = YoutubeDLRequest("file://${inputFile.absolutePath}")
            ytReq.addOption("--enable-file-urls")
            ytReq.addOption("-x")
            ytReq.addOption("--audio-format", "mp3")
            ytReq.addOption("--audio-quality", "0")
            ytReq.addOption("-o", outputMp3File.absolutePath)
            YoutubeDL.getInstance().execute(ytReq)
            outputMp3File.exists() && outputMp3File.length() > 0L
        } catch (e: Throwable) {
            false
        }
    }

    private fun finalizeAndVerifyDownload(
        taskId: String,
        savedFile: File,
        extension: String
    ) {
        val totalBytes = savedFile.length()
        updateDownloadItem(taskId) {
            it.copy(
                status = DownloadStatus.AGUARDANDO_ANALISE,
                securityStatus = SecurityStatus.AGUARDANDO_ANALISE,
                speedBytesPerSec = 0L,
                progressPercent = 100,
                knownSizeBytes = totalBytes,
                downloadedBytes = totalBytes
            )
        }

        savedFile.inputStream().use { verifyInput ->
            val report = securityAnalyzer.analyzeStream(
                inputStream = verifyInput,
                declaredExtension = extension,
                expectedSizeBytes = if (totalBytes > 0) totalBytes else null
            )
            updateDownloadItem(taskId) {
                it.copy(
                    status = DownloadStatus.CONCLUIDO,
                    securityStatus = report.status,
                    sha256 = report.sha256
                )
            }
        }
    }

    fun cancelDownload(taskId: String) {
        activeJobs[taskId]?.cancel()
        activeJobs.remove(taskId)
        try {
            YoutubeDL.getInstance().destroyProcessById(taskId)
        } catch (e: Exception) {
        }
        updateDownloadItem(taskId) {
            it.copy(
                status = DownloadStatus.CANCELADO,
                speedBytesPerSec = 0L,
                errorMessage = "Download cancelado pelo usuário."
            )
        }
    }

    fun analyzeSelectedFile(contentResolver: ContentResolver, uri: Uri, displayName: String) {
        _uiState.update {
            it.copy(
                isAnalyzingFile = true,
                localAudioExtractionMessage = null,
                selectedFileName = displayName,
                selectedFileUri = uri,
                latestFileReport = FileAnalysisReport(
                    status = SecurityStatus.AGUARDANDO_ANALISE,
                    sha256 = null,
                    detectedFormat = "Em inspeção",
                    sizeBytes = 0L,
                    explanation = "O arquivo será verificado em busca de ameaças, reputação e integridade."
                )
            )
        }

        viewModelScope.launch(Dispatchers.IO) {
            val ext = displayName.substringAfterLast('.', "mp4")
            val report = contentResolver.openInputStream(uri)?.use { stream ->
                securityAnalyzer.analyzeStream(stream, declaredExtension = ext)
            } ?: FileAnalysisReport(
                status = SecurityStatus.ANALISE_INCOMPLETA,
                sha256 = null,
                detectedFormat = "Inacessível",
                sizeBytes = 0L,
                explanation = "Não foi possível abrir o arquivo selecionado."
            )

            _uiState.update {
                it.copy(
                    isAnalyzingFile = false,
                    latestFileReport = report
                )
            }
        }
    }

    fun extractAudioFromAnalyzedVideo(
        contentResolver: ContentResolver,
        onComplete: (Boolean, String) -> Unit
    ) {
        val sourceVideoUri = _uiState.value.selectedFileUri ?: return
        val baseVideoName = (_uiState.value.selectedFileName ?: "video")
            .substringBeforeLast('.')
            .replace(Regex("[^a-zA-Z0-9_-]"), "_")
        val outputFileName = "${baseVideoName}_${System.currentTimeMillis()}.mp3"

        _uiState.update {
            it.copy(
                isExtractingLocalAudio = true,
                localAudioExtractionMessage = "Separando áudio para Download/$ROOT_FOLDER_NAME/Audios..."
            )
        }

        viewModelScope.launch(Dispatchers.IO) {
            val tempDir = File(context.cacheDir, "extract_${UUID.randomUUID()}").apply { mkdirs() }
            val ext = _uiState.value.selectedFileName?.substringAfterLast('.', "mp4") ?: "mp4"
            val tempVideo = File(tempDir, "input_video.$ext")
            val tempMp3 = File(tempDir, "output_audio.mp3")

            var success = false
            var message = "Não foi possível separar o áudio deste vídeo."

            try {
                contentResolver.openInputStream(sourceVideoUri)?.use { input ->
                    tempVideo.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }

                if (tempVideo.exists() && tempVideo.length() > 0L) {
                    val converted = convertMediaFileToMp3(tempVideo, tempMp3)
                    val producedMp3 = tempDir.listFiles()?.firstOrNull {
                        it.isFile && it.name.startsWith("output_audio") && it.length() > 0L
                    } ?: tempMp3.takeIf { converted && it.exists() }

                    if (producedMp3 != null && producedMp3.exists()) {
                        saveFileToCategoryFolder(
                            sourceFile = producedMp3,
                            fileName = outputFileName,
                            category = MediaCategory.AUDIO,
                            extension = "mp3"
                        )
                        success = true
                        message = "Salvo automaticamente em Download/$ROOT_FOLDER_NAME/Audios/$outputFileName"
                    }
                }
            } catch (e: Exception) {
                message = "Erro ao extrair áudio: ${e.message ?: "falha na conversão"}"
            } finally {
                tempDir.deleteRecursively()
            }

            _uiState.update {
                it.copy(
                    isExtractingLocalAudio = false,
                    localAudioExtractionMessage = message
                )
            }

            withContext(Dispatchers.Main) {
                onComplete(success, message)
            }
        }
    }

    fun deleteAnalyzedFile(documentFile: DocumentFile?, onResult: (Boolean) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val deleted = documentFile?.delete() == true
            if (deleted) {
                _uiState.update {
                    it.copy(
                        selectedFileName = null,
                        selectedFileUri = null,
                        latestFileReport = null,
                        localAudioExtractionMessage = null
                    )
                }
            }
            withContext(Dispatchers.Main) {
                onResult(deleted)
            }
        }
    }

    fun refreshRamMetrics() {
        val snapshot = ramProvider.captureSnapshot()
        _uiState.update { it.copy(ramSnapshot = snapshot) }
    }

    private fun updateDownloadItem(taskId: String, transform: (DownloadTaskItem) -> DownloadTaskItem) {
        _uiState.update { state ->
            state.copy(
                downloads = state.downloads.map { item ->
                    if (item.id == taskId) transform(item) else item
                }
            )
        }
    }

    companion object {
        const val ROOT_FOLDER_NAME = "GuardiaoMobile"
        private const val KEY_AUTO_DOWNLOAD_ON_SHARE = "auto_download_on_share"
        private const val DESKTOP_USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    }
}