package br.com.guardiaomobile.downloads

import android.net.Uri

enum class MediaCategory(
    val displayName: String,
    val defaultExtension: String,
    val defaultMimeType: String,
    val supportedExtensions: Set<String>
) {
    VIDEO(
        displayName = "Vídeo",
        defaultExtension = "mp4",
        defaultMimeType = "video/mp4",
        supportedExtensions = setOf("mp4", "mkv", "webm", "mov")
    ),
    AUDIO(
        displayName = "Áudio",
        defaultExtension = "mp3",
        defaultMimeType = "audio/mpeg",
        supportedExtensions = setOf("mp3", "m4a", "wav", "ogg", "flac")
    ),
    IMAGE(
        displayName = "Foto",
        defaultExtension = "jpg",
        defaultMimeType = "image/jpeg",
        supportedExtensions = setOf("jpg", "jpeg", "png", "webp")
    )
}

sealed class UrlValidationResult {
    data class Valid(
        val normalizedUrl: String,
        val host: String,
        val suggestedFileName: String,
        val extension: String,
        val mimeType: String,
        val category: MediaCategory
    ) : UrlValidationResult()

    data class Invalid(val reason: String) : UrlValidationResult()
}

class UrlValidator {

    private val extensionToMime = mapOf(
        "mp4" to "video/mp4",
        "mkv" to "video/x-matroska",
        "webm" to "video/webm",
        "mov" to "video/quicktime",
        "mp3" to "audio/mpeg",
        "m4a" to "audio/mp4",
        "wav" to "audio/wav",
        "ogg" to "audio/ogg",
        "flac" to "audio/flac",
        "jpg" to "image/jpeg",
        "jpeg" to "image/jpeg",
        "png" to "image/png",
        "webp" to "image/webp"
    )

    private val audioOnlyDomains = listOf(
        "spotify.com",
        "spotify.link",
        "soundcloud.com",
        "deezer.com",
        "music.youtube.com"
    )

    fun extractUrlFromSharedText(sharedText: String): String? {
        val regex = Regex("https?://[^\\s\"'<>]+", RegexOption.IGNORE_CASE)
        return regex.find(sharedText)?.value
    }

    fun isSpotifyUrl(rawUrl: String): Boolean {
        val lower = rawUrl.lowercase()
        return lower.contains("spotify.com") || lower.contains("spotify.link")
    }

    fun detectPlatform(rawUrl: String): Boolean {
        val lower = rawUrl.lowercase()
        return listOf(
            "youtube.com",
            "youtu.be",
            "music.youtube.com",
            "spotify.com",
            "spotify.link",
            "instagram.com",
            "tiktok.com",
            "vm.tiktok.com",
            "vt.tiktok.com",
            "twitter.com",
            "x.com",
            "facebook.com",
            "fb.watch",
            "kwai.com",
            "pinterest.com",
            "pin.it",
            "reddit.com",
            "redd.it",
            "vimeo.com",
            "soundcloud.com",
            "deezer.com",
            "twitch.tv",
            "threads.net",
            "dailymotion.com"
        ).any { lower.contains(it) }
    }

    fun detectCategoryByExtension(rawUrl: String): MediaCategory? {
        val lower = rawUrl.lowercase()
        if (audioOnlyDomains.any { lower.contains(it) }) {
            return MediaCategory.AUDIO
        }
        val parsed = try {
            Uri.parse(rawUrl.trim())
        } catch (e: Exception) {
            return null
        }
        val cleanPath = parsed.path ?: ""
        val ext = cleanPath.substringAfterLast('.', "").lowercase()
        return MediaCategory.values().firstOrNull { ext in it.supportedExtensions }
    }

    fun validateMediaUrl(rawUrl: String, selectedCategory: MediaCategory): UrlValidationResult {
        val extracted = extractUrlFromSharedText(rawUrl) ?: rawUrl.trim()
        if (extracted.isEmpty()) {
            return UrlValidationResult.Invalid("Cole ou compartilhe uma URL antes de iniciar o download.")
        }

        val uri = try {
            Uri.parse(extracted)
        } catch (e: Exception) {
            return UrlValidationResult.Invalid("Formato de URL inválido.")
        }

        val scheme = uri.scheme?.lowercase()
            ?: return UrlValidationResult.Invalid("A URL deve incluir https://.")

        if (scheme != "https" && scheme != "http") {
            return UrlValidationResult.Invalid("Esquema '$scheme://' não suportado.")
        }

        val host = uri.host?.lowercase()
            ?: return UrlValidationResult.Invalid("Host de origem não identificado na URL.")

        if (host == "localhost" || host.startsWith("127.") || host.startsWith("192.168.") || host.startsWith("10.")) {
            return UrlValidationResult.Invalid("Endereços locais ou de rede privada não são permitidos.")
        }

        val isPlatform = detectPlatform(extracted)
        val isAudioPlatform = audioOnlyDomains.any { host.contains(it) }
        val path = uri.path ?: ""
        val rawLastSegment = path.substringAfterLast('/')
        val detectedExt = rawLastSegment.substringAfterLast('.', "").lowercase()

        val allSupportedExtensions = MediaCategory.values().flatMap { it.supportedExtensions }.toSet()

        val resolvedCategory: MediaCategory
        val resolvedExt: String

        if (isAudioPlatform) {
            resolvedCategory = MediaCategory.AUDIO
            resolvedExt = "mp3"
        } else if (isPlatform) {
            resolvedCategory = selectedCategory
            resolvedExt = selectedCategory.defaultExtension
        } else if (detectedExt in allSupportedExtensions) {
            resolvedCategory = MediaCategory.values().first { detectedExt in it.supportedExtensions }
            resolvedExt = detectedExt
        } else {
            resolvedCategory = selectedCategory
            resolvedExt = selectedCategory.defaultExtension
        }

        val baseName = if (isPlatform || detectedExt !in allSupportedExtensions) {
            "midia_${host.replace("www.", "").replace("open.", "").substringBefore('.')}_${System.currentTimeMillis()}"
        } else {
            rawLastSegment
                .substringBeforeLast('.')
                .replace(Regex("[^a-zA-Z0-9_-]"), "_")
                .ifBlank { "arquivo_${resolvedCategory.name.lowercase()}" }
        }

        val finalFileName = "$baseName.$resolvedExt"
        val resolvedMime = extensionToMime[resolvedExt] ?: resolvedCategory.defaultMimeType
        val secureUrl = if (scheme == "http") extracted.replaceFirst("http://", "https://") else extracted

        return UrlValidationResult.Valid(
            normalizedUrl = secureUrl,
            host = host,
            suggestedFileName = finalFileName,
            extension = resolvedExt,
            mimeType = resolvedMime,
            category = resolvedCategory
        )
    }
}