package br.com.guardiaomobile.security

import java.io.InputStream
import java.security.MessageDigest

enum class SecurityStatus {
    AGUARDANDO_ANALISE,
    SEM_AMEACA_DETECTADA,
    SUSPEITO,
    AMEACA_DETECTADA,
    ANALISE_INCOMPLETA
}

data class FileAnalysisReport(
    val status: SecurityStatus,
    val sha256: String?,
    val detectedFormat: String,
    val sizeBytes: Long,
    val explanation: String,
    val isVideoFile: Boolean = false,
    val methodologyDisclaimer: String = "Verificação estática local (assinatura binária e hash SHA-256). " +
        "Esta análise é limitada e não substitui um antivírus completo."
)

class FileSecurityAnalyzer(
    private val knownMaliciousHashes: Set<String> = emptySet()
) {

    private val videoFormats = setOf(
        "ISO_BMFF_MP4_MOV_3GP",
        "MATROSKA_WEBM",
        "AVI_VIDEO",
        "FLV_VIDEO",
        "ASF_WMV_VIDEO",
        "MPEG_VIDEO_STREAM"
    )

    private val videoExtensions = setOf(
        "mp4", "mov", "m4v", "mkv", "webm", "avi", "flv", "3gp", "3g2", "wmv", "ts", "mts", "mpg", "mpeg", "ogv"
    )

    fun analyzeStream(
        inputStream: InputStream,
        declaredExtension: String,
        expectedSizeBytes: Long? = null
    ): FileAnalysisReport {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(8192)
            val headerBytes = ByteArray(16)
            var headerRead = 0
            var totalRead = 0L

            var bytesRead: Int
            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                if (headerRead < headerBytes.size) {
                    val toCopy = minOf(bytesRead, headerBytes.size - headerRead)
                    System.arraycopy(buffer, 0, headerBytes, headerRead, toCopy)
                    headerRead += toCopy
                }
                digest.update(buffer, 0, bytesRead)
                totalRead += bytesRead
            }

            if (totalRead == 0L) {
                return FileAnalysisReport(
                    status = SecurityStatus.SUSPEITO,
                    sha256 = null,
                    detectedFormat = "Vazio",
                    sizeBytes = 0L,
                    explanation = "O arquivo está vazio (0 bytes) ou o download foi interrompido.",
                    isVideoFile = false
                )
            }

            if (expectedSizeBytes != null && expectedSizeBytes > 0 && totalRead != expectedSizeBytes) {
                return FileAnalysisReport(
                    status = SecurityStatus.SUSPEITO,
                    sha256 = null,
                    detectedFormat = "Incompleto",
                    sizeBytes = totalRead,
                    explanation = "Tamanho do arquivo ($totalRead bytes) diverge do esperado ($expectedSizeBytes bytes).",
                    isVideoFile = false
                )
            }

            val sha256Hex = digest.digest().joinToString("") { "%02x".format(it) }
            val normalizedExt = declaredExtension.lowercase().trimStart('.')
            val detectedFormat = detectMagicFormat(headerBytes, headerRead)
            val isVideo = detectedFormat in videoFormats || normalizedExt in videoExtensions

            if (sha256Hex in knownMaliciousHashes) {
                return FileAnalysisReport(
                    status = SecurityStatus.AMEACA_DETECTADA,
                    sha256 = sha256Hex,
                    detectedFormat = detectedFormat,
                    sizeBytes = totalRead,
                    explanation = "O hash SHA-256 coincide com um indicador conhecido de ameaça.",
                    isVideoFile = false
                )
            }

            if (detectedFormat in setOf("ELF_EXECUTABLE", "PE_EXECUTABLE", "APK_OR_ZIP", "HTML_OR_TEXT")) {
                return FileAnalysisReport(
                    status = SecurityStatus.SUSPEITO,
                    sha256 = sha256Hex,
                    detectedFormat = detectedFormat,
                    sizeBytes = totalRead,
                    explanation = "Alerta: o arquivo possui assinatura binária ($detectedFormat) incompatível com mídia segura.",
                    isVideoFile = false
                )
            }

            val isFormatCompatible = isExtensionMatchingFormat(normalizedExt, detectedFormat)

            if (!isFormatCompatible && detectedFormat != "UNKNOWN_MEDIA_CONTAINER") {
                return FileAnalysisReport(
                    status = SecurityStatus.SUSPEITO,
                    sha256 = sha256Hex,
                    detectedFormat = detectedFormat,
                    sizeBytes = totalRead,
                    explanation = "A extensão declarada (.$normalizedExt) não corresponde à assinatura binária detectada ($detectedFormat).",
                    isVideoFile = isVideo
                )
            }

            FileAnalysisReport(
                status = SecurityStatus.SEM_AMEACA_DETECTADA,
                sha256 = sha256Hex,
                detectedFormat = detectedFormat,
                sizeBytes = totalRead,
                explanation = "Formato de mídia compatível e integridade verificada. Nenhum indicador básico de ameaça foi detectado.",
                isVideoFile = isVideo
            )
        } catch (e: Exception) {
            FileAnalysisReport(
                status = SecurityStatus.ANALISE_INCOMPLETA,
                sha256 = null,
                detectedFormat = "Desconhecido",
                sizeBytes = 0L,
                explanation = "Não foi possível concluir a leitura do arquivo: ${e.message ?: "erro de I/O"}.",
                isVideoFile = false
            )
        }
    }

    private fun detectMagicFormat(header: ByteArray, length: Int): String {
        if (length < 4) return "UNKNOWN_MEDIA_CONTAINER"

        if (header[0] == 0x4D.toByte() && header[1] == 0x5A.toByte()) return "PE_EXECUTABLE"

        if (header[0] == 0x7F.toByte() && header[1] == 0x45.toByte() &&
            header[2] == 0x4C.toByte() && header[3] == 0x46.toByte()
        ) return "ELF_EXECUTABLE"

        if (header[0] == 0x50.toByte() && header[1] == 0x4B.toByte() &&
            header[2] == 0x03.toByte() && header[3] == 0x04.toByte()
        ) return "APK_OR_ZIP"

        if (header[0] == 0x3C.toByte() && (header[1] == 0x21.toByte() || header[1] == 0x68.toByte() || header[1] == 0x48.toByte())) {
            return "HTML_OR_TEXT"
        }

        if (header[0] == 0x1A.toByte() && header[1] == 0x45.toByte() &&
            header[2] == 0xDF.toByte() && header[3] == 0xA3.toByte()
        ) return "MATROSKA_WEBM"

        if (length >= 8) {
            val boxType = String(header, 4, 4, Charsets.US_ASCII)
            if (boxType in setOf("ftyp", "moov", "mdat", "wide", "free", "skip", "pnot", "pict")) {
                return "ISO_BMFF_MP4_MOV_3GP"
            }
        }

        if (header[0] == 0x46.toByte() && header[1] == 0x4C.toByte() && header[2] == 0x56.toByte()) {
            return "FLV_VIDEO"
        }

        if (length >= 8 &&
            header[0] == 0x30.toByte() && header[1] == 0x26.toByte() &&
            header[2] == 0xB2.toByte() && header[3] == 0x75.toByte()
        ) return "ASF_WMV_VIDEO"

        if (header[0] == 0x47.toByte() ||
            (header[0] == 0x00.toByte() && header[1] == 0x00.toByte() && header[2] == 0x01.toByte())
        ) return "MPEG_VIDEO_STREAM"

        if (header[0] == 0x49.toByte() && header[1] == 0x44.toByte() && header[2] == 0x33.toByte()) {
            return "MP3_AUDIO"
        }
        if (header[0] == 0xFF.toByte() && (header[1].toInt() and 0xE0) == 0xE0) {
            return "MP3_AUDIO"
        }

        if (header[0] == 0x4F.toByte() && header[1] == 0x67.toByte() &&
            header[2] == 0x67.toByte() && header[3] == 0x53.toByte()
        ) return "OGG_MEDIA"

        if (header[0] == 0x66.toByte() && header[1] == 0x4C.toByte() &&
            header[2] == 0x61.toByte() && header[3] == 0x43.toByte()
        ) return "FLAC_AUDIO"

        if (header[0] == 0xFF.toByte() && header[1] == 0xD8.toByte() && header[2] == 0xFF.toByte()) {
            return "JPEG_IMAGE"
        }

        if (header[0] == 0x89.toByte() && header[1] == 0x50.toByte() &&
            header[2] == 0x4E.toByte() && header[3] == 0x47.toByte()
        ) return "PNG_IMAGE"

        if (length >= 12 &&
            header[0] == 0x52.toByte() && header[1] == 0x49.toByte() &&
            header[2] == 0x46.toByte() && header[3] == 0x46.toByte()
        ) {
            if (header[8] == 0x57.toByte() && header[9] == 0x41.toByte() &&
                header[10] == 0x56.toByte() && header[11] == 0x45.toByte()
            ) return "WAV_AUDIO"
            if (header[8] == 0x57.toByte() && header[9] == 0x45.toByte() &&
                header[10] == 0x42.toByte() && header[11] == 0x50.toByte()
            ) return "WEBP_IMAGE"
            if (header[8] == 0x41.toByte() && header[9] == 0x56.toByte() &&
                header[10] == 0x49.toByte() && header[11] == 0x20.toByte()
            ) return "AVI_VIDEO"
        }

        return "UNKNOWN_MEDIA_CONTAINER"
    }

    private fun isExtensionMatchingFormat(ext: String, format: String): Boolean {
        val allValidMediaFormats = videoFormats + setOf(
            "MP3_AUDIO",
            "WAV_AUDIO",
            "OGG_MEDIA",
            "FLAC_AUDIO",
            "JPEG_IMAGE",
            "PNG_IMAGE",
            "WEBP_IMAGE"
        )
        return when (ext) {
            in videoExtensions -> format in videoFormats || format == "OGG_MEDIA"
            "mp3", "m4a", "aac", "wav", "ogg", "opus", "flac" -> format in setOf(
                "MP3_AUDIO",
                "ISO_BMFF_MP4_MOV_3GP",
                "WAV_AUDIO",
                "OGG_MEDIA",
                "FLAC_AUDIO",
                "MATROSKA_WEBM"
            )
            "jpg", "jpeg", "png", "webp" -> format in setOf("JPEG_IMAGE", "PNG_IMAGE", "WEBP_IMAGE")
            else -> format in allValidMediaFormats
        }
    }
}