package br.com.guardiaomobile.adfilter

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.text.SimpleDateFormat
import java.util.Collections
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

enum class VpnCountry(
    val code: String,
    val displayName: String,
    val virtualIp: String,
    val virtualDns: String,
    val simulatedPublicIp: String,
    val ecsSubnetBytes: ByteArray
) {
    BRASIL(
        code = "BR",
        displayName = "Brasil",
        virtualIp = "10.10.1.1",
        virtualDns = "10.10.1.2",
        simulatedPublicIp = "177.54.144.1",
        ecsSubnetBytes = byteArrayOf(177.toByte(), 54.toByte(), 144.toByte(), 0.toByte())
    ),
    ESTADOS_UNIDOS(
        code = "US",
        displayName = "Estados Unidos",
        virtualIp = "10.20.1.1",
        virtualDns = "10.20.1.2",
        simulatedPublicIp = "104.244.42.1",
        ecsSubnetBytes = byteArrayOf(104.toByte(), 244.toByte(), 42.toByte(), 0.toByte())
    ),
    REINO_UNIDO(
        code = "GB",
        displayName = "Reino Unido",
        virtualIp = "10.30.1.1",
        virtualDns = "10.30.1.2",
        simulatedPublicIp = "81.2.69.142",
        ecsSubnetBytes = byteArrayOf(81.toByte(), 2.toByte(), 69.toByte(), 0.toByte())
    ),
    ALEMANHA(
        code = "DE",
        displayName = "Alemanha",
        virtualIp = "10.40.1.1",
        virtualDns = "10.40.1.2",
        simulatedPublicIp = "141.1.1.1",
        ecsSubnetBytes = byteArrayOf(141.toByte(), 1.toByte(), 1.toByte(), 0.toByte())
    ),
    JAPAO(
        code = "JP",
        displayName = "Japão",
        virtualIp = "10.50.1.1",
        virtualDns = "10.50.1.2",
        simulatedPublicIp = "210.140.92.1",
        ecsSubnetBytes = byteArrayOf(210.toByte(), 140.toByte(), 92.toByte(), 0.toByte())
    ),
    SUICA(
        code = "CH",
        displayName = "Suíça",
        virtualIp = "10.60.1.1",
        virtualDns = "10.60.1.2",
        simulatedPublicIp = "185.159.157.1",
        ecsSubnetBytes = byteArrayOf(185.toByte(), 159.toByte(), 157.toByte(), 0.toByte())
    );

    companion object {
        fun fromCode(code: String?): VpnCountry {
            return values().firstOrNull { it.code.equals(code, ignoreCase = true) } ?: BRASIL
        }
    }
}

data class NetworkThreatAlert(
    val id: String,
    val targetHostOrIp: String,
    val category: String,
    val description: String,
    val timeFormatted: String
)

class LocalAdBlockerVpnService : VpnService() {

    @Volatile
    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var readerThread: Thread? = null
    private var lastAlertEpochMs: Long = 0L

    private val dynamicBlockedHosts: MutableSet<String> = Collections.newSetFromMap(ConcurrentHashMap())

    private val staticDnsResolver = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            return when (hostname.lowercase()) {
                "dns.adguard-dns.com" -> listOf(
                    InetAddress.getByAddress(byteArrayOf(94.toByte(), 140.toByte(), 14.toByte(), 14.toByte())),
                    InetAddress.getByAddress(byteArrayOf(94.toByte(), 140.toByte(), 15.toByte(), 15.toByte()))
                )
                "security.cloudflare-dns.com" -> listOf(
                    InetAddress.getByAddress(byteArrayOf(1.toByte(), 1.toByte(), 1.toByte(), 2.toByte())),
                    InetAddress.getByAddress(byteArrayOf(1.toByte(), 0.toByte(), 0.toByte(), 2.toByte()))
                )
                "raw.githubusercontent.com" -> listOf(
                    InetAddress.getByAddress(byteArrayOf(185.toByte(), 199.toByte(), 108.toByte(), 133.toByte())),
                    InetAddress.getByAddress(byteArrayOf(185.toByte(), 199.toByte(), 109.toByte(), 133.toByte()))
                )
                else -> Dns.SYSTEM.lookup(hostname)
            }
        }
    }

    private val okHttpClient = OkHttpClient.Builder()
        .dns(staticDnsResolver)
        .connectTimeout(2000, TimeUnit.MILLISECONDS)
        .readTimeout(2000, TimeUnit.MILLISECONDS)
        .retryOnConnectionFailure(false)
        .build()

    private val blockedAdSuffixes = setOf(
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "adservice.google.com", "pagead2.googlesyndication.com", "adnxs.com",
        "adsrvr.org", "criteo.com", "criteo.net", "taboola.com", "outbrain.com",
        "adcolony.com", "applovin.com", "applvn.com", "unityads.unity3d.com",
        "vungle.com", "chartboost.com", "mopub.com", "inmobi.com", "ironsrc.com",
        "supersonicads.com", "startappservice.com", "ads.tiktok.com",
        "analytics.tiktok.com", "ads-api.twitter.com", "an.facebook.com",
        "pixel.facebook.com", "adform.net", "pubmatic.com", "rubiconproject.com",
        "openx.net", "smartadserver.com", "moatads.com", "scorecardresearch.com",
        "quantserve.com", "zedo.com", "admob.com", "ads.yahoo.com",
        "advertising.com", "amazonaax.com", "amazon-adsystem.com",
        "appsflyer.com", "rayjump.com", "mintegral.com", "mintegral.net",
        "pangle.io", "pglstatp-toutiao.com", "fyber.com", "inner-active.mobi",
        "smaato.net", "smaato.com", "ssp.yahoo.com", "flurry.com",
        "kochava.com", "adjust.com", "branch.io", "singular.net",
        "bidmachine.io", "omtrdc.net", "demdex.net", "2o7.net",
        "yandexadexchange.net", "ads.oppomobile.com", "ad.xiaomi.com",
        "sdkconfig.ad.xiaomi.com", "tracking.miui.com", "data.mistat.xiaomi.com",
        "samsungads.com", "smetrics.samsung.com", "nmetrics.samsung.com",
        "ad.samsungadhub.com", "config.samsungads.com"
    )

    private val malvertisingAndVirusDomains = setOf(
        "popads.net", "popcash.net", "propellerads.com", "adcash.com",
        "exoclick.com", "juicyads.com", "trafficjunky.net", "hilltopads.net",
        "clickadu.com", "adsterra.com", "admaven.com", "richpush.co",
        "pushwelcome.com", "pushengage.com", "megapush.com", "evadav.com",
        "coinhive.com", "crypto-loot.com", "cryptoloot.pro", "minero.cc",
        "webmine.cz", "jsecoin.com", "authedmine.com", "ppoi.org",
        "load.jsecoin.com", "miner.pr0gramm.com", "onclickads.net",
        "adf.ly", "bc.vc", "ouo.io", "shorte.st", "sh.st",
        "malware-check.disconnect.me", "bananaclicker.com", "bet365affiliates.com"
    )

    private val suspiciousRemoteTunnelDomains = setOf(
        "ngrok.io", "ngrok-free.app", "ngrok.app", "duckdns.org",
        "no-ip.org", "no-ip.biz", "no-ip.info", "ddns.net",
        "hopto.org", "zapto.org", "sytes.net", "serveo.net",
        "localtunnel.me", "trycloudflare.com", "portmap.io",
        "playit.gg", "pastebin.com", "iplogger.org", "grabify.link",
        "2no.co", "blasze.com", "blasze.tk"
    )

    private val suspiciousMalwarePorts = setOf(4444, 5555, 1337, 6667, 6697, 3333, 14444, 31337)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val prefs = getSharedPreferences("guardiao_prefs", Context.MODE_PRIVATE)
        if (intent?.action == ACTION_STOP) {
            prefs.edit().putBoolean(PREF_VPN_ENABLED, false).apply()
            VpnWatchdogWorker.cancel(this)
            stopVpn()
            return START_NOT_STICKY
        }

        val requestedCountryCode = intent?.getStringExtra(EXTRA_COUNTRY_CODE)
            ?: prefs.getString(PREF_VPN_COUNTRY, VpnCountry.BRASIL.code)
        val newCountry = VpnCountry.fromCode(requestedCountryCode)
        val countryChanged = _activeCountry.value != newCountry
        _activeCountry.value = newCountry

        prefs.edit()
            .putBoolean(PREF_VPN_ENABLED, true)
            .putString(PREF_VPN_COUNTRY, newCountry.code)
            .apply()

        VpnWatchdogWorker.schedule(this)
        ensureAlertNotificationChannel()
        startForegroundSafely(newCountry)

        serviceScope.launch {
            loadAndSyncHostBlocklist()
        }
        serviceScope.launch {
            if (countryChanged && vpnInterface != null) {
                restartTunnelForNewCountry(newCountry)
            } else {
                startVpnTunnel(newCountry)
            }
        }
        return START_STICKY
    }

    private fun restartTunnelForNewCountry(country: VpnCountry) {
        try {
            vpnInterface?.close()
        } catch (e: Throwable) {
        }
        vpnInterface = null
        try {
            readerThread?.interrupt()
        } catch (e: Throwable) {
        }
        readerThread = null
        startVpnTunnel(country)
    }

    private fun loadAndSyncHostBlocklist() {
        val cacheFile = File(filesDir, "hosts_blocklist.txt")
        if (cacheFile.exists()) {
            try {
                cacheFile.useLines { lines ->
                    lines.forEach { line ->
                        val clean = line.trim().lowercase()
                        if (clean.isNotEmpty() && !clean.startsWith("#")) {
                            dynamicBlockedHosts.add(clean)
                        }
                    }
                }
            } catch (e: Exception) {
            }
        }

        val listUrls = listOf(
            "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
        )
        for (url in listUrls) {
            try {
                val req = Request.Builder().url(url).get().build()
                okHttpClient.newCall(req).execute().use { resp ->
                    if (resp.isSuccessful) {
                        val body = resp.body?.string() ?: return@use
                        val parsed = HashSet<String>()
                        body.lineSequence().forEach { rawLine ->
                            val line = rawLine.substringBefore('#').trim()
                            if (line.startsWith("0.0.0.0 ") || line.startsWith("127.0.0.1 ")) {
                                val parts = line.split(Regex("\\s+"))
                                if (parts.size >= 2) {
                                    val host = parts[1].trim().lowercase()
                                    if (host != "localhost" && host != "0.0.0.0" && host.contains('.')) {
                                        parsed.add(host)
                                    }
                                }
                            }
                        }
                        if (parsed.isNotEmpty()) {
                            dynamicBlockedHosts.addAll(parsed)
                            cacheFile.writeText(parsed.joinToString("\n"))
                            return
                        }
                    }
                }
            } catch (e: Exception) {
            }
        }
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        val prefs = getSharedPreferences("guardiao_prefs", Context.MODE_PRIVATE)
        if (prefs.getBoolean(PREF_VPN_ENABLED, false)) {
            scheduleImmediateRestart()
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onRevoke() {
        val prefs = getSharedPreferences("guardiao_prefs", Context.MODE_PRIVATE)
        prefs.edit().putBoolean(PREF_VPN_ENABLED, false).apply()
        VpnWatchdogWorker.cancel(this)
        stopVpn()
        super.onRevoke()
    }

    private fun scheduleImmediateRestart() {
        try {
            val restartIntent = Intent(applicationContext, VpnBootReceiver::class.java).apply {
                action = "br.com.guardiaomobile.RESTART_VPN"
            }
            val pendingIntent = PendingIntent.getBroadcast(
                applicationContext,
                1002,
                restartIntent,
                PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE
            )
            val alarmManager = getSystemService(Context.ALARM_SERVICE) as? AlarmManager
            alarmManager?.setExactAndAllowWhileIdle(
                AlarmManager.ELAPSED_REALTIME_WAKEUP,
                SystemClock.elapsedRealtime() + 2000L,
                pendingIntent
            )
        } catch (e: Throwable) {
        }
    }

    private fun ensureAlertNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java) ?: return
            val alertChannel = NotificationChannel(
                ALERT_CHANNEL_ID,
                "Alertas de Ameaças e Conexões Suspeitas",
                NotificationManager.IMPORTANCE_HIGH
            )
            manager.createNotificationChannel(alertChannel)
        }
    }

    private fun recordAndNotifyThreat(hostOrIp: String, category: String, description: String) {
        val now = System.currentTimeMillis()
        val timeStr = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(now))
        val alert = NetworkThreatAlert(
            id = "${now}_$hostOrIp",
            targetHostOrIp = hostOrIp,
            category = category,
            description = description,
            timeFormatted = timeStr
        )
        _threatAlerts.value = (listOf(alert) + _threatAlerts.value).take(50)

        if (now - lastAlertEpochMs < 8000L) return
        lastAlertEpochMs = now

        try {
            val manager = getSystemService(NotificationManager::class.java) ?: return
            val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Notification.Builder(this, ALERT_CHANNEL_ID)
            } else {
                @Suppress("DEPRECATION")
                Notification.Builder(this)
            }
            val notification = builder
                .setContentTitle("Alerta de Segurança: $category")
                .setContentText("Bloqueado: $hostOrIp — $description")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setAutoCancel(true)
                .build()

            manager.notify((now % 10000).toInt() + 2000, notification)
        } catch (e: Throwable) {
        }
    }

    private fun startForegroundSafely(country: VpnCountry) {
        try {
            val channelId = "guardiao_vpn_channel"
            val manager = getSystemService(NotificationManager::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && manager != null) {
                val channel = NotificationChannel(
                    channelId,
                    "Bloqueador de Anúncios 24h",
                    NotificationManager.IMPORTANCE_LOW
                )
                manager.createNotificationChannel(channel)
            }
            val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Notification.Builder(this, channelId)
            } else {
                @Suppress("DEPRECATION")
                Notification.Builder(this)
            }
            val notification = builder
                .setContentTitle("Guardião Antivírus & VPN (${country.displayName})")
                .setContentText("Proteção ativa contra malvertising e conexões suspeitas")
                .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
                .setOngoing(true)
                .build()

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(1001, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(1001, notification)
            }
        } catch (e: Throwable) {
        }
    }

    private fun startVpnTunnel(country: VpnCountry) {
        if (vpnInterface != null) return
        try {
            val builder = Builder()
                .setSession("Guardião Antivírus VPN (${country.displayName})")
                .setMtu(1400)
                .addAddress(country.virtualIp, 24)
                .addDnsServer(country.virtualDns)
                .addRoute(country.virtualDns, 32)
                .addAddress(VPN_CLIENT_IPV6, 128)
                .addDnsServer(VPN_VIRTUAL_DNS_IPV6)
                .addRoute(VPN_VIRTUAL_DNS_IPV6, 128)
                .setBlocking(true)

            val publicDnsIps = listOf(
                "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"
            )
            for (ip in publicDnsIps) {
                try {
                    builder.addRoute(ip, 32)
                } catch (e: Exception) {
                }
            }

            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
            }

            val established = builder.establish()
            if (established != null) {
                vpnInterface = established
                _isRunning.value = true
                readerThread = Thread({
                    runDnsInterceptorLoop(established)
                }, "GuardiaoVpnReader").apply {
                    isDaemon = true
                    start()
                }
            } else {
                stopVpn()
            }
        } catch (e: Throwable) {
            stopVpn()
        }
    }

    private fun runDnsInterceptorLoop(pfd: ParcelFileDescriptor) {
        val inputStream = FileInputStream(pfd.fileDescriptor)
        val outputStream = FileOutputStream(pfd.fileDescriptor)
        val packetBuffer = ByteArray(32767)

        try {
            while (_isRunning.value && vpnInterface != null) {
                val length = inputStream.read(packetBuffer)
                if (length <= 0) continue

                val packet = packetBuffer.copyOfRange(0, length)
                val version = (packet[0].toInt() ushr 4) and 0x0F

                var ihl = 0
                var protocol = 0
                if (version == 4) {
                    if (length < 28) continue
                    ihl = (packet[0].toInt() and 0x0F) * 4
                    protocol = packet[9].toInt() and 0xFF
                } else if (version == 6) {
                    if (length < 48) continue
                    ihl = 40
                    protocol = packet[6].toInt() and 0xFF
                } else {
                    continue
                }

                if (length < ihl + 8) continue
                val destPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or
                    (packet[ihl + 3].toInt() and 0xFF)

                if (destPort in suspiciousMalwarePorts) {
                    _blockedCount.value = _blockedCount.value + 1
                    recordAndNotifyThreat(
                        hostOrIp = "Porta $destPort",
                        category = "Conexão Remota Suspeita",
                        description = "Tentativa de conexão em porta usada por controle remoto/trojan ($destPort) bloqueada."
                    )
                    continue
                }

                if (protocol != 17 || destPort != 53) continue

                val dnsOffset = ihl + 8
                val dnsLength = length - dnsOffset
                if (dnsLength <= 12) continue

                val dnsPayload = packet.copyOfRange(dnsOffset, length)
                val parsedQuery = parseDnsQuery(dnsPayload)

                if (parsedQuery != null) {
                    val threatClassification = classifyDomainThreat(parsedQuery.domain)
                    if (threatClassification != null) {
                        _blockedCount.value = _blockedCount.value + 1
                        if (threatClassification.shouldAlertUser) {
                            recordAndNotifyThreat(
                                hostOrIp = parsedQuery.domain,
                                category = threatClassification.category,
                                description = threatClassification.reason
                            )
                        }
                        val blockedDnsResponse = buildBlockedDnsResponse(dnsPayload, parsedQuery)
                        val responsePacket = if (version == 4) {
                            buildIpv4UdpResponsePacket(packet, ihl, blockedDnsResponse)
                        } else {
                            buildIpv6UdpResponsePacket(packet, blockedDnsResponse)
                        }
                        synchronized(outputStream) {
                            outputStream.write(responsePacket)
                            outputStream.flush()
                        }
                        continue
                    }
                }

                serviceScope.launch {
                    try {
                        val geoQuery = if (parsedQuery != null) {
                            injectEdnsClientSubnet(dnsPayload, parsedQuery, _activeCountry.value)
                        } else {
                            dnsPayload
                        }
                        val upstreamResponse = resolveUpstreamDns(geoQuery) ?: resolveUpstreamDns(dnsPayload)
                        if (upstreamResponse != null) {
                            if (isSinkholeResponse(upstreamResponse)) {
                                _blockedCount.value = _blockedCount.value + 1
                                if (parsedQuery != null) {
                                    recordAndNotifyThreat(
                                        hostOrIp = parsedQuery.domain,
                                        category = "Ameaça / Anúncio Malicioso",
                                        description = "Domínio neutralizado pelo filtro de segurança contra malware e anúncios."
                                    )
                                }
                            }
                            val responsePacket = if (version == 4) {
                                buildIpv4UdpResponsePacket(packet, ihl, upstreamResponse)
                            } else {
                                buildIpv6UdpResponsePacket(packet, upstreamResponse)
                            }
                            synchronized(outputStream) {
                                outputStream.write(responsePacket)
                                outputStream.flush()
                            }
                        }
                    } catch (e: Throwable) {
                    }
                }
            }
        } catch (e: Throwable) {
        } finally {
            if (_isRunning.value) {
                stopVpn()
            }
        }
    }

    private data class ThreatClassification(
        val category: String,
        val reason: String,
        val shouldAlertUser: Boolean
    )

    private fun classifyDomainThreat(domain: String): ThreatClassification? {
        val clean = domain.trimEnd('.').lowercase()

        if (malvertisingAndVirusDomains.any { clean == it || clean.endsWith(".$it") }) {
            return ThreatClassification(
                category = "Anúncio com Vírus (Malvertising)",
                reason = "Rede de pop-up malicioso, script de mineração ou distribuição de malware bloqueada.",
                shouldAlertUser = true
            )
        }

        if (suspiciousRemoteTunnelDomains.any { clean == it || clean.endsWith(".$it") }) {
            return ThreatClassification(
                category = "Pedido de Conexão Suspeito",
                reason = "Tentativa de comunicação com túnel remoto / DNS dinâmico frequentemente usado por spywares.",
                shouldAlertUser = true
            )
        }

        if (clean.contains("xn--") ||
            clean.endsWith(".tk") || clean.endsWith(".ml") ||
            clean.endsWith(".cf") || clean.endsWith(".gq") ||
            (clean.contains("login") && (clean.endsWith(".top") || clean.endsWith(".xyz") || clean.endsWith(".icu")))
        ) {
            return ThreatClassification(
                category = "Domínio de Phishing / Fraude",
                reason = "Domínio camuflado ou de alto risco bloqueado antes de estabelecer conexão.",
                shouldAlertUser = true
            )
        }

        if (clean in dynamicBlockedHosts) {
            return ThreatClassification(
                category = "Anúncio / Rastreador",
                reason = "Domínio bloqueado pela lista de proteção.",
                shouldAlertUser = false
            )
        }

        if (clean.startsWith("ads.") || clean.startsWith("ad.") ||
            clean.startsWith("adserver.") || clean.startsWith("telemetry.") ||
            clean.startsWith("tracking.") || clean.startsWith("metrics.") ||
            clean.startsWith("banners.") || clean.startsWith("pagead.") ||
            clean.contains(".ads.") || clean.contains(".adserver.") ||
            clean.contains(".doubleclick.") || clean.contains("-ads.") ||
            clean.contains("adsystem") || clean.contains("googlesyndication")
        ) {
            return ThreatClassification(
                category = "Anúncio / Telemetria",
                reason = "Servidor de publicidade ou rastreamento bloqueado.",
                shouldAlertUser = false
            )
        }

        var current = clean
        while (current.contains('.')) {
            if (current in blockedAdSuffixes || current in dynamicBlockedHosts) {
                return ThreatClassification(
                    category = "Rede de Anúncios",
                    reason = "Domínio de publicidade bloqueado.",
                    shouldAlertUser = false
                )
            }
            current = current.substringAfter('.')
        }

        return null
    }

    private fun injectEdnsClientSubnet(
        originalQuery: ByteArray,
        parsed: ParsedDnsQuery,
        country: VpnCountry
    ): ByteArray {
        return try {
            val out = ByteArrayOutputStream(parsed.questionEndOffset + 24)
            out.write(originalQuery, 0, 10)
            out.write(0x00)
            out.write(0x01)
            out.write(originalQuery, 12, parsed.questionEndOffset - 12)

            val ecsRecord = byteArrayOf(
                0x00,
                0x00, 0x29,
                0x05, 0xDC.toByte(),
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x0B,
                0x00, 0x08,
                0x00, 0x07,
                0x00, 0x01,
                0x18,
                0x00,
                country.ecsSubnetBytes[0],
                country.ecsSubnetBytes[1],
                country.ecsSubnetBytes[2]
            )
            out.write(ecsRecord)
            out.toByteArray()
        } catch (e: Exception) {
            originalQuery
        }
    }

    private data class ParsedDnsQuery(
        val domain: String,
        val qType: Int,
        val questionEndOffset: Int
    )

    private fun parseDnsQuery(dnsPayload: ByteArray): ParsedDnsQuery? {
        return try {
            var pos = 12
            val labels = mutableListOf<String>()
            while (pos < dnsPayload.size) {
                val len = dnsPayload[pos].toInt() and 0xFF
                if (len == 0) {
                    pos++
                    break
                }
                if ((len and 0xC0) == 0xC0) return null
                pos++
                if (pos + len > dnsPayload.size) return null
                val label = String(dnsPayload, pos, len, Charsets.UTF_8)
                labels.add(label)
                pos += len
            }
            if (labels.isEmpty() || pos + 4 > dnsPayload.size) return null
            val qType = ((dnsPayload[pos].toInt() and 0xFF) shl 8) or (dnsPayload[pos + 1].toInt() and 0xFF)
            val questionEnd = pos + 4
            ParsedDnsQuery(
                domain = labels.joinToString(".").lowercase(),
                qType = qType,
                questionEndOffset = questionEnd
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun buildBlockedDnsResponse(query: ByteArray, parsed: ParsedDnsQuery): ByteArray {
        val out = ByteArrayOutputStream(parsed.questionEndOffset + 32)
        val questionSection = query.copyOfRange(12, parsed.questionEndOffset)

        val isTypeA = parsed.qType == 1
        val isTypeAAAA = parsed.qType == 28
        val hasAnswer = isTypeA || isTypeAAAA

        out.write(query[0].toInt())
        out.write(query[1].toInt())
        out.write(0x81)
        out.write(0x80)
        out.write(0x00)
        out.write(0x01)
        out.write(0x00)
        out.write(if (hasAnswer) 0x01 else 0x00)
        out.write(0x00)
        out.write(0x00)
        out.write(0x00)
        out.write(0x00)

        out.write(questionSection)

        if (isTypeA) {
            out.write(
                byteArrayOf(
                    0xC0.toByte(), 0x0C.toByte(),
                    0x00, 0x01,
                    0x00, 0x01,
                    0x00, 0x00, 0x01, 0x2C,
                    0x00, 0x04,
                    0x00, 0x00, 0x00, 0x00
                )
            )
        } else if (isTypeAAAA) {
            out.write(
                byteArrayOf(
                    0xC0.toByte(), 0x0C.toByte(),
                    0x00, 0x1C,
                    0x00, 0x01,
                    0x00, 0x00, 0x01, 0x2C,
                    0x00, 0x10,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                )
            )
        }

        return out.toByteArray()
    }

    private fun resolveUpstreamDns(dnsQuery: ByteArray): ByteArray? {
        val adGuardAndSecurityUdpIps = listOf(
            byteArrayOf(94.toByte(), 140.toByte(), 14.toByte(), 14.toByte()),
            byteArrayOf(94.toByte(), 140.toByte(), 15.toByte(), 15.toByte()),
            byteArrayOf(1.toByte(), 1.toByte(), 1.toByte(), 2.toByte())
        )
        for (ipBytes in adGuardAndSecurityUdpIps) {
            val udpResp = queryUdpServer(dnsQuery, ipBytes, 900)
            if (udpResp != null) return udpResp
        }

        val dohResp = queryDoHServer(dnsQuery)
        if (dohResp != null) return dohResp

        val fallbackUdpIps = listOf(
            byteArrayOf(1, 1, 1, 1),
            byteArrayOf(8, 8, 8, 8)
        )
        for (ipBytes in fallbackUdpIps) {
            val udpResp = queryUdpServer(dnsQuery, ipBytes, 1200)
            if (udpResp != null) return udpResp
        }
        return null
    }

    private fun queryUdpServer(dnsQuery: ByteArray, serverIpBytes: ByteArray, timeoutMs: Int): ByteArray? {
        var socket: DatagramSocket? = null
        return try {
            socket = DatagramSocket()
            if (!protect(socket)) return null
            socket.soTimeout = timeoutMs
            val address = InetAddress.getByAddress(serverIpBytes)
            val outPacket = DatagramPacket(dnsQuery, dnsQuery.size, address, 53)
            socket.send(outPacket)

            val receiveBuf = ByteArray(1500)
            val inPacket = DatagramPacket(receiveBuf, receiveBuf.size)
            socket.receive(inPacket)
            receiveBuf.copyOfRange(0, inPacket.length)
        } catch (e: Exception) {
            null
        } finally {
            try {
                socket?.close()
            } catch (e: Exception) {
            }
        }
    }

    private fun queryDoHServer(dnsQuery: ByteArray): ByteArray? {
        val requestBody = dnsQuery.toRequestBody("application/dns-message".toMediaType())
        val dohUrls = listOf(
            "https://dns.adguard-dns.com/dns-query",
            "https://security.cloudflare-dns.com/dns-query"
        )
        for (url in dohUrls) {
            val request = Request.Builder()
                .url(url)
                .header("Accept", "application/dns-message")
                .post(requestBody)
                .build()
            try {
                okHttpClient.newCall(request).execute().use { response ->
                    if (response.isSuccessful) {
                        val bytes = response.body?.bytes()
                        if (bytes != null && bytes.size >= 12) return bytes
                    }
                }
            } catch (e: Exception) {
            }
        }
        return null
    }

    private fun isSinkholeResponse(dnsResponse: ByteArray): Boolean {
        if (dnsResponse.size < 16) return false
        val rcode = dnsResponse[3].toInt() and 0x0F
        if (rcode == 3) return true
        val ancount = ((dnsResponse[6].toInt() and 0xFF) shl 8) or (dnsResponse[7].toInt() and 0xFF)
        if (ancount > 0 && dnsResponse.size >= 16) {
            val last4 = dnsResponse.takeLast(4)
            if (last4.size == 4 && last4.all { it == 0.toByte() }) return true
        }
        return false
    }

    private fun buildIpv4UdpResponsePacket(
        requestPacket: ByteArray,
        ihl: Int,
        dnsResponse: ByteArray
    ): ByteArray {
        val udpLength = 8 + dnsResponse.size
        val totalLength = 20 + udpLength
        val buffer = ByteBuffer.allocate(totalLength)

        buffer.put(0x45.toByte())
        buffer.put(0x00.toByte())
        buffer.putShort(totalLength.toShort())
        buffer.putShort(1.toShort())
        buffer.putShort(0x4000.toShort())
        buffer.put(64.toByte())
        buffer.put(17.toByte())
        buffer.putShort(0.toShort())

        buffer.put(requestPacket, 16, 4)
        buffer.put(requestPacket, 12, 4)

        val ipHeaderBytes = buffer.array()
        val checksum = computeIpv4Checksum(ipHeaderBytes, 20)
        buffer.putShort(10, checksum)

        val srcPort = ((requestPacket[ihl].toInt() and 0xFF) shl 8) or
            (requestPacket[ihl + 1].toInt() and 0xFF)
        val dstPort = ((requestPacket[ihl + 2].toInt() and 0xFF) shl 8) or
            (requestPacket[ihl + 3].toInt() and 0xFF)

        buffer.position(20)
        buffer.putShort(dstPort.toShort())
        buffer.putShort(srcPort.toShort())
        buffer.putShort(udpLength.toShort())
        buffer.putShort(0.toShort())
        buffer.put(dnsResponse)

        return buffer.array()
    }

    private fun buildIpv6UdpResponsePacket(requestPacket: ByteArray, dnsResponse: ByteArray): ByteArray {
        val udpLength = 8 + dnsResponse.size
        val totalLength = 40 + udpLength
        val buffer = ByteBuffer.allocate(totalLength)

        buffer.put(requestPacket, 0, 4)
        buffer.putShort(udpLength.toShort())
        buffer.put(17.toByte())
        buffer.put(64.toByte())

        val srcIp = requestPacket.copyOfRange(8, 24)
        val dstIp = requestPacket.copyOfRange(24, 40)
        buffer.put(dstIp)
        buffer.put(srcIp)

        val srcPort = ((requestPacket[40].toInt() and 0xFF) shl 8) or (requestPacket[41].toInt() and 0xFF)
        val dstPort = ((requestPacket[42].toInt() and 0xFF) shl 8) or (requestPacket[43].toInt() and 0xFF)
        buffer.putShort(dstPort.toShort())
        buffer.putShort(srcPort.toShort())
        buffer.putShort(udpLength.toShort())
        buffer.putShort(0.toShort())
        buffer.put(dnsResponse)

        val packet = buffer.array()
        var sum = 0

        for (i in 8 until 40 step 2) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
        }
        sum += (udpLength ushr 16) and 0xFFFF
        sum += udpLength and 0xFFFF
        sum += 17

        for (i in 40 until packet.size - 1 step 2) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
        }
        if (packet.size % 2 != 0) {
            sum += (packet.last().toInt() and 0xFF) shl 8
        }

        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        var checksum = (sum.inv() and 0xFFFF).toShort()
        if (checksum == 0.toShort()) checksum = 0xFFFF.toShort()

        buffer.position(46)
        buffer.putShort(checksum)

        return buffer.array()
    }

    private fun computeIpv4Checksum(header: ByteArray, length: Int): Short {
        var sum = 0
        var i = 0
        while (i < length) {
            if (i != 10) {
                val word = ((header[i].toInt() and 0xFF) shl 8) or (header[i + 1].toInt() and 0xFF)
                sum += word
            }
            i += 2
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toShort()
    }

    private fun stopVpn() {
        _isRunning.value = false
        try {
            vpnInterface?.close()
        } catch (e: Throwable) {
        }
        vpnInterface = null
        try {
            readerThread?.interrupt()
        } catch (e: Throwable) {
        }
        readerThread = null
        try {
            stopForeground(true)
        } catch (e: Throwable) {
        }
        stopSelf()
    }

    override fun onDestroy() {
        val prefs = getSharedPreferences("guardiao_prefs", Context.MODE_PRIVATE)
        val shouldStayActive = prefs.getBoolean(PREF_VPN_ENABLED, false)
        stopVpn()
        serviceScope.cancel()
        if (shouldStayActive) {
            scheduleImmediateRestart()
        }
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "STOP"
        const val EXTRA_COUNTRY_CODE = "EXTRA_COUNTRY_CODE"
        const val PREF_VPN_ENABLED = "vpn_24h_enabled"
        const val PREF_VPN_COUNTRY = "vpn_country_code"
        private const val ALERT_CHANNEL_ID = "guardiao_security_alerts"
        private const val VPN_CLIENT_IPV6 = "fd00:1:fd00:1:fd00:1:fd00:1"
        private const val VPN_VIRTUAL_DNS_IPV6 = "fd00:1:fd00:1:fd00:1:fd00:2"

        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

        private val _blockedCount = MutableStateFlow(0)
        val blockedCount: StateFlow<Int> = _blockedCount.asStateFlow()

        private val _activeCountry = MutableStateFlow(VpnCountry.BRASIL)
        val activeCountry: StateFlow<VpnCountry> = _activeCountry.asStateFlow()

        private val _threatAlerts = MutableStateFlow<List<NetworkThreatAlert>>(emptyList())
        val threatAlerts: StateFlow<List<NetworkThreatAlert>> = _threatAlerts.asStateFlow()

        fun clearThreatAlerts() {
            _threatAlerts.value = emptyList()
        }

        fun startServiceCompat(context: Context, country: VpnCountry? = null) {
            val intent = Intent(context, LocalAdBlockerVpnService::class.java).apply {
                if (country != null) {
                    putExtra(EXTRA_COUNTRY_CODE, country.code)
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }
}