package ir.abulix.psiphone

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread

class AbulixVpnService : VpnService() {

    companion object {
        const val ACTION_START = "ir.abulix.psiphone.START"
        const val ACTION_STOP = "ir.abulix.psiphone.STOP"

        @Volatile var state = "idle"      // idle | connecting | connected | error
        @Volatile var message = ""
        @Volatile var connectedAt = 0L
        @Volatile var rx = 0L
        @Volatile var tx = 0L
        @Volatile var rtt = -1L
        @Volatile var stability = 0
        @Volatile var exitIp = ""
        @Volatile var exitInfo = ""

        private val logBuf = StringBuilder()

        fun log(s: String) {
            synchronized(logBuf) {
                val t = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())
                logBuf.append(t).append("  ").append(s).append('\n')
                if (logBuf.length > 8000) logBuf.delete(0, logBuf.length - 5000)
            }
        }

        fun logText(): String = synchronized(logBuf) { logBuf.toString() }

        /** Reads the public exit IP through the tunnel (Cloudflare trace). */
        fun refreshIp() {
            thread {
                exitInfo = "در حال دریافت..."
                var found = false
                for (i in 0 until 8) {
                    try {
                        val hc = URL("https://www.cloudflare.com/cdn-cgi/trace").openConnection() as HttpURLConnection
                        hc.connectTimeout = 5000
                        hc.readTimeout = 5000
                        val t = hc.inputStream.bufferedReader().readText()
                        hc.disconnect()
                        var ip = ""
                        var loc = ""
                        var warp = ""
                        for (line in t.lines()) {
                            if (line.startsWith("ip=")) ip = line.substring(3).trim()
                            if (line.startsWith("loc=")) loc = line.substring(4).trim()
                            if (line.startsWith("warp=")) warp = line.substring(5).trim()
                        }
                        if (ip.isNotEmpty()) {
                            exitIp = ip
                            exitInfo = "کشور: $loc  |  WARP: $warp"
                            found = true
                            break
                        }
                    } catch (e: Exception) {
                    }
                    try {
                        Thread.sleep(1500)
                    } catch (e: Exception) {
                    }
                }
                if (!found) exitInfo = "دریافت نشد (برای تلاش دوباره لمس کنید)"
            }
        }
    }

    private data class Att(val host: String, val mode: Int, val sni: String)

    @Volatile private var running = false
    @Volatile private var conn: Http2Conn? = null
    @Volatile private var netConn: Net.Conn? = null
    @Volatile private var pfd: ParcelFileDescriptor? = null
    @Volatile private var tunOut: FileOutputStream? = null
    @Volatile private var pongs = 0
    @Volatile private var lastRtt = -1L
    private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopAll()
            state = "idle"
            message = "قطع شد"
            connectedAt = 0
            stopForeground(Service.STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        startFg()
        if (!running) {
            try {
                worker?.join(1500)
            } catch (e: Exception) {
            }
            running = true
            state = "connecting"
            message = ""
            rx = 0
            tx = 0
            rtt = -1
            stability = 0
            exitIp = ""
            exitInfo = ""
            worker = thread { runSession() }
        }
        return START_NOT_STICKY
    }

    private fun startFg() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("abulix", "Psiphone abulix", NotificationManager.IMPORTANCE_LOW))
        val n = Notification.Builder(this, "abulix")
            .setContentTitle("Psiphone abulix")
            .setContentText("VPN")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .build()
        startForeground(1, n)
    }

    private fun stopAll() {
        running = false
        try {
            conn?.close("stop")
        } catch (e: Exception) {
        }
        try {
            netConn?.close()
        } catch (e: Exception) {
        }
        try {
            pfd?.close()
        } catch (e: Exception) {
        }
        pfd = null
        tunOut = null
        conn = null
        netConn = null
    }

    override fun onRevoke() {
        stopAll()
        state = "idle"
        message = "VPN توسط سیستم قطع شد"
        super.onRevoke()
    }

    override fun onDestroy() {
        stopAll()
        super.onDestroy()
    }

    private fun closeQuiet() {
        try {
            conn?.close("retry")
        } catch (e: Exception) {
        }
        try {
            netConn?.close()
        } catch (e: Exception) {
        }
        conn = null
        netConn = null
    }

    /** Opens TCP + TLS(h2) + CONNECT-IP to one endpoint. Throws on any failure. */
    private fun openTunnel(host: String, port: Int, mode: Int, sni: String): Http2Conn {
        log("اتصال به $host:$port (${if (mode == 1) "frag" else "direct"} | $sni)")
        val nc = Net.open(host, port, sni, mode, { s -> protect(s) }, KeyHelper.sslContext(), 4000, 5000)
        netConn = nc
        val ssl = nc.ssl

        val c = Http2Conn(ssl)
        conn = c
        c.onPacket = { b, o, l ->
            try {
                tunOut?.write(b, o, l)
                rx += l
            } catch (e: Exception) {
            }
        }
        c.onPong = { r ->
            lastRtt = r
            pongs++
        }
        c.start()
        thread { c.runReader() }
        c.sendConnect(
            "cloudflareaccess.com", "cf-connect-ip",
            listOf("user-agent" to "WARP for Android", "capsule-protocol" to "?1")
        )
        val st = c.awaitStatus(8000)
        if (st == -1) throw Exception("پاسخی از سرور نیامد")
        if (st == -2) throw Exception("سرور اتصال را بست: ${c.closeReason}")
        if (st != 0 && st !in 200..299) throw Exception("سرور خطا داد: HTTP $st")
        log("تونل MASQUE باز شد (status=$st)")
        return c
    }

    private fun runSession() {
        try {
            val a4 = Store.get(this, "addr4")
            val a6 = Store.get(this, "addr6")
            if (a4.isEmpty() && a6.isEmpty()) throw Exception("کلید WARP ندارید؛ ابتدا دریافت کنید")
            val port = Store.get(this, "ep_port", "443").toIntOrNull() ?: 443
            val atts = ArrayList<Att>()
            fun add(h: String, m: Int, sni: String) {
                if (h.isNotEmpty() && atts.none { it.host == h && it.mode == m && it.sni == sni }) atts.add(Att(h, m, sni))
            }
            WarpApi.ensureEnabled(this) { log(it) }
            // scanned entries look like "ip@mode@sni"
            val scanned = ArrayList<Att>()
            for (x in Store.get(this, "ep_list").split(",")) {
                if (x.isEmpty()) continue
                val parts = x.split("@")
                val sIdx = (parts.getOrNull(2)?.toIntOrNull() ?: 0).coerceIn(0, 2)
                scanned.add(Att(parts[0], parts.getOrNull(1)?.toIntOrNull() ?: 1, Net.SNIS[sIdx]))
            }
            val first = Store.get(this, "ep_host")
            if (first.isNotEmpty() && scanned.none { it.host == first }) scanned.add(0, Att(first, 1, Net.SNI0))
            for (x in scanned.take(4)) add(x.host, x.mode, x.sni)
            // endpoints from an imported link
            for (h in listOf(Store.get(this, "imp_outer"), Store.get(this, "imp_inner"))) {
                add(h, 1, Net.SNI0)
                add(h, 0, Net.SNI0)
                add(h, 1, Net.SNI1)
            }
            val e4 = Store.get(this, "reg_ep4")
            val e6 = Store.get(this, "reg_ep6")
            for (sn in arrayOf(Net.SNI0, Net.SNI1)) {
                add(e4, 1, sn)
                add(e4, 0, sn)
            }
            add(e6, 1, Net.SNI0)
            for (x in scanned) {
                add(x.host, 1, Net.SNI0)
                add(x.host, 0, Net.SNI0)
                add(x.host, 1, Net.SNI1)
            }
            add("162.159.198.2", 1, Net.SNI0)
            add(e4, 1, Net.SNI2)
            if (atts.isEmpty()) throw Exception("کانفیگ ندارید؛ ابتدا اسکن کنید")

            var found: Http2Conn? = null
            var lastErr = "ناموفق"
            for (a in atts.take(12)) {
                if (!running) return
                try {
                    found = openTunnel(a.host, port, a.mode, a.sni)
                    break
                } catch (e: Exception) {
                    lastErr = e.message ?: "خطا"
                    log("${a.host} ناموفق: $lastErr")
                    closeQuiet()
                }
            }
            if (found == null && lastErr.contains("timed out")) {
                lastErr = "سرور پاسخ نداد (timeout). شبکه/اپراتور را عوض کنید و دوباره اسکن بزنید"
            }
            val c: Http2Conn = found ?: throw Exception(lastErr)
            if (!running) return

            val b = Builder()
            b.setSession("Psiphone abulix")
            b.setMtu(1280)
            if (a4.isNotEmpty()) b.addAddress(a4, 32) else b.addAddress("172.16.0.2", 32)
            if (a6.isNotEmpty()) b.addAddress(a6, 128) else b.addAddress("fd12:3456:789a::2", 128)
            b.addRoute("0.0.0.0", 0)
            b.addRoute("::", 0)
            b.addDnsServer("1.1.1.1")
            b.addDnsServer("1.0.0.1")
            if (a6.isNotEmpty()) b.addDnsServer("2606:4700:4700::1111")
            b.setBlocking(true)
            val p = b.establish() ?: throw Exception("ساخت VPN ناموفق بود (مجوز؟)")
            pfd = p
            val tunIn = FileInputStream(p.fileDescriptor)
            tunOut = FileOutputStream(p.fileDescriptor)
            if (!running) return

            state = "connected"
            connectedAt = System.currentTimeMillis()
            log("VPN وصل شد")
            refreshIp()

            thread {
                val buf = ByteArray(32768)
                try {
                    while (running && !c.closed) {
                        val n = tunIn.read(buf)
                        if (n < 0) break
                        if (n > 0) {
                            if (!c.sendPacket(buf, n)) break
                            tx += n
                        }
                    }
                } catch (e: Exception) {
                }
                if (running) c.close("خواندن از tun تمام شد")
            }

            // Stability monitor: PING over HTTP/2 every ~2.5s, keep last 20 samples.
            val samples = ArrayList<Long>()
            var fails = 0
            while (running && !c.closed) {
                val before = pongs
                c.sendPing()
                var waited = 0
                while (waited < 1500 && pongs == before && !c.closed && running) {
                    Thread.sleep(50)
                    waited += 50
                }
                if (pongs > before) {
                    samples.add(lastRtt)
                    fails = 0
                } else {
                    samples.add(-1L)
                    fails++
                }
                while (samples.size > 20) samples.removeAt(0)
                val ok = samples.filter { it >= 0 }
                val rate = if (samples.isEmpty()) 1.0 else ok.size.toDouble() / samples.size
                var jit = 0.0
                if (ok.size > 1) {
                    var sum = 0.0
                    for (i in 1 until ok.size) sum += Math.abs(ok[i] - ok[i - 1]).toDouble()
                    jit = sum / (ok.size - 1)
                }
                stability = (rate * 100.0 - minOf(40.0, jit * 0.8)).toInt().coerceIn(0, 100)
                rtt = if (ok.isNotEmpty()) ok[ok.size - 1] else -1L
                if (fails >= 5) throw Exception("اتصال پاسخ نمی‌دهد (ping timeout)")
                var s = 0
                while (s < 1000 && running && !c.closed) {
                    Thread.sleep(100)
                    s += 100
                }
            }
            if (running && c.closed) throw Exception("ارتباط با سرور بسته شد: ${c.closeReason}")
        } catch (e: Exception) {
            log("خطا: ${e.message}")
            if (running) {
                state = "error"
                message = e.message ?: "خطا"
            }
        } finally {
            val wasConnected = state == "connected"
            stopAll()
            if (state == "connected" || state == "connecting") {
                state = "idle"
                if (wasConnected) message = "اتصال قطع شد"
            }
            connectedAt = 0
            rtt = -1
            try {
                stopForeground(Service.STOP_FOREGROUND_REMOVE)
            } catch (e: Exception) {
            }
            stopSelf()
        }
    }
}
