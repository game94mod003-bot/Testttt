package ir.abulix.psiphone

import android.content.Context
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLContext

/**
 * Scanner for Cloudflare WARP MASQUE endpoints. An IP only counts when the real TLS handshake
 * (client certificate + ALPN h2) succeeds. When a WARP key exists, the CONNECT-IP stream is opened too.
 *
 * level 1 = TLS + h2 ok, level 2 = server announces extended CONNECT, level 3 = CONNECT-IP verified.
 */
object Scanner {
    data class Res(val ip: String, val ms: Int, val mode: Int, val sni: Int, val level: Int)

    val tested = AtomicInteger(0)
    val tcpOk = AtomicInteger(0)
    val tlsOk = AtomicInteger(0)
    val verified = AtomicInteger(0)
    val errors = ConcurrentHashMap<String, AtomicInteger>()
    @Volatile var best: Res? = null
    @Volatile var stop = false

    private val results = ArrayList<Res>()

    private fun candidates(c: Context): List<String> {
        val set = LinkedHashSet<String>()
        val io = Store.get(c, "imp_outer")
        val ii = Store.get(c, "imp_inner")
        if (io.isNotEmpty()) set.add(io)
        if (ii.isNotEmpty()) set.add(ii)
        val e4 = Store.get(c, "reg_ep4")
        if (e4.isNotEmpty()) set.add(e4)
        set.add("162.159.198.2")
        set.add("162.159.198.1")
        set.add("162.159.192.1")
        set.add("162.159.193.1")
        val first = ArrayList<String>()
        for (p in intArrayOf(198, 197, 195, 193, 192)) for (o in 1..254) first.add("162.159.$p.$o")
        first.shuffle()
        val second = ArrayList<String>()
        for (p in 96..99) for (o in 1..254) second.add("188.114.$p.$o")
        for (p in 68..69) for (o in 1..254) second.add("8.47.$p.$o")
        second.shuffle()
        set.addAll(first)
        set.addAll(second)
        return ArrayList(set)
    }

    private fun better(a: Res, b: Res?): Boolean {
        if (b == null) return true
        if (a.level != b.level) return a.level > b.level
        return a.ms < b.ms
    }

    private fun err(e: Exception) {
        val m = (e.message ?: "").lowercase()
        val k = when {
            e is SocketTimeoutException || m.contains("timed out") -> "timeout"
            m.contains("reset") -> "reset"
            m.contains("no-h2") -> "no-h2"
            m.contains("closed") || m.contains("eof") || m.contains("end of stream") -> "closed"
            m.contains("alert") || m.contains("handshake") || m.contains("ssl") -> "tls-error"
            else -> e.javaClass.simpleName
        }
        errors.getOrPut(k) { AtomicInteger(0) }.incrementAndGet()
    }

    private fun probe(ip: String, ctx: SSLContext, registered: Boolean): Res? {
        var ms = 0
        val s = Socket()
        try {
            val t0 = System.nanoTime()
            s.connect(InetSocketAddress(ip, 443), 2000)
            ms = ((System.nanoTime() - t0) / 1_000_000).toInt()
        } catch (e: Exception) {
            return null
        } finally {
            try {
                s.close()
            } catch (e: Exception) {
            }
        }
        tcpOk.incrementAndGet()

        for (si in intArrayOf(0, 1)) {
            for (m in intArrayOf(1, 0)) {
                if (stop) return null
                var conn: Net.Conn? = null
                try {
                    conn = Net.open(ip, 443, Net.SNIS[si], m, null, ctx, 3000, 4000)
                    tlsOk.incrementAndGet()
                    var level = 1
                    if (registered) {
                        val st = Net.connectIp(conn)
                        if (st == 0 || st in 200..299) {
                            level = 3
                        } else {
                            errors.getOrPut("connect:$st") { AtomicInteger(0) }.incrementAndGet()
                        }
                    } else {
                        if (Net.peekSettings(conn.ssl, 2500) == 2) level = 2
                    }
                    return Res(ip, ms, m, si, level)
                } catch (e: Exception) {
                    err(e)
                } finally {
                    conn?.close()
                }
            }
        }
        return null
    }

    /** Blocks until time is up, the list is exhausted, enough verified endpoints exist, or [stop] is set. */
    fun scan(c: Context, durationSec: Int): List<Res> {
        stop = false
        tested.set(0)
        tcpOk.set(0)
        tlsOk.set(0)
        verified.set(0)
        errors.clear()
        best = null
        synchronized(results) { results.clear() }

        val registered = Store.get(c, "addr4").isNotEmpty() || Store.get(c, "addr6").isNotEmpty()
        val ctx: SSLContext = try {
            KeyHelper.sslContext()
        } catch (e: Exception) {
            AbulixVpnService.log("خطا در ساخت کلید: ${e.message}")
            return emptyList()
        }

        val list = candidates(c)
        val idx = AtomicInteger(0)
        val deadline = System.currentTimeMillis() + durationSec * 1000L
        val workers = ArrayList<Thread>()
        for (w in 0 until 40) {
            val t = Thread {
                while (!stop && System.currentTimeMillis() < deadline) {
                    val i = idx.getAndIncrement()
                    if (i >= list.size) break
                    val r = probe(list[i], ctx, registered)
                    tested.incrementAndGet()
                    if (r != null) {
                        if (r.level == 3) verified.incrementAndGet()
                        synchronized(results) {
                            results.add(r)
                            if (better(r, best)) best = r
                        }
                        if (verified.get() >= 6) stop = true
                    }
                }
            }
            t.start()
            workers.add(t)
        }
        for (t in workers) {
            try {
                t.join()
            } catch (e: Exception) {
            }
        }
        return synchronized(results) { results.sortedWith(compareBy<Res>({ -it.level }, { it.ms })) }
    }
}
