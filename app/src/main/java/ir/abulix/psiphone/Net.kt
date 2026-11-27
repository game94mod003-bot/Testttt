package ir.abulix.psiphone

import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Random
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread

/**
 * Local loopback relay for ONE connection. It forwards bytes to the real server and splits the
 * first TLS record (ClientHello) into tiny TCP packets, which defeats SNI-based DPI filtering.
 */
class Relay(
    private val host: String,
    private val port: Int,
    private val tcpMs: Int,
    private val prot: ((Socket) -> Boolean)?
) {
    private val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))

    @Volatile private var up: Socket? = null
    @Volatile private var down: Socket? = null
    @Volatile private var dead = false

    val localPort: Int
        get() = server.localPort

    fun start() {
        thread { serve() }
    }

    private fun serve() {
        try {
            server.soTimeout = 6000
            val c = server.accept()
            down = c
            try {
                server.close()
            } catch (e: Exception) {
            }
            if (dead) {
                c.close()
                return
            }
            c.tcpNoDelay = true
            val u = Socket()
            up = u
            u.bind(InetSocketAddress(0))
            val p = prot
            if (p != null && !p(u)) throw Exception("protect failed")
            u.tcpNoDelay = true
            u.connect(InetSocketAddress(host, port), tcpMs)
            if (dead) return
            thread {
                try {
                    pipe(u.getInputStream(), c.getOutputStream(), false)
                } catch (e: Exception) {
                }
                close()
            }
            pipe(c.getInputStream(), u.getOutputStream(), true)
        } catch (e: Exception) {
        } finally {
            close()
        }
    }

    private fun pipe(i: InputStream, o: OutputStream, frag: Boolean) {
        val buf = ByteArray(16384)
        var first = frag
        val rnd = Random()
        while (!dead) {
            val n = i.read(buf)
            if (n < 0) break
            if (first && n > 5 && buf[0] == 0x16.toByte()) {
                first = false
                var p = 0
                while (p < n) {
                    val sz = minOf(n - p, 8 + rnd.nextInt(9))
                    o.write(buf, p, sz)
                    o.flush()
                    p += sz
                    if (p < n) Thread.sleep(5L + rnd.nextInt(11))
                }
            } else {
                first = false
                o.write(buf, 0, n)
                o.flush()
            }
        }
    }

    fun close() {
        if (dead) return
        dead = true
        try {
            server.close()
        } catch (e: Exception) {
        }
        try {
            up?.close()
        } catch (e: Exception) {
        }
        try {
            down?.close()
        } catch (e: Exception) {
        }
    }
}

object Net {
    const val SNI0 = "www.cloudflare.com"
    const val SNI1 = "consumer-masque.cloudflareclient.com"
    const val SNI2 = "consumer-masque-proxy.cloudflareclient.com"

    val SNIS = arrayOf(SNI0, SNI1, SNI2)

    private val PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)

    class Conn(val ssl: SSLSocket, private val raw: Socket, private val relay: Relay?) {
        fun close() {
            try {
                ssl.close()
            } catch (e: Exception) {
            }
            try {
                raw.close()
            } catch (e: Exception) {
            }
            relay?.close()
        }
    }

    /**
     * TCP + TLS (ALPN h2) with the client certificate. mode 1 = fragmented ClientHello through a
     * local relay, mode 0 = direct. [prot] protects the real socket from the VPN (used by the service).
     * Throws on any failure.
     */
    fun open(
        host: String,
        port: Int,
        sni: String,
        mode: Int,
        prot: ((Socket) -> Boolean)?,
        ctx: SSLContext,
        tcpMs: Int,
        hsMs: Int
    ): Conn {
        var relay: Relay? = null
        var raw: Socket? = null
        var ssl: SSLSocket? = null
        try {
            val r = Socket()
            raw = r
            if (mode == 1) {
                val rl = Relay(host, port, tcpMs, prot)
                relay = rl
                rl.start()
                r.connect(InetSocketAddress("127.0.0.1", rl.localPort), 3000)
            } else {
                r.bind(InetSocketAddress(0))
                if (prot != null && !prot(r)) throw Exception("protect failed")
                r.connect(InetSocketAddress(host, port), tcpMs)
            }
            r.tcpNoDelay = true
            val s = ctx.socketFactory.createSocket(r, sni, port, true) as SSLSocket
            ssl = s
            val sp = s.sslParameters
            sp.applicationProtocols = arrayOf("h2")
            sp.setServerNames(listOf<SNIServerName>(SNIHostName(sni)))
            s.sslParameters = sp
            s.soTimeout = hsMs
            s.startHandshake()
            val alpn = s.applicationProtocol
            if (alpn != "h2") throw Exception("no-h2 (alpn=$alpn)")
            s.soTimeout = 0
            return Conn(s, r, relay)
        } catch (e: Exception) {
            try {
                ssl?.close()
            } catch (x: Exception) {
            }
            try {
                raw?.close()
            } catch (x: Exception) {
            }
            relay?.close()
            throw e
        }
    }

    /** Sends the h2 preface and reads the server SETTINGS. 0 = nothing, 1 = settings, 2 = settings with extended CONNECT. */
    fun peekSettings(ssl: SSLSocket, ms: Int): Int {
        try {
            val o = ssl.outputStream
            o.write(PREFACE)
            o.write(byteArrayOf(0, 0, 0, 4, 0, 0, 0, 0, 0))
            o.flush()
            ssl.soTimeout = ms
            val i = DataInputStream(ssl.inputStream)
            val hdr = ByteArray(9)
            for (k in 0 until 4) {
                i.readFully(hdr)
                val len = ((hdr[0].toInt() and 0xff) shl 16) or ((hdr[1].toInt() and 0xff) shl 8) or (hdr[2].toInt() and 0xff)
                if (len > 65536) return 0
                val p = ByteArray(len)
                if (len > 0) i.readFully(p)
                val type = hdr[3].toInt() and 0xff
                if (type == 4 && (hdr[4].toInt() and 1) == 0) {
                    var res = 1
                    var j = 0
                    while (j + 6 <= len) {
                        val id = ((p[j].toInt() and 0xff) shl 8) or (p[j + 1].toInt() and 0xff)
                        val v = p[j + 5].toInt() and 0xff
                        if (id == 8 && v == 1) res = 2
                        j += 6
                    }
                    return res
                }
            }
        } catch (e: Exception) {
        }
        return 0
    }

    /** Full end-to-end check: opens the CONNECT-IP stream. Returns HTTP status (0 = unparsed), -1 = no answer, -2 = closed. */
    fun connectIp(c: Conn): Int {
        val h = Http2Conn(c.ssl)
        try {
            h.start()
            thread { h.runReader() }
            h.sendConnect(
                "cloudflareaccess.com", "cf-connect-ip",
                listOf("user-agent" to "WARP for Android", "capsule-protocol" to "?1")
            )
            return h.awaitStatus(5000)
        } finally {
            h.close("check")
        }
    }
}
