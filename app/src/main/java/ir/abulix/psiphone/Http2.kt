package ir.abulix.psiphone

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Minimal HTTP/2 client with one extended-CONNECT stream (stream id 1) carrying
 * CONNECT-IP capsules (DATAGRAM capsule = context id 0 + raw IP packet).
 */
class Http2Conn(private val sock: Socket) {
    companion object {
        const val RECV_WINDOW = 16 * 1024 * 1024
    }

    private val inp = DataInputStream(BufferedInputStream(sock.getInputStream(), 65536))
    private val out = BufferedOutputStream(sock.getOutputStream(), 65536)
    private val fc = ReentrantLock()
    private val fcCond = fc.newCondition()
    private var connWindow = 65535L
    private var streamWindow = 65535L
    private var peerInitial = 65535L
    @Volatile private var peerMaxFrame = 16384

    private val respLatch = CountDownLatch(1)
    @Volatile private var respStatus = 0
    private var statusSeen = false
    private val hdrBuf = ByteArrayOutputStream()
    private var hdrEndStream = false

    @Volatile var closed = false
    @Volatile var closeReason = ""
    @Volatile var peerConnectProtocol = false

    var onPacket: ((ByteArray, Int, Int) -> Unit)? = null
    var onPong: ((Long) -> Unit)? = null

    // ---------- writing ----------
    private fun put32(b: ByteArray, o: Int, v: Int) {
        b[o] = (v ushr 24).toByte()
        b[o + 1] = (v ushr 16).toByte()
        b[o + 2] = (v ushr 8).toByte()
        b[o + 3] = v.toByte()
    }

    private fun writeFrame(type: Int, flags: Int, stream: Int, p: ByteArray, off: Int, len: Int) {
        synchronized(out) {
            val h = ByteArray(9)
            h[0] = (len ushr 16).toByte()
            h[1] = (len ushr 8).toByte()
            h[2] = len.toByte()
            h[3] = type.toByte()
            h[4] = flags.toByte()
            h[5] = ((stream ushr 24) and 0x7f).toByte()
            h[6] = (stream ushr 16).toByte()
            h[7] = (stream ushr 8).toByte()
            h[8] = stream.toByte()
            out.write(h)
            if (len > 0) out.write(p, off, len)
            out.flush()
        }
    }

    fun start() {
        synchronized(out) {
            out.write("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII))
        }
        val s = ByteArray(18)
        s[1] = 2                       // ENABLE_PUSH = 0
        s[7] = 4                       // INITIAL_WINDOW_SIZE
        put32(s, 8, RECV_WINDOW)
        s[13] = 1                      // HEADER_TABLE_SIZE = 0 (no dynamic table)
        writeFrame(4, 0, 0, s, 0, 18)
        val w = ByteArray(4)
        put32(w, 0, RECV_WINDOW - 65535)
        writeFrame(8, 0, 0, w, 0, 4)
    }

    private fun hpInt(b: ByteArrayOutputStream, v: Int, prefix: Int, flagBits: Int) {
        val max = (1 shl prefix) - 1
        if (v < max) {
            b.write(flagBits or v)
        } else {
            b.write(flagBits or max)
            var r = v - max
            while (r >= 128) {
                b.write((r and 127) or 128)
                r = r ushr 7
            }
            b.write(r)
        }
    }

    private fun hpStr(b: ByteArrayOutputStream, s: String) {
        val bytes = s.toByteArray(Charsets.UTF_8)
        hpInt(b, bytes.size, 7, 0)
        b.write(bytes, 0, bytes.size)
    }

    fun sendConnect(authority: String, protocol: String, extra: List<Pair<String, String>>) {
        val b = ByteArrayOutputStream()
        fun lit(n: String, v: String) {
            b.write(0)
            hpStr(b, n)
            hpStr(b, v)
        }
        lit(":method", "CONNECT")
        lit(":scheme", "https")
        lit(":authority", authority)
        lit(":path", "/")
        lit(":protocol", protocol)
        for (e in extra) lit(e.first, e.second)
        val blk = b.toByteArray()
        writeFrame(1, 0x4, 1, blk, 0, blk.size)
    }

    fun awaitStatus(ms: Long): Int {
        val ok = respLatch.await(ms, TimeUnit.MILLISECONDS)
        if (!ok) return -1
        if (closed && respStatus == 0) return -2
        return respStatus
    }

    private fun varintSize(v: Int): Int = if (v < 64) 1 else if (v < 16384) 2 else 4

    private fun putVarint(b: ByteArray, o: Int, v: Int): Int {
        return when (varintSize(v)) {
            1 -> {
                b[o] = v.toByte()
                1
            }
            2 -> {
                b[o] = (0x40 or (v ushr 8)).toByte()
                b[o + 1] = v.toByte()
                2
            }
            else -> {
                b[o] = (0x80 or (v ushr 24)).toByte()
                b[o + 1] = (v ushr 16).toByte()
                b[o + 2] = (v ushr 8).toByte()
                b[o + 3] = v.toByte()
                4
            }
        }
    }

    /** Sends one IP packet as a DATAGRAM capsule. */
    fun sendPacket(pkt: ByteArray, len: Int): Boolean {
        if (closed) return false
        try {
            val plen = len + 1
            val cap = ByteArray(1 + varintSize(plen) + plen)
            var o = 0
            cap[o++] = 0                       // capsule type DATAGRAM
            o += putVarint(cap, o, plen)
            cap[o++] = 0                       // context id 0 = IP packet
            System.arraycopy(pkt, 0, cap, o, len)
            val n = cap.size
            if (n > peerMaxFrame) return true  // oversize: drop
            fc.withLock {
                var waited = 0
                while (!closed && (connWindow < n || streamWindow < n)) {
                    fcCond.await(500, TimeUnit.MILLISECONDS)
                    waited++
                    if (waited > 40) break
                }
                if (closed) return false
                connWindow -= n
                streamWindow -= n
            }
            writeFrame(0, 0, 1, cap, 0, n)
            return true
        } catch (e: Exception) {
            close("خطای ارسال: ${e.message}")
            return false
        }
    }

    fun sendPing() {
        val b = ByteArray(8)
        var t = System.nanoTime()
        for (i in 7 downTo 0) {
            b[i] = (t and 0xff).toByte()
            t = t ushr 8
        }
        writeFrame(6, 0, 0, b, 0, 8)
    }

    fun close(reason: String) {
        if (closed) return
        closed = true
        closeReason = reason
        try {
            sock.close()
        } catch (e: Exception) {
        }
        respLatch.countDown()
        fc.withLock { fcCond.signalAll() }
    }

    // ---------- capsule parsing ----------
    private var cbuf = ByteArray(8192)
    private var cn = 0
    private val vr = LongArray(2)

    private fun varint(b: ByteArray, pos: Int, end: Int): Boolean {
        if (pos >= end) return false
        val first = b[pos].toInt() and 0xff
        val size = 1 shl (first ushr 6)
        if (pos + size > end) return false
        var v = (first and 0x3f).toLong()
        for (i in 1 until size) v = (v shl 8) or (b[pos + i].toLong() and 0xff)
        vr[0] = v
        vr[1] = size.toLong()
        return true
    }

    private fun feed(d: ByteArray, off: Int, l: Int) {
        if (cn + l > cbuf.size) cbuf = cbuf.copyOf(maxOf(cbuf.size * 2, cn + l))
        System.arraycopy(d, off, cbuf, cn, l)
        cn += l
        var pos = 0
        while (true) {
            if (!varint(cbuf, pos, cn)) break
            val type = vr[0]
            val ts = vr[1].toInt()
            if (!varint(cbuf, pos + ts, cn)) break
            val lenL = vr[0]
            val ls = vr[1].toInt()
            if (lenL < 0 || lenL > 1_000_000L) {
                close("کپسول نامعتبر")
                return
            }
            val len = lenL.toInt()
            val start = pos + ts + ls
            if (start + len > cn) break
            if (type == 0L && len >= 1) {
                if (varint(cbuf, start, start + len)) {
                    val cs = vr[1].toInt()
                    if (vr[0] == 0L && len - cs > 0) onPacket?.invoke(cbuf, start + cs, len - cs)
                }
            }
            pos = start + len
        }
        if (pos > 0) {
            System.arraycopy(cbuf, pos, cbuf, 0, cn - pos)
            cn -= pos
        }
    }

    // ---------- HPACK (status only) ----------
    private var hp = 0

    private fun rInt(b: ByteArray, prefix: Int): Int {
        val max = (1 shl prefix) - 1
        var v = b[hp].toInt() and max
        hp++
        if (v < max) return v
        var m = 0
        while (hp < b.size) {
            val x = b[hp].toInt() and 0xff
            hp++
            v += (x and 0x7f) shl m
            m += 7
            if ((x and 0x80) == 0) break
        }
        return v
    }

    private fun decodeNum(b: ByteArray, start: Int, l: Int, huff: Boolean): Int {
        if (!huff) return String(b, start, l, Charsets.US_ASCII).toIntOrNull() ?: 0
        var bits = 0L
        var nb = 0
        var res = 0
        var digits = 0
        for (i in 0 until l) {
            bits = (bits shl 8) or (b[start + i].toLong() and 0xff)
            nb += 8
            while (true) {
                if (nb >= 5) {
                    val v5 = ((bits shr (nb - 5)) and 0x1f).toInt()
                    if (v5 <= 2) {
                        res = res * 10 + v5
                        digits++
                        nb -= 5
                        bits = bits and ((1L shl nb) - 1)
                        continue
                    }
                }
                if (nb >= 6) {
                    val v6 = ((bits shr (nb - 6)) and 0x3f).toInt()
                    if (v6 in 0x19..0x1f) {
                        res = res * 10 + (v6 - 0x19 + 3)
                        digits++
                        nb -= 6
                        bits = bits and ((1L shl nb) - 1)
                        continue
                    }
                }
                break
            }
        }
        return if (digits == 3) res else 0
    }

    private fun parseStatus(b: ByteArray): Int {
        hp = 0
        val table = intArrayOf(200, 204, 206, 304, 400, 404, 500)
        try {
            while (hp < b.size) {
                val c = b[hp].toInt() and 0xff
                if ((c and 0x80) != 0) {
                    val idx = rInt(b, 7)
                    if (idx in 8..14) return table[idx - 8]
                } else {
                    val prefix = if ((c and 0xc0) == 0x40) 6 else if ((c and 0xe0) == 0x20) 5 else 4
                    if (prefix == 5) {
                        rInt(b, 5)
                        continue
                    }
                    val idx = rInt(b, prefix)
                    if (idx == 0) {
                        val nl = rInt(b, 7)
                        hp += nl
                    }
                    val huff = (b[hp].toInt() and 0x80) != 0
                    val l = rInt(b, 7)
                    if (idx == 8) return decodeNum(b, hp, l, huff)
                    hp += l
                }
            }
        } catch (e: Exception) {
        }
        return 0
    }

    private fun onHeaders() {
        val blk = hdrBuf.toByteArray()
        hdrBuf.reset()
        if (!statusSeen) {
            statusSeen = true
            respStatus = parseStatus(blk)
            respLatch.countDown()
        }
        if (hdrEndStream) close("سرور جریان را بست")
    }

    // ---------- reading ----------
    fun runReader() {
        var consumed = 0
        try {
            val hdr = ByteArray(9)
            while (!closed) {
                inp.readFully(hdr)
                val len = ((hdr[0].toInt() and 0xff) shl 16) or ((hdr[1].toInt() and 0xff) shl 8) or (hdr[2].toInt() and 0xff)
                val type = hdr[3].toInt() and 0xff
                val flags = hdr[4].toInt() and 0xff
                val sid = ((hdr[5].toInt() and 0x7f) shl 24) or ((hdr[6].toInt() and 0xff) shl 16) or
                    ((hdr[7].toInt() and 0xff) shl 8) or (hdr[8].toInt() and 0xff)
                val p = ByteArray(len)
                if (len > 0) inp.readFully(p)
                when (type) {
                    0 -> {
                        var off = 0
                        var end = len
                        if ((flags and 0x8) != 0 && len > 0) {
                            val pad = p[0].toInt() and 0xff
                            off = 1
                            end = len - pad
                        }
                        if (sid == 1 && end > off) feed(p, off, end - off)
                        consumed += len
                        if (consumed >= 262144) {
                            val w = ByteArray(4)
                            put32(w, 0, consumed)
                            writeFrame(8, 0, 0, w, 0, 4)
                            writeFrame(8, 0, 1, w, 0, 4)
                            consumed = 0
                        }
                        if ((flags and 1) != 0) close("پایان جریان از سرور")
                    }
                    1, 9 -> {
                        var off = 0
                        var end = len
                        if (type == 1) {
                            if ((flags and 0x8) != 0 && len > 0) {
                                val pad = p[0].toInt() and 0xff
                                off = 1
                                end = len - pad
                            }
                            if ((flags and 0x20) != 0) off += 5
                            hdrEndStream = (flags and 0x1) != 0
                            hdrBuf.reset()
                        }
                        if (sid == 1 && end > off) hdrBuf.write(p, off, end - off)
                        if ((flags and 0x4) != 0 && sid == 1) onHeaders()
                    }
                    3 -> {
                        if (sid == 1) close("RST_STREAM")
                    }
                    4 -> {
                        if ((flags and 1) == 0) {
                            var i = 0
                            while (i + 6 <= len) {
                                val id = ((p[i].toInt() and 0xff) shl 8) or (p[i + 1].toInt() and 0xff)
                                val v = ((p[i + 2].toLong() and 0xff) shl 24) or ((p[i + 3].toLong() and 0xff) shl 16) or
                                    ((p[i + 4].toLong() and 0xff) shl 8) or (p[i + 5].toLong() and 0xff)
                                if (id == 4) {
                                    fc.withLock {
                                        streamWindow += v - peerInitial
                                        peerInitial = v
                                        fcCond.signalAll()
                                    }
                                } else if (id == 5) {
                                    peerMaxFrame = v.toInt()
                                } else if (id == 8) {
                                    peerConnectProtocol = (v == 1L)
                                }
                                i += 6
                            }
                            writeFrame(4, 1, 0, ByteArray(0), 0, 0)
                        }
                    }
                    6 -> {
                        if ((flags and 1) == 0) {
                            writeFrame(6, 1, 0, p, 0, len)
                        } else if (len == 8) {
                            var t = 0L
                            for (i in 0 until 8) t = (t shl 8) or (p[i].toLong() and 0xff)
                            onPong?.invoke((System.nanoTime() - t) / 1_000_000)
                        }
                    }
                    7 -> close("GOAWAY از سرور")
                    8 -> {
                        if (len >= 4) {
                            val inc = (((p[0].toInt() and 0x7f) shl 24) or ((p[1].toInt() and 0xff) shl 16) or
                                ((p[2].toInt() and 0xff) shl 8) or (p[3].toInt() and 0xff)).toLong()
                            fc.withLock {
                                if (sid == 0) {
                                    connWindow += inc
                                } else if (sid == 1) {
                                    streamWindow += inc
                                }
                                fcCond.signalAll()
                            }
                        }
                    }
                    else -> {
                    }
                }
            }
        } catch (e: Exception) {
            close("خطای دریافت: ${e.message}")
        } finally {
            close("اتصال بسته شد")
        }
    }
}
