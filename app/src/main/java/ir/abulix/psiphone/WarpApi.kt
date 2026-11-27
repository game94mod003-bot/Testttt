package ir.abulix.psiphone

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.Random
import java.util.TimeZone
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Registers a WARP account (MASQUE / secp256r1 key) with Cloudflare. */
object WarpApi {
    private const val HOST = "api.cloudflareclient.com"
    private const val BASE = "/v0a4471/reg"

    private fun dechunk(b: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        var i = 0
        while (i < b.size) {
            var j = i
            while (j < b.size - 1 && !(b[j] == '\r'.code.toByte() && b[j + 1] == '\n'.code.toByte())) j++
            val ln = String(b, i, j - i).trim().substringBefore(';').toIntOrNull(16) ?: break
            if (ln == 0) break
            i = j + 2
            o.write(b, i, minOf(ln, b.size - i))
            i += ln + 2
        }
        return o.toByteArray()
    }

    private fun raw(method: String, path: String, body: String?, token: String?): Pair<Int, String> {
        val s = SSLSocketFactory.getDefault().createSocket(HOST, 443) as SSLSocket
        s.soTimeout = 15000
        s.startHandshake()
        val bb = body?.toByteArray(Charsets.UTF_8)
        val sb = StringBuilder()
        sb.append("$method $path HTTP/1.1\r\n")
        sb.append("Host: $HOST\r\n")
        sb.append("User-Agent: WARP for Android\r\n")
        sb.append("CF-Client-Version: a-6.35-4471\r\n")
        sb.append("Accept: application/json\r\n")
        sb.append("Connection: close\r\n")
        if (token != null) sb.append("Authorization: Bearer $token\r\n")
        if (bb != null) {
            sb.append("Content-Type: application/json; charset=UTF-8\r\n")
            sb.append("Content-Length: ${bb.size}\r\n")
        }
        sb.append("\r\n")
        val os = s.outputStream
        os.write(sb.toString().toByteArray(Charsets.UTF_8))
        if (bb != null) os.write(bb)
        os.flush()

        val acc = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        try {
            while (true) {
                val n = s.inputStream.read(buf)
                if (n < 0) break
                acc.write(buf, 0, n)
            }
        } catch (e: Exception) {
        }
        try {
            s.close()
        } catch (e: Exception) {
        }
        val data = acc.toByteArray()
        var idx = -1
        for (i in 0 until data.size - 3) {
            if (data[i] == 13.toByte() && data[i + 1] == 10.toByte() && data[i + 2] == 13.toByte() && data[i + 3] == 10.toByte()) {
                idx = i
                break
            }
        }
        if (idx < 0) return Pair(0, "")
        val head = String(data, 0, idx, Charsets.ISO_8859_1)
        val status = head.substringBefore("\r\n").split(" ").getOrNull(1)?.toIntOrNull() ?: 0
        var bodyBytes = data.copyOfRange(idx + 4, data.size)
        if (head.lowercase(Locale.US).contains("transfer-encoding: chunked")) bodyBytes = dechunk(bodyBytes)
        return Pair(status, String(bodyBytes, Charsets.UTF_8))
    }

    private fun clean(x: String?): String = if (x == null || x == "null") "" else x

    private fun parseAndSave(ctx: Context, text: String, log: (String) -> Unit): Boolean {
        return try {
            val j = JSONObject(text)
            val cfg = j.optJSONObject("config")
            val addr = cfg?.optJSONObject("interface")?.optJSONObject("addresses")
            val a4 = clean(addr?.optString("v4")).substringBefore("/")
            val a6 = clean(addr?.optString("v6")).substringBefore("/")
            val ep = cfg?.optJSONArray("peers")?.optJSONObject(0)?.optJSONObject("endpoint")
            val e4 = clean(ep?.optString("v4")).substringBeforeLast(":")
            val e6 = clean(ep?.optString("v6")).removePrefix("[").substringBefore("]")
            if (a4.isEmpty() && a6.isEmpty()) {
                log("پاسخ سرور آدرسی نداشت")
                false
            } else {
                Store.put(ctx, "reg_id", clean(j.optString("id")))
                Store.put(ctx, "reg_token", clean(j.optString("token")))
                Store.put(ctx, "addr4", a4)
                Store.put(ctx, "addr6", a6)
                Store.put(ctx, "reg_ep4", e4)
                Store.put(ctx, "reg_ep6", e6)
                if (Store.get(ctx, "ep_host").isEmpty() && e4.isNotEmpty()) {
                    Store.put(ctx, "ep_host", e4)
                    Store.put(ctx, "ep_port", "443")
                }
                true
            }
        } catch (e: Exception) {
            log("خطا در خواندن پاسخ: ${e.message}")
            false
        }
    }

    /** Registration is two requests (like the app): register, then enable WARP on the device. */
    fun register(ctx: Context, log: (String) -> Unit): Boolean {
        if (!registerOnly(ctx, log)) return false
        enableWarp(ctx, log)
        return true
    }

    /** Turns WARP on for the registered device; without it the edge resets the tunnel stream (RST_STREAM). */
    fun enableWarp(ctx: Context, log: (String) -> Unit): Boolean {
        val id = Store.get(ctx, "reg_id")
        val token = Store.get(ctx, "reg_token")
        if (id.isEmpty() || token.isEmpty()) return false
        return try {
            val r = raw("PATCH", "$BASE/$id", JSONObject().put("warp_enabled", true).toString(), token)
            log("فعال‌سازی WARP: HTTP ${r.first}")
            if (r.first in 200..299) {
                Store.put(ctx, "warp_en", "1")
                true
            } else {
                false
            }
        } catch (e: Exception) {
            log("خطا در فعال‌سازی WARP: ${e.message}")
            false
        }
    }

    fun ensureEnabled(ctx: Context, log: (String) -> Unit) {
        if (Store.get(ctx, "warp_en") != "1") enableWarp(ctx, log)
    }

    private fun registerOnly(ctx: Context, log: (String) -> Unit): Boolean {
        try {
            KeyHelper.regenerate()
            Store.put(ctx, "warp_en", "")
            val pub = Base64.encodeToString(KeyHelper.publicKeyDer(), Base64.NO_WRAP)
            val df = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
            df.timeZone = TimeZone.getTimeZone("UTC")
            val tos = df.format(Date())
            val rnd = Random()
            val serial = StringBuilder()
            for (i in 0 until 16) serial.append("0123456789abcdef"[rnd.nextInt(16)])

            val b1 = JSONObject()
                .put("key", pub)
                .put("install_id", "")
                .put("fcm_token", "")
                .put("tos", tos)
                .put("model", "Android")
                .put("serial_number", serial.toString())
                .put("key_type", "secp256r1")
                .put("tunnel_type", "masque")
                .put("locale", "en_US")
            log("ثبت حساب WARP...")
            val r1 = raw("POST", BASE, b1.toString(), null)
            log("پاسخ ثبت: HTTP ${r1.first}")
            if (r1.first in 200..299 && parseAndSave(ctx, r1.second, log)) return true

            // Fallback: register with a legacy key, then switch the account to a MASQUE key.
            val legacy = ByteArray(32)
            rnd.nextBytes(legacy)
            legacy[0] = (legacy[0].toInt() and 248).toByte()
            legacy[31] = ((legacy[31].toInt() and 127) or 64).toByte()
            val b2 = JSONObject()
                .put("key", Base64.encodeToString(legacy, Base64.NO_WRAP))
                .put("install_id", "")
                .put("fcm_token", "")
                .put("tos", tos)
                .put("model", "Android")
                .put("serial_number", serial.toString())
                .put("locale", "en_US")
            val r2 = raw("POST", BASE, b2.toString(), null)
            log("ثبت جایگزین: HTTP ${r2.first}")
            if (r2.first !in 200..299) return false
            val j2 = JSONObject(r2.second)
            val id = clean(j2.optString("id"))
            val token = clean(j2.optString("token"))
            if (id.isEmpty() || token.isEmpty()) return false
            val b3 = JSONObject()
                .put("key", pub)
                .put("key_type", "secp256r1")
                .put("tunnel_type", "masque")
            val r3 = raw("PATCH", "$BASE/$id", b3.toString(), token)
            log("فعال‌سازی MASQUE: HTTP ${r3.first}")
            if (r3.first in 200..299 && parseAndSave(ctx, r3.second, log)) return true
            return parseAndSave(ctx, r2.second, log)
        } catch (e: Exception) {
            log("خطا: ${e.message}")
            return false
        }
    }
}
