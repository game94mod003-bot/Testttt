package ir.abulix.psiphone

import android.util.Base64
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Encrypted share links (abulix://...). Only this app holds the key, so other apps cannot read them. */
object Share {
    private val KEYS = arrayOf("ep_host", "ep_port", "ep_ms", "ep_level", "ep_list")

    private fun key() = SecretKeySpec(
        MessageDigest.getInstance("SHA-256").digest("abulix::psiphone::v1::lion-sun".toByteArray()), "AES"
    )

    fun encode(get: (String) -> String): String {
        val o = JSONObject()
        for (k in KEYS) o.put(k, get(k))
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key(), GCMParameterSpec(128, iv))
        val enc = c.doFinal(o.toString().toByteArray())
        return "abulix://" + Base64.encodeToString(iv + enc, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    fun decode(link: String): Map<String, String>? {
        return try {
            val raw = Base64.decode(link.trim().removePrefix("abulix://"), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, raw.copyOfRange(0, 12)))
            val o = JSONObject(String(c.doFinal(raw.copyOfRange(12, raw.size))))
            val m = HashMap<String, String>()
            for (k in KEYS) m[k] = o.optString(k, "")
            if (m["ep_host"].isNullOrEmpty()) null else m
        } catch (e: Exception) {
            null
        }
    }
}
