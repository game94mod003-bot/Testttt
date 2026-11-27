package ir.abulix.psiphone

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509KeyManager
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

/** EC P-256 key (kept in Android Keystore) used for the MASQUE mTLS client certificate. */
object KeyHelper {
    private const val ALIAS = "abulix_ec"

    private fun store(): KeyStore {
        val k = KeyStore.getInstance("AndroidKeyStore")
        k.load(null)
        return k
    }

    private fun generate() {
        val now = System.currentTimeMillis()
        val spec = KeyGenParameterSpec.Builder(
            ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(
                KeyProperties.DIGEST_NONE,
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512
            )
            .setCertificateSubject(X500Principal("CN=abulix"))
            .setCertificateSerialNumber(BigInteger.valueOf(now))
            .setCertificateNotBefore(Date(now - 86400000L))
            .setCertificateNotAfter(Date(now + 3650L * 86400000L))
            .build()
        val g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        g.initialize(spec)
        g.generateKeyPair()
    }

    fun ensureKey() {
        if (!store().containsAlias(ALIAS)) generate()
    }

    fun regenerate() {
        val k = store()
        if (k.containsAlias(ALIAS)) k.deleteEntry(ALIAS)
        generate()
    }

    /** X.509 SubjectPublicKeyInfo DER of the public key. */
    fun publicKeyDer(): ByteArray {
        ensureKey()
        return store().getCertificate(ALIAS).publicKey.encoded
    }

    fun sslContext(): SSLContext {
        ensureKey()
        val km = object : X509KeyManager {
            override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? =
                arrayOf(ALIAS)

            override fun chooseClientAlias(
                keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?
            ): String? = ALIAS

            override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null

            override fun chooseServerAlias(
                keyType: String?, issuers: Array<out Principal>?, socket: Socket?
            ): String? = null

            override fun getCertificateChain(alias: String?): Array<X509Certificate>? {
                val chain = store().getCertificateChain(ALIAS) ?: return null
                return chain.map { it as X509Certificate }.toTypedArray()
            }

            override fun getPrivateKey(alias: String?): PrivateKey? =
                store().getKey(ALIAS, null) as? PrivateKey
        }
        // The WARP MASQUE endpoint does not present a publicly trusted chain, so server
        // certificate validation is skipped for this single connection.
        val tm = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf<X509Certificate>()
        }
        val c = SSLContext.getInstance("TLS")
        c.init(arrayOf<KeyManager>(km), arrayOf<TrustManager>(tm), null)
        return c
    }
}
