package ir.abulix.psiphone

import android.content.Context

object Store {
    private fun p(c: Context) = c.getSharedPreferences("abulix", Context.MODE_PRIVATE)

    fun get(c: Context, k: String, d: String = ""): String = p(c).getString(k, d) ?: d

    fun put(c: Context, k: String, v: String) {
        p(c).edit().putString(k, v).apply()
    }
}
