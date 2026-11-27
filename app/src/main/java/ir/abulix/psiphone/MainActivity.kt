package ir.abulix.psiphone

import android.app.Activity
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.util.Locale
import kotlin.concurrent.thread

class MainActivity : Activity() {
    private val h = Handler(Looper.getMainLooper())
    private val cBg = Color.parseColor("#0A0E1A")
    private val cCard = Color.parseColor("#141A2B")
    private val cCard2 = Color.parseColor("#1D2540")
    private val cAccent = Color.parseColor("#00E5A8")
    private val cRed = Color.parseColor("#FF5C7A")
    private val cYellow = Color.parseColor("#FFC857")
    private val cText = Color.parseColor("#E8ECF6")
    private val cSub = Color.parseColor("#8A94AD")

    private val durations = intArrayOf(30, 60, 120, 300, 600, 1800)

    private lateinit var ring: GradientDrawable
    private lateinit var btnConn: TextView
    private lateinit var tvState: TextView
    private lateinit var tvTime: TextView
    private lateinit var tvPing: TextView
    private lateinit var tvDown: TextView
    private lateinit var tvUp: TextView
    private lateinit var tvStab: TextView
    private lateinit var pbStab: ProgressBar
    private lateinit var tvIp: TextView
    private lateinit var tvIpInfo: TextView
    private lateinit var tvCfg: TextView
    private lateinit var tvScan: TextView
    private lateinit var tvLog: TextView
    private lateinit var btnScan: Button
    private lateinit var btnKey: Button
    private lateinit var beast: BeastView
    private lateinit var chart: SpeedChart
    private lateinit var tvUsage: TextView
    private val chips = ArrayList<TextView>()
    private lateinit var etLink: EditText
    private var fontR: Typeface? = null
    private var fontB: Typeface? = null

    @Volatile private var scanning = false
    private var scanStart = 0L
    private var scanDur = 30
    private var gettingKey = false
    private var lastRx = 0L
    private var lastTx = 0L
    private var lastT = 0L
    private var tick = 0

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    private fun tv(t: String, size: Float, color: Int, bold: Boolean = false): TextView {
        val x = TextView(this)
        x.text = t
        x.textSize = size
        x.setTextColor(color)
        if (bold) x.setTypeface(Typeface.DEFAULT, Typeface.BOLD)
        return x
    }

    private fun card(): LinearLayout {
        val l = LinearLayout(this)
        l.orientation = LinearLayout.VERTICAL
        l.setPadding(dp(16), dp(14), dp(16), dp(14))
        val g = GradientDrawable()
        g.setColor(cCard)
        g.cornerRadius = dp(22).toFloat()
        g.setStroke(dp(1), Color.parseColor("#26304F"))
        l.background = g
        val lp = LinearLayout.LayoutParams(-1, -2)
        lp.bottomMargin = dp(12)
        l.layoutParams = lp
        return l
    }

    private fun button(t: String, color: Int, textColor: Int): Button {
        val b = Button(this)
        b.text = t
        b.isAllCaps = false
        b.textSize = 16f
        b.setTextColor(textColor)
        val g = GradientDrawable()
        g.setColor(color)
        g.cornerRadius = dp(16).toFloat()
        b.background = g
        val lp = LinearLayout.LayoutParams(-1, dp(52))
        lp.bottomMargin = dp(10)
        b.layoutParams = lp
        return b
    }

    private fun metric(label: String, valueView: TextView): LinearLayout {
        val col = LinearLayout(this)
        col.orientation = LinearLayout.VERTICAL
        col.gravity = Gravity.CENTER
        col.layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        valueView.gravity = Gravity.CENTER
        col.addView(valueView)
        val l = tv(label, 12f, cSub)
        l.gravity = Gravity.CENTER
        col.addView(l)
        return col
    }

    private fun styleChips() {
        for (i in chips.indices) {
            val sel = durations[i] == scanDur
            val g = GradientDrawable()
            g.cornerRadius = dp(12).toFloat()
            g.setColor(if (sel) cAccent else cCard2)
            chips[i].background = g
            chips[i].setTextColor(if (sel) cBg else cText)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = cBg
        window.navigationBarColor = cBg
        scanDur = Store.get(this, "scan_sec", "30").toIntOrNull() ?: 30

        val root = LinearLayout(this)
        root.orientation = LinearLayout.VERTICAL
        root.setPadding(dp(16), dp(18), dp(16), dp(24))

        val sv = ScrollView(this)
        val bgG = GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, intArrayOf(Color.parseColor("#060A14"), Color.parseColor("#0F1838"), Color.parseColor("#0A0E1A")))
        sv.background = bgG
        try {
            fontR = Typeface.createFromAsset(assets, "fonts/vazir.ttf")
            fontB = try {
                Typeface.createFromAsset(assets, "fonts/vazir-bold.ttf")
            } catch (e: Exception) {
                fontR
            }
        } catch (e: Exception) {
            fontR = null
            fontB = null
        }
        sv.fitsSystemWindows = true
        sv.layoutDirection = View.LAYOUT_DIRECTION_RTL
        sv.addView(root)
        setContentView(sv)

        // header
        val title = tv("Psiphone abulix", 28f, cYellow, true)
        title.gravity = Gravity.CENTER
        title.letterSpacing = 0.15f
        root.addView(title)
        val sub = tv("CDN Fronting · MASQUE · Beast Mode 🔥", 12f, cSub)
        sub.gravity = Gravity.CENTER
        root.addView(sub)

        // big connect button
        ring = GradientDrawable()
        ring.shape = GradientDrawable.OVAL
        ring.setColor(cCard)
        ring.setStroke(dp(5), cSub)
        btnConn = tv("اتصال", 22f, cText, true)
        btnConn.gravity = Gravity.CENTER
        btnConn.background = ring
        val frame = FrameLayout(this)
        val flp = LinearLayout.LayoutParams(dp(280), dp(280))
        flp.gravity = Gravity.CENTER_HORIZONTAL
        flp.topMargin = dp(6)
        frame.layoutParams = flp
        beast = BeastView(this)
        frame.addView(beast, FrameLayout.LayoutParams(-1, -1))
        val blp = FrameLayout.LayoutParams(dp(150), dp(150))
        blp.gravity = Gravity.CENTER
        btnConn.layoutParams = blp
        frame.addView(btnConn)
        root.addView(frame)

        tvState = tv("قطع", 18f, cText, true)
        tvState.gravity = Gravity.CENTER
        root.addView(tvState)
        tvTime = tv("00:00:00", 15f, cSub)
        tvTime.gravity = Gravity.CENTER
        val tlp = LinearLayout.LayoutParams(-1, -2)
        tlp.bottomMargin = dp(16)
        tvTime.layoutParams = tlp
        root.addView(tvTime)

        // metrics
        val c2 = card()
        val mrow = LinearLayout(this)
        mrow.orientation = LinearLayout.HORIZONTAL
        tvPing = tv("—", 18f, cText, true)
        tvDown = tv("—", 18f, cText, true)
        tvUp = tv("—", 18f, cText, true)
        mrow.addView(metric("پینگ", tvPing))
        mrow.addView(metric("دانلود", tvDown))
        mrow.addView(metric("آپلود", tvUp))
        c2.addView(mrow)
        root.addView(c2)

        // usage chart
        val c2b = card()
        c2b.addView(tv("نمودار مصرف (دانلود زنده)", 12f, cSub))
        chart = SpeedChart(this)
        val chlp = LinearLayout.LayoutParams(-1, dp(110))
        chlp.topMargin = dp(8)
        chlp.bottomMargin = dp(8)
        chart.layoutParams = chlp
        c2b.addView(chart)
        tvUsage = tv("مصرف نشست: —", 13f, cText, true)
        c2b.addView(tvUsage)
        root.addView(c2b)

        // stability
        val c3 = card()
        tvStab = tv("پایداری: —", 15f, cText, true)
        c3.addView(tvStab)
        pbStab = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal)
        pbStab.max = 100
        pbStab.progressTintList = ColorStateList.valueOf(cAccent)
        val plp = LinearLayout.LayoutParams(-1, dp(10))
        plp.topMargin = dp(10)
        pbStab.layoutParams = plp
        c3.addView(pbStab)
        root.addView(c3)

        // exit ip
        val c4 = card()
        c4.addView(tv("IP خروجی (برای تازه‌سازی لمس کنید)", 12f, cSub))
        tvIp = tv("—", 22f, cText, true)
        tvIp.layoutDirection = View.LAYOUT_DIRECTION_LTR
        c4.addView(tvIp)
        tvIpInfo = tv("", 12f, cSub)
        c4.addView(tvIpInfo)
        c4.setOnClickListener {
            if (AbulixVpnService.state == "connected") AbulixVpnService.refreshIp()
        }
        root.addView(c4)

        // scan section
        val c5 = card()
        c5.addView(tv("مدت اسکن", 12f, cSub))
        val crow = LinearLayout(this)
        crow.orientation = LinearLayout.HORIZONTAL
        val clp = LinearLayout.LayoutParams(-1, -2)
        clp.topMargin = dp(8)
        clp.bottomMargin = dp(10)
        crow.layoutParams = clp
        for (m in durations) {
            val chip = tv(if (m < 60) "$m ثانیه" else "${m / 60} دقیقه", 12f, cText)
            chip.gravity = Gravity.CENTER
            chip.setPadding(dp(4), dp(10), dp(4), dp(10))
            val lp = LinearLayout.LayoutParams(0, -2, 1f)
            lp.leftMargin = dp(3)
            lp.rightMargin = dp(3)
            chip.layoutParams = lp
            chip.setOnClickListener {
                if (!scanning) {
                    scanDur = m
                    Store.put(this, "scan_sec", m.toString())
                    styleChips()
                }
            }
            chips.add(chip)
            crow.addView(chip)
        }
        c5.addView(crow)
        styleChips()
        tvScan = tv("", 13f, cText)
        tvScan.layoutDirection = View.LAYOUT_DIRECTION_RTL
        c5.addView(tvScan)
        root.addView(c5)

        // config
        val c6 = card()
        c6.addView(tv("کانفیگ", 12f, cSub))
        tvCfg = tv("—", 13f, cText)
        c6.addView(tvCfg)
        root.addView(c6)

        // import abulix:// link
        val c8 = card()
        c8.addView(tv("ورود لینک abulix:// (فقط مخصوص همین برنامه)", 12f, cSub))
        etLink = EditText(this)
        etLink.hint = "abulix://..."
        etLink.setHintTextColor(cSub)
        etLink.setTextColor(cText)
        etLink.textSize = 12f
        etLink.setSingleLine(true)
        etLink.layoutDirection = View.LAYOUT_DIRECTION_LTR
        c8.addView(etLink)
        val btnLink = button("ورود لینک", cCard2, cAccent)
        btnLink.setOnClickListener { importLink(etLink.text.toString().trim()) }
        c8.addView(btnLink)
        val btnShare = button("اشتراک کانفیگ فعلی", cCard2, cYellow)
        btnShare.setOnClickListener { shareCfg() }
        c8.addView(btnShare)
        root.addView(c8)

        btnScan = button("شروع اسکن", cCard2, cText)
        btnKey = button("دریافت کلید WARP", cCard2, cText)
        root.addView(btnScan)
        root.addView(btnKey)

        val c7 = card()
        tvLog = tv("", 11f, cSub)
        tvLog.typeface = Typeface.MONOSPACE
        tvLog.layoutDirection = View.LAYOUT_DIRECTION_LTR
        c7.addView(tvLog)
        c7.setOnLongClickListener {
            val cm = getSystemService(android.content.ClipboardManager::class.java)
            cm.setPrimaryClip(android.content.ClipData.newPlainText("log", AbulixVpnService.logText()))
            toast("لاگ کپی شد")
            true
        }
        root.addView(c7)

        btnScan.setOnClickListener { doScan() }
        btnKey.setOnClickListener { doKey() }
        btnConn.setOnClickListener { toggle() }

        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 2)
        }
        applyFont(sv)
        for (i in 0 until root.childCount) {
            val v = root.getChildAt(i)
            v.alpha = 0f
            v.translationY = dp(40).toFloat()
            v.animate().alpha(1f).translationY(0f).setStartDelay(i * 70L).setDuration(500)
                .setInterpolator(android.view.animation.DecelerateInterpolator()).start()
        }
        handleLink(intent)
        lastT = SystemClock.elapsedRealtime()
        h.post(object : Runnable {
            override fun run() {
                update()
                h.postDelayed(this, 500)
            }
        })
    }

    private fun applyFont(v: View) {
        if (v is TextView) {
            val bold = v.typeface?.isBold == true
            val f = if (bold) fontB else fontR
            if (f != null && v.typeface != Typeface.MONOSPACE) v.typeface = f
        }
        if (v is android.view.ViewGroup) {
            for (i in 0 until v.childCount) applyFont(v.getChildAt(i))
        }
    }

    private fun splitHp(x: String): Pair<String, String> {
        val i = x.lastIndexOf(':')
        return if (i > 0) Pair(x.substring(0, i), x.substring(i + 1)) else Pair(x, "443")
    }

    private fun importLink(link: String) {
        val m = Share.decode(link)
        if (m == null) {
            toast("لینک معتبر نیست (فقط لینک‌های همین برنامه)")
            return
        }
        for ((k, v) in m) Store.put(this, k, v)
        AbulixVpnService.log("کانفیگ وارد شد: ${m["ep_host"]}:${m["ep_port"]}")
        toast("کانفیگ وارد شد ✅")
    }

    private fun shareCfg() {
        if (Store.get(this, "ep_host").isEmpty()) {
            toast("اول اسکن کنید")
            return
        }
        val link = Share.encode { Store.get(this, it) }
        val i = Intent(Intent.ACTION_SEND)
        i.type = "text/plain"
        i.putExtra(Intent.EXTRA_TEXT, link)
        startActivity(Intent.createChooser(i, "اشتراک کانفیگ"))
    }

    private fun handleLink(i: Intent?) {
        val d = i?.data?.toString() ?: return
        if (d.startsWith("abulix://")) importLink(d)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        handleLink(intent)
    }

    private fun fmtBytes(b: Long): String {
        return when {
            b >= 1073741824L -> String.format(Locale.US, "%.2f GB", b / 1073741824.0)
            b >= 1048576L -> String.format(Locale.US, "%.1f MB", b / 1048576.0)
            b >= 1024L -> String.format(Locale.US, "%.0f KB", b / 1024.0)
            else -> "$b B"
        }
    }

    private fun flagOf(cc: String): String {
        if (cc.length != 2) return "🌍"
        val u = cc.uppercase(Locale.US)
        return String(Character.toChars(0x1F1E6 + (u[0] - 'A'))) + String(Character.toChars(0x1F1E6 + (u[1] - 'A')))
    }

    private fun toast(m: String) {
        Toast.makeText(this, m, Toast.LENGTH_SHORT).show()
    }

    private fun busyVpn(): Boolean {
        val st = AbulixVpnService.state
        return st == "connected" || st == "connecting"
    }

    private fun doScan() {
        if (scanning) {
            Scanner.stop = true
            return
        }
        if (busyVpn()) {
            toast("اول اتصال را قطع کنید")
            return
        }
        scanning = true
        scanStart = SystemClock.elapsedRealtime()
        val dur = scanDur
        thread {
            try {
                if (Store.get(this, "addr4").isEmpty() && Store.get(this, "addr6").isEmpty()) {
                    AbulixVpnService.log("ابتدا کلید WARP گرفته می‌شود...")
                    WarpApi.register(this) { AbulixVpnService.log(it) }
                }
                WarpApi.ensureEnabled(this) { AbulixVpnService.log(it) }
                AbulixVpnService.log("شروع اسکن (${dur} ثانیه)")
                val res = Scanner.scan(this, dur)
                val stat = "${Scanner.tested.get()} تست | TCP: ${Scanner.tcpOk.get()} | TLS+h2: ${Scanner.tlsOk.get()} | تاییدشده: ${Scanner.verified.get()}"
                val errs = Scanner.errors.entries.sortedByDescending { it.value.get() }.take(3)
                    .joinToString(", ") { "${it.key}=${it.value.get()}" }
                if (res.isEmpty()) {
                    AbulixVpnService.log("آی‌پی سالمی پیدا نشد | $stat | خطاها: $errs")
                    if (Scanner.tcpOk.get() > 0 && Scanner.tlsOk.get() == 0) {
                        AbulixVpnService.log("TCP باز است ولی TLS جواب نمی‌دهد؛ احتمالا فیلتر است. اینترنت (وای‌فای/سیم‌کارت) را عوض کنید")
                    }
                } else {
                    val top = res.take(8)
                    Store.put(this, "ep_host", top[0].ip)
                    Store.put(this, "ep_port", "443")
                    Store.put(this, "ep_ms", top[0].ms.toString())
                    Store.put(this, "ep_level", top[0].level.toString())
                    Store.put(this, "ep_list", top.joinToString(",") { "${it.ip}@${it.mode}@${it.sni}" })
                    AbulixVpnService.log("بهترین: ${top[0].ip} (${top[0].ms}ms، سطح ${top[0].level}) | $stat")
                }
            } catch (e: Exception) {
                AbulixVpnService.log("خطای اسکن: ${e.message}")
            }
            scanning = false
        }
    }

    private fun doKey() {
        if (gettingKey) return
        if (busyVpn()) {
            toast("اول اتصال را قطع کنید")
            return
        }
        gettingKey = true
        btnKey.isEnabled = false
        btnKey.text = "در حال دریافت..."
        thread {
            val ok = WarpApi.register(this) { AbulixVpnService.log(it) }
            AbulixVpnService.log(if (ok) "کلید WARP دریافت شد" else "دریافت کلید ناموفق بود")
            h.post {
                btnKey.text = "دریافت کلید WARP"
                btnKey.isEnabled = true
                gettingKey = false
            }
        }
    }

    private fun toggle() {
        if (busyVpn()) {
            startService(Intent(this, AbulixVpnService::class.java).setAction(AbulixVpnService.ACTION_STOP))
            return
        }
        if (scanning) {
            toast("اسکن در حال انجام است")
            return
        }
        if (Store.get(this, "ep_host").isEmpty()) {
            toast("اول اسکن کنید")
            return
        }
        if (Store.get(this, "addr4").isEmpty() && Store.get(this, "addr6").isEmpty()) {
            toast("اول کلید WARP بگیرید")
            return
        }
        val i = VpnService.prepare(this)
        if (i != null) startActivityForResult(i, 77) else startVpn()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 77 && resultCode == RESULT_OK) startVpn()
    }

    private fun startVpn() {
        val i = Intent(this, AbulixVpnService::class.java).setAction(AbulixVpnService.ACTION_START)
        startForegroundService(i)
    }

    private fun fmtSpeed(bps: Double): String {
        return when {
            bps >= 1048576.0 -> String.format(Locale.US, "%.1f MB/s", bps / 1048576.0)
            bps >= 1024.0 -> String.format(Locale.US, "%.0f KB/s", bps / 1024.0)
            else -> String.format(Locale.US, "%.0f B/s", bps)
        }
    }

    private fun mmss(sec: Long): String = String.format(Locale.US, "%02d:%02d", sec / 60, sec % 60)

    private fun setRing(color: Int) {
        ring.setStroke(dp(5), color)
    }

    private fun update() {
        tick++
        val st = AbulixVpnService.state
        beast.mode = when (st) { "connected" -> 2; "connecting" -> 1; "error" -> 3; else -> 0 }
        beast.target = when (st) { "connected" -> cAccent; "connecting" -> cYellow; "error" -> cRed; else -> cSub }
        when (st) {
            "connected" -> {
                btnConn.animate().scaleX(1f).scaleY(1f).setDuration(200).start()
                setRing(cAccent)
                btnConn.text = "قطع"
                btnConn.setTextColor(cAccent)
                tvState.text = "متصل"
                tvState.setTextColor(cAccent)
            }
            "connecting" -> {
                setRing(if (tick % 2 == 0) cYellow else cCard2)
                val sc = if (tick % 2 == 0) 1.07f else 1f
                btnConn.animate().scaleX(sc).scaleY(sc).setDuration(450).start()
                btnConn.text = "..."
                btnConn.setTextColor(cYellow)
                tvState.text = "در حال اتصال..."
                tvState.setTextColor(cYellow)
            }
            "error" -> {
                setRing(cRed)
                btnConn.text = "اتصال"
                btnConn.setTextColor(cText)
                tvState.text = AbulixVpnService.message.ifEmpty { "خطا" }
                tvState.setTextColor(cRed)
            }
            else -> {
                setRing(cSub)
                btnConn.text = "اتصال"
                btnConn.setTextColor(cText)
                tvState.text = if (AbulixVpnService.message.isEmpty()) "قطع" else AbulixVpnService.message
                tvState.setTextColor(cText)
            }
        }

        if (st == "connected") {
            val s = (System.currentTimeMillis() - AbulixVpnService.connectedAt) / 1000
            tvTime.text = String.format(Locale.US, "%02d:%02d:%02d", s / 3600, (s / 60) % 60, s % 60)
            val now = SystemClock.elapsedRealtime()
            val dt = (now - lastT).coerceAtLeast(1) / 1000.0
            val rx = AbulixVpnService.rx
            val tx = AbulixVpnService.tx
            val dbps = (rx - lastRx) / dt
            chart.push(dbps.toFloat().coerceAtLeast(0f))
            tvUsage.text = "مصرف نشست:  ⬇ ${fmtBytes(rx)}    ⬆ ${fmtBytes(tx)}"
            tvDown.text = fmtSpeed(dbps)
            tvUp.text = fmtSpeed((tx - lastTx) / dt)
            lastRx = rx
            lastTx = tx
            lastT = now
            val r = AbulixVpnService.rtt
            tvPing.text = if (r >= 0) "$r ms" else "—"
            val sb = AbulixVpnService.stability
            val lbl = when {
                sb >= 90 -> "عالی"
                sb >= 70 -> "خوب"
                sb >= 40 -> "ضعیف"
                else -> "ناپایدار"
            }
            tvStab.text = "پایداری: $sb% ($lbl)"
            pbStab.progress = sb
            pbStab.progressTintList = ColorStateList.valueOf(
                if (sb >= 70) cAccent else if (sb >= 40) cYellow else cRed
            )
            tvIp.text = AbulixVpnService.exitIp.ifEmpty { "..." }
            val ccm = Regex("کشور: ([A-Za-z]{2})").find(AbulixVpnService.exitInfo)
            tvIpInfo.text = if (ccm != null) flagOf(ccm.groupValues[1]) + "  " + AbulixVpnService.exitInfo else AbulixVpnService.exitInfo
        } else {
            tvTime.text = "00:00:00"
            tvDown.text = "—"
            tvUp.text = "—"
            tvPing.text = "—"
            tvStab.text = "پایداری: —"
            pbStab.progress = 0
            tvIp.text = "—"
            tvIpInfo.text = ""
            chart.clear()
            tvUsage.text = "مصرف نشست: —"
            lastRx = 0
            lastTx = 0
            lastT = SystemClock.elapsedRealtime()
        }

        // scan status
        if (scanning) {
            val el = (SystemClock.elapsedRealtime() - scanStart) / 1000
            val b = Scanner.best
            tvScan.text = "در حال اسکن ${mmss(el)} / ${mmss(scanDur.toLong())}" +
                "\nتست‌شده: ${Scanner.tested.get()} | TCP: ${Scanner.tcpOk.get()} | TLS+h2: ${Scanner.tlsOk.get()} | تاییدشده: ${Scanner.verified.get()}" +
                (if (b != null) "\nبهترین تا الان: ${b.ip} (${b.ms}ms، سطح ${b.level})" else "")
            btnScan.text = "توقف اسکن"
        } else {
            btnScan.text = "شروع اسکن"
            if (Scanner.tested.get() > 0 && tvScan.text.isEmpty()) tvScan.text = ""
            if (!scanning && tvScan.text.startsWith("در حال")) tvScan.text = "اسکن تمام شد"
        }

        val host = Store.get(this, "ep_host")
        val a4 = Store.get(this, "addr4")
        val a6 = Store.get(this, "addr6")
        val ms = Store.get(this, "ep_ms")
        tvCfg.text = "Endpoint: " +
            (if (host.isEmpty()) "— (اسکن نشده)" else "$host:${Store.get(this, "ep_port", "443")}" + (if (ms.isNotEmpty()) " (${ms}ms)" else "")) +
            "\nپروتکل: MASQUE (CONNECT-IP) روی HTTP/2" +
            "\nIPv4 تونل: " + (if (a4.isEmpty()) "—" else a4) +
            "\nIPv6 تونل: " + (if (a6.isEmpty()) "—" else a6)

        val lines = AbulixVpnService.logText().trimEnd().lines()
        tvLog.text = lines.takeLast(14).joinToString("\n")
    }
}
