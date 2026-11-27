package ir.abulix.psiphone

import android.animation.ArgbEvaluator
import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.Shader
import android.graphics.SweepGradient
import android.graphics.RectF
import android.os.SystemClock
import android.view.View
import android.view.animation.LinearInterpolator
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

/** Animated aura behind the connect button: ripples, spinning arcs, orbiting sparks. */
class BeastView(ctx: Context) : View(ctx) {
    var mode = 0                      // 0 idle, 1 connecting, 2 connected, 3 error
    var target = Color.GRAY
    private var cur = Color.GRAY
    private val ev = ArgbEvaluator()
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private var rot = 0f
    private var ph = 0f
    private var last = 0L
    private val rect = RectF()
    private val d = resources.displayMetrics.density

    private val anim = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = 1000
        repeatCount = ValueAnimator.INFINITE
        interpolator = LinearInterpolator()
        addUpdateListener { step(); invalidate() }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        last = SystemClock.uptimeMillis()
        anim.start()
    }

    override fun onDetachedFromWindow() {
        anim.cancel()
        super.onDetachedFromWindow()
    }

    private fun step() {
        val now = SystemClock.uptimeMillis()
        val dt = (now - last).coerceIn(0, 50) / 1000f
        last = now
        val sp = when (mode) { 2 -> 1f; 1 -> 3.2f; 3 -> 0.5f; else -> 0.35f }
        rot = (rot + dt * 100f * sp) % 360f
        ph = (ph + dt * 0.45f * sp) % 1f
        cur = ev.evaluate(0.10f, cur, target) as Int
    }

    private fun a(c: Int, alpha: Int): Int = (c and 0x00FFFFFF) or (alpha.coerceIn(0, 255) shl 24)

    override fun onDraw(canvas: Canvas) {
        val cx = width / 2f
        val cy = height / 2f
        val maxR = min(width, height) / 2f
        val core = maxR * 0.56f
        val active = mode == 1 || mode == 2

        // soft glow
        paint.reset(); paint.isAntiAlias = true
        paint.shader = RadialGradient(cx, cy, core * 1.7f, intArrayOf(a(cur, if (active) 120 else 50), Color.TRANSPARENT), null, Shader.TileMode.CLAMP)
        canvas.drawCircle(cx, cy, core * 1.7f, paint)

        // expanding ripples
        for (i in 0 until 3) {
            val f = (ph + i / 3f) % 1f
            val r = core + (maxR - core) * f
            paint.reset(); paint.isAntiAlias = true
            paint.style = Paint.Style.STROKE
            paint.strokeWidth = 2.5f * d
            paint.color = a(cur, ((1f - f) * (if (active) 140 else 45)).toInt())
            canvas.drawCircle(cx, cy, r, paint)
        }

        // spinning sweep arcs (two, opposite directions)
        val sweep = SweepGradient(cx, cy, intArrayOf(Color.TRANSPARENT, cur, Color.TRANSPARENT), floatArrayOf(0f, 0.5f, 1f))
        paint.reset(); paint.isAntiAlias = true
        paint.style = Paint.Style.STROKE
        paint.strokeCap = Paint.Cap.ROUND
        paint.shader = sweep
        paint.strokeWidth = 5f * d
        var r1 = core + 10f * d
        rect.set(cx - r1, cy - r1, cx + r1, cy + r1)
        canvas.save(); canvas.rotate(rot, cx, cy); canvas.drawArc(rect, 0f, 360f, false, paint); canvas.restore()
        paint.strokeWidth = 3f * d
        paint.alpha = 150
        r1 = core + 22f * d
        rect.set(cx - r1, cy - r1, cx + r1, cy + r1)
        canvas.save(); canvas.rotate(-rot * 1.6f, cx, cy); canvas.drawArc(rect, 0f, 360f, false, paint); canvas.restore()

        // orbiting sparks
        if (active) {
            paint.reset(); paint.isAntiAlias = true
            paint.style = Paint.Style.FILL
            val n = 16
            for (i in 0 until n) {
                val ang = (i * 2.0 * PI / n) + Math.toRadians((rot * 1.4f).toDouble())
                val rr = core + 36f * d + (sin((ph * 2.0 * PI) + i).toFloat()) * 5f * d
                val x = cx + (cos(ang) * rr).toFloat()
                val y = cy + (sin(ang) * rr).toFloat()
                paint.color = a(cur, 90 + ((i % 4) * 40))
                canvas.drawCircle(x, y, (1.6f + (i % 3) * 0.8f) * d, paint)
            }
        }
    }
}

/** Live download-speed chart (last ~45 s). */
class SpeedChart(ctx: Context) : View(ctx) {
    private val data = ArrayList<Float>()
    private val line = Paint(Paint.ANTI_ALIAS_FLAG)
    private val fill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val grid = Paint(Paint.ANTI_ALIAS_FLAG)
    private val d = resources.displayMetrics.density
    private val path = android.graphics.Path()
    private val fpath = android.graphics.Path()
    private val maxPts = 90

    init {
        line.style = Paint.Style.STROKE
        line.strokeWidth = 2.5f * d
        line.strokeCap = Paint.Cap.ROUND
        line.strokeJoin = Paint.Join.ROUND
        line.color = Color.parseColor("#00E5A8")
        grid.color = Color.parseColor("#26304F")
        grid.strokeWidth = 1f * d
    }

    fun push(v: Float) {
        data.add(v)
        while (data.size > maxPts) data.removeAt(0)
        invalidate()
    }

    fun clear() {
        data.clear()
        invalidate()
    }

    override fun onSizeChanged(w: Int, h: Int, ow: Int, oh: Int) {
        fill.shader = LinearGradient(0f, 0f, 0f, h.toFloat(), Color.parseColor("#6600E5A8"), Color.TRANSPARENT, Shader.TileMode.CLAMP)
    }

    override fun onDraw(canvas: Canvas) {
        val w = width.toFloat()
        val h = height.toFloat()
        for (i in 1..3) canvas.drawLine(0f, h * i / 4f, w, h * i / 4f, grid)
        if (data.size < 2) return
        var mx = 1024f
        for (v in data) if (v > mx) mx = v
        mx *= 1.15f
        val dx = w / (maxPts - 1)
        path.reset(); fpath.reset()
        val off = w - (data.size - 1) * dx
        for (i in data.indices) {
            val x = off + i * dx
            val y = h - (data[i] / mx) * h
            if (i == 0) { path.moveTo(x, y); fpath.moveTo(x, h); fpath.lineTo(x, y) } else { path.lineTo(x, y); fpath.lineTo(x, y) }
        }
        fpath.lineTo(w, h); fpath.close()
        canvas.drawPath(fpath, fill)
        canvas.drawPath(path, line)
    }
}
