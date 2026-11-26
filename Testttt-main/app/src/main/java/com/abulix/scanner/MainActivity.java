package com.abulix.scanner;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.PowerManager;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.util.ArrayList;
import java.util.Collections;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class MainActivity extends Activity {

    private WebView web;
    private volatile boolean cancel = false;
    private PowerManager.WakeLock wl;

    interface Task {
        String run(String ip) throws Exception;
    }

    private void js(final String code) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (web != null) {
                    web.evaluateJavascript(code, null);
                }
            }
        });
    }

    private static String q(String s) {
        return "'" + s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "") + "'";
    }

    private void keepOn(final boolean on) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                try {
                    if (on) {
                        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
                        if (wl == null) {
                            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
                            wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "abulix:scan");
                        }
                        if (!wl.isHeld()) {
                            wl.acquire(2 * 60 * 60 * 1000L);
                        }
                    } else {
                        getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
                        if (wl != null && wl.isHeld()) {
                            wl.release();
                        }
                    }
                } catch (Throwable e) {
                    // ignore
                }
            }
        });
    }

    private static long lat(String s) {
        int i = s.lastIndexOf(':');
        try {
            return Long.parseLong(s.substring(i + 1));
        } catch (Exception e) {
            return Long.MAX_VALUE;
        }
    }

    private static String finish(String kind, ConcurrentLinkedQueue<String> res) {
        ArrayList<String> l = new ArrayList<String>(res);
        boolean quote = false;
        if (kind.equals("tcp")) {
            quote = true;
            Collections.sort(l, new java.util.Comparator<String>() {
                @Override
                public int compare(String a, String b) {
                    return Long.compare(lat(a), lat(b));
                }
            });
            if (l.size() > 800) {
                l = new ArrayList<String>(l.subList(0, 800));
            }
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < l.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            if (quote) {
                sb.append('"').append(l.get(i)).append('"');
            } else {
                sb.append(l.get(i));
            }
        }
        return sb.append(']').toString();
    }

    private static String[] split(String csv) {
        ArrayList<String> l = new ArrayList<String>();
        for (String s : csv.split(",")) {
            String t = s.trim();
            if (t.length() > 0) {
                l.add(t);
            }
        }
        return l.toArray(new String[0]);
    }

    private void job(final String kind, final String[] ips, final int threads, final Task task) {
        cancel = false;
        Checks.stop = false;
        keepOn(true);
        final int nt = Math.max(1, Math.min(threads, 600));
        new Thread(new Runnable() {
            @Override
            public void run() {
                final ExecutorService ex = Executors.newFixedThreadPool(nt, new java.util.concurrent.ThreadFactory() {
                    @Override
                    public Thread newThread(final Runnable r) {
                        Thread t = new Thread(new Runnable() {
                            @Override
                            public void run() {
                                try {
                                    android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_FOREGROUND);
                                } catch (Throwable e) {
                                    // ignore
                                }
                                r.run();
                            }
                        });
                        t.setDaemon(true);
                        return t;
                    }
                });
                final AtomicInteger cnt = new AtomicInteger();
                final AtomicInteger okc = new AtomicInteger();
                final ConcurrentLinkedQueue<String> res = new ConcurrentLinkedQueue<String>();
                final int total = ips.length;
                for (final String ip : ips) {
                    ex.execute(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                if (!cancel) {
                                    String r = task.run(ip);
                                    if (r != null) {
                                        res.add(r);
                                        if (!r.contains("\"ok\":false")) {
                                            okc.incrementAndGet();
                                        }
                                    }
                                }
                            } catch (Throwable e) {
                                // ignore
                            }
                            cnt.incrementAndGet();
                        }
                    });
                }
                ex.shutdown();
                try {
                    while (!ex.awaitTermination(250, TimeUnit.MILLISECONDS)) {
                        js("window.onProg('" + kind + "'," + cnt.get() + "," + total + "," + okc.get() + ")");
                    }
                } catch (InterruptedException e) {
                    // ignore
                }
                js("window.onProg('" + kind + "'," + total + "," + total + "," + okc.get() + ")");
                String outJson = finish(kind, res);
                js("window.onJobDone('" + kind + "'," + q(outJson) + ")");
                keepOn(false);
            }
        }).start();
    }

    class Bridge {
        @JavascriptInterface
        public void scanTcp(final String csv, final int port, final int timeout, final int threads) {
            try {
                job("tcp", split(csv), threads, new Task() {
                    @Override
                    public String run(String ip) {
                        return Checks.tcp(ip, port, timeout);
                    }
                });
            } catch (Throwable e) {
                js("window.onJobDone('tcp','[]')");
            }
        }

        @JavascriptInterface
        public void tunnelBatch(final String csv, String type, String id, int port, boolean tls,
                                String sni, String host, String path, int threads) {
            try {
                final Tunnel.Cfg c = Checks.cfg(type, id, port, tls, sni, host, path);
                job("tun", split(csv), threads, new Task() {
                    @Override
                    public String run(String ip) {
                        return Checks.tunnel(ip, c);
                    }
                });
            } catch (Throwable e) {
                js("window.onJobDone('tun','[]')");
            }
        }

        @JavascriptInterface
        public void speedBatch(final String csv, String type, String id, int port, boolean tls,
                               String sni, String host, String path, final int seconds, int threads) {
            try {
                final Tunnel.Cfg c = Checks.cfg(type, id, port, tls, sni, host, path);
                job("spd", split(csv), threads, new Task() {
                    @Override
                    public String run(String ip) {
                        return Checks.speed(ip, c, seconds);
                    }
                });
            } catch (Throwable e) {
                js("window.onJobDone('spd','[]')");
            }
        }

        @JavascriptInterface
        public void stabBatch(final String csv, String type, String id, int port, boolean tls,
                              String sni, String host, String path, final int rounds, int threads) {
            try {
                final Tunnel.Cfg c = Checks.cfg(type, id, port, tls, sni, host, path);
                job("stb", split(csv), threads, new Task() {
                    @Override
                    public String run(String ip) {
                        return Checks.stab(ip, c, rounds);
                    }
                });
            } catch (Throwable e) {
                js("window.onJobDone('stb','[]')");
            }
        }

        @JavascriptInterface
        public void geminiBatch(final String csv, String type, String id, int port, boolean tls,
                                String sni, String host, String path, final String key, final boolean full, int threads) {
            try {
                final Tunnel.Cfg c = Checks.cfg(type, id, port, tls, sni, host, path);
                job("gem", split(csv), threads, new Task() {
                    @Override
                    public String run(String ip) {
                        return Checks.gemini(ip, c, key, full);
                    }
                });
            } catch (Throwable e) {
                js("window.onJobDone('gem','[]')");
            }
        }

        @JavascriptInterface
        public String deviceInfo() {
            int mem = ((android.app.ActivityManager) getSystemService(Context.ACTIVITY_SERVICE)).getMemoryClass();
            return "{\"cores\":" + Runtime.getRuntime().availableProcessors() + ",\"mem\":" + mem + "}";
        }

        @JavascriptInterface
        public void share(final String text) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Intent i = new Intent(Intent.ACTION_SEND);
                        i.setType("text/plain");
                        i.putExtra(Intent.EXTRA_TEXT, text);
                        startActivity(Intent.createChooser(i, "Export"));
                    } catch (Throwable e) {
                        // ignore
                    }
                }
            });
        }

        @JavascriptInterface
        public String saveFile(String name, String text) {
            try {
                java.io.File d = getExternalFilesDir(null);
                if (d == null) {
                    d = getFilesDir();
                }
                java.io.File f = new java.io.File(d, name.replaceAll("[^A-Za-z0-9._-]", "_"));
                java.io.FileOutputStream o = new java.io.FileOutputStream(f);
                o.write(text.getBytes("UTF-8"));
                o.close();
                return f.getAbsolutePath();
            } catch (Throwable e) {
                return "";
            }
        }

        @JavascriptInterface
        public void cancel() {
            cancel = true;
            Checks.stop = true;
        }

        @JavascriptInterface
        public void copy(final String text) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                    cm.setPrimaryClip(ClipData.newPlainText("cfg", text));
                }
            });
        }

        @JavascriptInterface
        public void open(final String url) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
                    } catch (Throwable e) {
                        // ignore
                    }
                }
            });
        }
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setStatusBarColor(Color.parseColor("#04070d"));
        getWindow().setNavigationBarColor(Color.parseColor("#04070d"));
        web = new WebView(this);
        web.setBackgroundColor(Color.parseColor("#04070d"));
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        web.addJavascriptInterface(new Bridge(), "Native");
        web.setWebViewClient(new WebViewClient());
        setContentView(web);
        web.loadUrl("file:///android_asset/index.html");
    }

    @Override
    protected void onDestroy() {
        cancel = true;
        Checks.stop = true;
        try {
            if (wl != null && wl.isHeld()) {
                wl.release();
            }
        } catch (Throwable e) {
            // ignore
        }
        super.onDestroy();
    }
}
