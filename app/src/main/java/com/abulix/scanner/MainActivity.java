package com.abulix.scanner;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class MainActivity extends Activity {
    private WebView web;
    private final ExecutorService pool = Executors.newFixedThreadPool(48);

    private static long ms(long t0) { return (System.nanoTime() - t0) / 1000000; }

    private void js(final String code) {
        runOnUiThread(() -> web.evaluateJavascript(code, null));
    }

    class Bridge {
        /** Stage 1: real TCP connect time. */
        @JavascriptInterface
        public void tcp(final String id, final String ip, final int port, final int timeout) {
            pool.execute(() -> {
                long t = System.nanoTime();
                long r = -1;
                Socket s = new Socket();
                try {
                    s.connect(new InetSocketAddress(ip, port), timeout);
                    r = ms(t);
                } catch (Exception e) {
                } finally {
                    try { s.close(); } catch (Exception e) {}
                }
                js("window.onTcp('" + id + "'," + r + ")");
            });
        }

        /** Stage 2: full test with the user's config: TCP + TLS(SNI) + HTTP/WebSocket upgrade with Host/path. */
        @JavascriptInterface
        public void full(final String id, final String ip, final int port, final boolean tls,
                         final String sni, final String host, final String path, final int timeout) {
            pool.execute(() -> {
                long t0 = System.nanoTime();
                long tcp = -1, hs = -1, total = -1;
                int status = 0;
                Socket s = null;
                try {
                    Socket raw = new Socket();
                    raw.connect(new InetSocketAddress(ip, port), timeout);
                    raw.setSoTimeout(timeout);
                    tcp = ms(t0);
                    s = raw;
                    if (tls) {
                        SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
                        SSLSocket ss = (SSLSocket) f.createSocket(raw, sni, port, true);
                        ss.startHandshake();
                        s = ss;
                    }
                    hs = ms(t0);
                    String req = "GET " + path + " HTTP/1.1\r\nHost: " + host
                            + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                            + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
                            + "User-Agent: Mozilla/5.0\r\n\r\n";
                    s.getOutputStream().write(req.getBytes("UTF-8"));
                    s.getOutputStream().flush();
                    InputStream in = s.getInputStream();
                    StringBuilder sb = new StringBuilder();
                    int c, n = 0;
                    while (n++ < 256 && (c = in.read()) != -1 && c != '\n') sb.append((char) c);
                    String line = sb.toString().trim();
                    if (line.startsWith("HTTP/")) {
                        String[] p = line.split(" ");
                        if (p.length > 1) status = Integer.parseInt(p[1]);
                    }
                    total = ms(t0);
                } catch (Exception e) {
                } finally {
                    try { if (s != null) s.close(); } catch (Exception e) {}
                }
                js("window.onFull('" + id + "',{tcp:" + tcp + ",hs:" + hs + ",total:" + total + ",status:" + status + "})");
            });
        }

        @JavascriptInterface
        public void copy(final String text) {
            runOnUiThread(() -> {
                ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                cm.setPrimaryClip(ClipData.newPlainText("cfg", text));
            });
        }

        @JavascriptInterface
        public void open(final String url) {
            runOnUiThread(() -> startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url))));
        }
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setStatusBarColor(Color.parseColor("#0d0720"));
        getWindow().setNavigationBarColor(Color.parseColor("#0d0720"));
        web = new WebView(this);
        web.setBackgroundColor(Color.parseColor("#0d0720"));
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        web.addJavascriptInterface(new Bridge(), "Native");
        web.setWebViewClient(new WebViewClient());
        setContentView(web);
        web.loadUrl("file:///android_asset/index.html");
    }
}
