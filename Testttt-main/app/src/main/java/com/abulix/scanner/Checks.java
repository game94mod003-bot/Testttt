package com.abulix.scanner;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Locale;

/** Test routines. Every method returns a small JSON string (or "ip:ms" for tcp) and never throws. */
final class Checks {

    static volatile boolean stop = false;

    static Tunnel.Cfg cfg(String type, String id, int port, boolean tls, String sni, String host, String path) {
        Tunnel.Cfg c = new Tunnel.Cfg();
        c.vless = "vless".equalsIgnoreCase(type);
        if (c.vless) {
            String h = id.replace("-", "");
            byte[] b = new byte[16];
            for (int i = 0; i < 16; i++) {
                b[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
            }
            c.uuid = b;
        } else {
            c.password = id;
        }
        c.port = port;
        c.tls = tls;
        c.sni = sni;
        c.host = host;
        c.path = (path == null || path.length() == 0) ? "/" : path;
        return c;
    }

    static String san(Throwable t) {
        String m = t.getClass().getSimpleName() + ":" + t.getMessage();
        m = m.replaceAll("[^A-Za-z0-9 :._/-]", "_");
        return m.length() > 70 ? m.substring(0, 70) : m;
    }

    private static void close(Tunnel t) {
        if (t != null) {
            t.close();
        }
    }

    /** Real TCP connect time. */
    static String tcp(String ip, int port, int timeout) {
        long t = System.nanoTime();
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(ip, port), timeout);
            return ip + ":" + Tunnel.ms(t);
        } catch (Throwable e) {
            return null;
        } finally {
            try {
                s.close();
            } catch (Throwable x) {
                // ignore
            }
        }
    }

    private static long site(String ip, Tunnel.Cfg c, String host) {
        Tunnel t = null;
        try {
            t = new Tunnel(c);
            t.open(ip, 3500);
            Tunnel.Res r = t.fetch(host, 80, "/", 4000, 1);
            return r.status > 0 ? r.ttfb : -1;
        } catch (Throwable e) {
            return -1;
        } finally {
            close(t);
        }
    }

    /** Opens the tunnel, checks data really passes (generate_204), then measures latency to YouTube/Telegram/fast.com. */
    static String tunnel(String ip, Tunnel.Cfg c) {
        long setup = -1;
        long gen = -1;
        long yt = -1;
        long tg = -1;
        long fa = -1;
        String err = "";
        boolean ok = false;
        Tunnel t = null;
        try {
            t = new Tunnel(c);
            t.open(ip, 3500);
            setup = t.setupMs;
            Tunnel.Res r = t.fetch("connectivitycheck.gstatic.com", 80, "/generate_204", 4500, 1);
            if (r.status > 0) {
                ok = true;
                gen = r.ttfb;
            } else {
                err = "nohttp";
            }
        } catch (Throwable e) {
            err = san(e);
        } finally {
            close(t);
        }
        if (ok) {
            yt = site(ip, c, "www.youtube.com");
            tg = site(ip, c, "telegram.org");
            fa = site(ip, c, "fast.com");
        }
        return "{\"ip\":\"" + ip + "\",\"ok\":" + ok + ",\"setup\":" + setup + ",\"gen\":" + gen
                + ",\"yt\":" + yt + ",\"tg\":" + tg + ",\"fast\":" + fa + ",\"err\":\"" + err + "\"}";
    }

    private static final String[][] SRC = {
        {"speedtest.tele2.net", "/10MB.zip", "tele2"},
        {"ipv4.download.thinkbroadband.com", "/10MB.zip", "thinkbb"},
        {"cachefly.cachefly.net", "/10mb.test", "cachefly"}
    };

    /** Download speed through the tunnel (plain HTTP test files). */
    static String speed(String ip, Tunnel.Cfg c, int seconds) {
        String err = "";
        for (String[] s : SRC) {
            Tunnel t = null;
            try {
                t = new Tunnel(c);
                t.open(ip, 3500);
                Tunnel.Res r = t.fetch(s[0], 80, s[1], seconds * 1000L, 30L * 1024 * 1024);
                long body = r.bytes - r.firstLen;
                if (r.status == 200 && body > 50000 && r.dlMs > 0) {
                    double mbps = body * 8.0 / (r.dlMs * 1000.0);
                    return "{\"ip\":\"" + ip + "\",\"mbps\":" + String.format(Locale.US, "%.2f", mbps)
                            + ",\"mb\":" + String.format(Locale.US, "%.2f", r.bytes / 1048576.0)
                            + ",\"src\":\"" + s[2] + "\",\"err\":\"\"}";
                }
                err = "status" + r.status + " bytes" + r.bytes;
            } catch (Throwable e) {
                err = san(e);
            } finally {
                close(t);
            }
        }
        return "{\"ip\":\"" + ip + "\",\"mbps\":0,\"mb\":0,\"src\":\"\",\"err\":\"" + err.replace("\"", "_") + "\"}";
    }

    private static final String GEM = "generativelanguage.googleapis.com";

    private static String classify(int code, String b, boolean key, boolean full) {
        if (b.contains("location is not supported")) {
            return "REGION";
        }
        if (b.contains("api key not valid") || b.contains("api_key_invalid")) {
            return key ? "KEYBAD" : "REACHABLE";
        }
        if (code == 200) {
            if (!key) {
                return "REACHABLE";
            }
            return full ? (b.contains("candidates") ? "OK" : "BADRESP") : (b.contains("models") ? "LISTOK" : "BADRESP");
        }
        if (code == 429) {
            return "QUOTA";
        }
        if (code >= 500) {
            return "SERVER";
        }
        if (code == 403) {
            return key ? "FORBIDDEN" : "REACHABLE";
        }
        if (code == 400 || code == 401 || code == 404) {
            return key ? "APIERR" : "REACHABLE";
        }
        return "OTHER";
    }

    /** Gemini reachability through the tunnel. full=false: models list (cheap); full=true: real generateContent (needs key). */
    static String gemini(String ip, Tunnel.Cfg c, String key, boolean full) {
        String g;
        int code = 0;
        long ms = -1;
        Tunnel t = null;
        try {
            boolean hk = key != null && key.length() > 0;
            t = new Tunnel(c);
            t.open(ip, 3500);
            Tunnel.Res r;
            if (full && hk) {
                r = t.fetchTls(GEM, 443, "POST", "/v1beta/models/gemini-flash-latest:generateContent",
                        "x-goog-api-key: " + key + "\r\nContent-Type: application/json\r\n",
                        "{\"contents\":[{\"parts\":[{\"text\":\"Reply with the single word: ok\"}]}],\"generationConfig\":{\"maxOutputTokens\":16}}", 10000);
            } else {
                r = t.fetchTls(GEM, 443, "GET", "/v1beta/models?pageSize=1",
                        hk ? "x-goog-api-key: " + key + "\r\n" : "", "", 9000);
            }
            code = r.status;
            ms = r.ttfb;
            g = classify(code, r.text.toLowerCase(Locale.US), hk, full);
        } catch (SocketTimeoutException e) {
            g = "TIMEOUT";
        } catch (Throwable e) {
            g = "NETERR";
        } finally {
            close(t);
        }
        return "{\"ip\":\"" + ip + "\",\"g\":\"" + g + "\",\"code\":" + code + ",\"ms\":" + ms + "}";
    }

    /** Connecting + stability: several consecutive real tunnel connects, latency spread and failure ratio. */
    static String stab(String ip, Tunnel.Cfg c, int rounds) {
        long[] v = new long[rounds];
        int ok = 0;
        int to = 0;
        int n = 0;
        long t0 = System.nanoTime();
        for (int i = 0; i < rounds && !stop; i++) {
            n++;
            Tunnel t = null;
            long s = System.nanoTime();
            try {
                t = new Tunnel(c);
                t.open(ip, 3000);
                Tunnel.Res r = t.fetch("connectivitycheck.gstatic.com", 80, "/generate_204", 3500, 1);
                if (r.status > 0) {
                    v[ok++] = Tunnel.ms(s);
                }
            } catch (SocketTimeoutException e) {
                to++;
            } catch (Throwable e) {
                // failed attempt
            } finally {
                close(t);
            }
            try {
                Thread.sleep(120);
            } catch (InterruptedException e) {
                break;
            }
        }
        long sum = 0;
        long mn = 0;
        long mx = 0;
        for (int i = 0; i < ok; i++) {
            sum += v[i];
            mn = i == 0 ? v[i] : Math.min(mn, v[i]);
            mx = Math.max(mx, v[i]);
        }
        long avg = ok > 0 ? sum / ok : 0;
        double var = 0;
        for (int i = 0; i < ok; i++) {
            var += (v[i] - avg) * (double) (v[i] - avg);
        }
        long sd = ok > 1 ? (long) Math.sqrt(var / ok) : 0;
        String st;
        if (ok == 0) {
            st = to * 2 >= n ? "TIMEOUT" : "FAILED";
        } else if (ok == n && sd <= Math.max(40, avg / 2)) {
            st = "CONNECTED";
        } else {
            st = "UNSTABLE";
        }
        return "{\"ip\":\"" + ip + "\",\"ok\":" + (ok > 0) + ",\"n\":" + n + ",\"succ\":" + ok + ",\"to\":" + to
                + ",\"avg\":" + avg + ",\"min\":" + mn + ",\"max\":" + mx + ",\"sd\":" + sd
                + ",\"ms\":" + Tunnel.ms(t0) + ",\"status\":\"" + st + "\"}";
    }
}
