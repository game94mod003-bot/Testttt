package com.abulix.scanner;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** Minimal VLESS / Trojan over WebSocket (optionally TLS) client used to test that data really passes. */
final class Tunnel {

    static final class Cfg {
        boolean vless;
        byte[] uuid;
        String password = "";
        int port;
        boolean tls;
        String sni;
        String host;
        String path;
    }

    static final class Res {
        long ttfb = -1;
        int status;
        long bytes;
        long firstLen;
        long dlMs;
        String text = "";
    }

    private static final SecureRandom RND = new SecureRandom();
    private final Cfg cfg;
    private Socket sock;
    private OutputStream out;
    private BufferedInputStream in;
    private boolean respHdrDone;
    long setupMs;

    Tunnel(Cfg c) {
        cfg = c;
    }

    static long ms(long t0) {
        return (System.nanoTime() - t0) / 1000000L;
    }

    private static String b64(byte[] d) {
        String a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < d.length; i += 3) {
            int b0 = d[i] & 255;
            int b1 = i + 1 < d.length ? d[i + 1] & 255 : 0;
            int b2 = i + 2 < d.length ? d[i + 2] & 255 : 0;
            int n = (b0 << 16) | (b1 << 8) | b2;
            sb.append(a.charAt((n >> 18) & 63)).append(a.charAt((n >> 12) & 63));
            sb.append(i + 1 < d.length ? a.charAt((n >> 6) & 63) : '=');
            sb.append(i + 2 < d.length ? a.charAt(n & 63) : '=');
        }
        return sb.toString();
    }

    private static String sha224hex(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-224");
        byte[] h = md.digest(s.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte b : h) {
            sb.append(String.format("%02x", b & 255));
        }
        return sb.toString();
    }

    /** TCP + optional TLS (SNI) + WebSocket upgrade to the given edge IP. */
    void open(String ip, int timeoutMs) throws Exception {
        long t0 = System.nanoTime();
        Socket raw = new Socket();
        raw.setTcpNoDelay(true);
        raw.connect(new InetSocketAddress(ip, cfg.port), timeoutMs);
        raw.setSoTimeout(timeoutMs);
        sock = raw;
        Socket s = raw;
        if (cfg.tls) {
            SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket ss = (SSLSocket) f.createSocket(raw, cfg.sni, cfg.port, true);
            ss.startHandshake();
            s = ss;
            sock = ss;
        }
        out = s.getOutputStream();
        in = new BufferedInputStream(s.getInputStream(), 16384);

        byte[] kb = new byte[16];
        RND.nextBytes(kb);
        String req = "GET " + cfg.path + " HTTP/1.1\r\nHost: " + cfg.host
                + "\r\nUser-Agent: Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36"
                + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + b64(kb)
                + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
        out.write(req.getBytes("UTF-8"));
        out.flush();

        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) != -1) {
            sb.append((char) c);
            int l = sb.length();
            if (l > 8192) {
                throw new IOException("ws header too big");
            }
            if (l >= 4 && sb.charAt(l - 1) == '\n' && sb.charAt(l - 2) == '\r'
                    && sb.charAt(l - 3) == '\n' && sb.charAt(l - 4) == '\r') {
                break;
            }
        }
        String head = sb.toString();
        String first = head.split("\r\n")[0];
        String[] p = first.split(" ");
        if (p.length < 2 || !p[1].equals("101")) {
            throw new IOException("ws:" + first);
        }
        setupMs = ms(t0);
    }

    private void sendFrame(byte[] p) throws IOException {
        ByteArrayOutputStream f = new ByteArrayOutputStream(p.length + 14);
        f.write(0x82);
        int len = p.length;
        if (len < 126) {
            f.write(0x80 | len);
        } else if (len < 65536) {
            f.write(0x80 | 126);
            f.write(len >> 8);
            f.write(len & 255);
        } else {
            f.write(0x80 | 127);
            for (int i = 7; i >= 0; i--) {
                f.write((int) (((long) len >> (8 * i)) & 255));
            }
        }
        byte[] mask = new byte[4];
        RND.nextBytes(mask);
        f.write(mask, 0, 4);
        byte[] m = new byte[len];
        for (int i = 0; i < len; i++) {
            m[i] = (byte) (p[i] ^ mask[i & 3]);
        }
        f.write(m, 0, len);
        out.write(f.toByteArray());
        out.flush();
    }

    private int readB() throws IOException {
        int v = in.read();
        if (v < 0) {
            throw new EOFException();
        }
        return v;
    }

    private void readFully(byte[] b) throws IOException {
        int o = 0;
        while (o < b.length) {
            int r = in.read(b, o, b.length - o);
            if (r < 0) {
                throw new EOFException();
            }
            o += r;
        }
    }

    /** Next WebSocket data payload, or null when the peer closed. */
    private byte[] readFrame() throws IOException {
        while (true) {
            int b0 = in.read();
            if (b0 < 0) {
                return null;
            }
            int b1 = in.read();
            if (b1 < 0) {
                return null;
            }
            int op = b0 & 15;
            boolean masked = (b1 & 128) != 0;
            long len = b1 & 127;
            if (len == 126) {
                int h = readB();
                int l = readB();
                len = (h << 8) | l;
            } else if (len == 127) {
                len = 0;
                for (int i = 0; i < 8; i++) {
                    len = (len << 8) | readB();
                }
            }
            byte[] mk = null;
            if (masked) {
                mk = new byte[4];
                readFully(mk);
            }
            if (len > (1L << 25)) {
                throw new IOException("frame too big");
            }
            byte[] p = new byte[(int) len];
            readFully(p);
            if (masked) {
                for (int i = 0; i < p.length; i++) {
                    p[i] = (byte) (p[i] ^ mk[i & 3]);
                }
            }
            if (op == 8) {
                return null;
            }
            if (op == 9 || op == 10) {
                continue;
            }
            return p;
        }
    }

    /** Next chunk of tunnel payload with the VLESS response header removed; null on EOF. */
    private byte[] recv() throws IOException {
        while (true) {
            byte[] p = readFrame();
            if (p == null) {
                return null;
            }
            if (!cfg.vless || respHdrDone) {
                if (p.length == 0) {
                    continue;
                }
                return p;
            }
            if (p.length < 2) {
                throw new IOException("short vless header");
            }
            int skip = 2 + (p[1] & 255);
            if (p.length < skip) {
                throw new IOException("short vless addons");
            }
            respHdrDone = true;
            if (p.length == skip) {
                continue;
            }
            byte[] r = new byte[p.length - skip];
            System.arraycopy(p, skip, r, 0, r.length);
            return r;
        }
    }

    private void connectTarget(String host, int port, byte[] first) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] hb = host.getBytes("UTF-8");
        if (cfg.vless) {
            b.write(0);
            b.write(cfg.uuid, 0, 16);
            b.write(0);
            b.write(1);
            b.write(port >> 8);
            b.write(port & 255);
            b.write(2);
            b.write(hb.length);
            b.write(hb, 0, hb.length);
        } else {
            byte[] h = sha224hex(cfg.password).getBytes("UTF-8");
            b.write(h, 0, h.length);
            b.write('\r');
            b.write('\n');
            b.write(1);
            b.write(3);
            b.write(hb.length);
            b.write(hb, 0, hb.length);
            b.write(port >> 8);
            b.write(port & 255);
            b.write('\r');
            b.write('\n');
        }
        if (first != null) {
            b.write(first, 0, first.length);
        }
        sendFrame(b.toByteArray());
    }

    private static int parseStatus(byte[] p) {
        try {
            String s = new String(p, 0, Math.min(p.length, 24), "ISO-8859-1");
            if (!s.startsWith("HTTP/")) {
                return 0;
            }
            String[] a = s.split(" ");
            return a.length > 1 ? Integer.parseInt(a[1].trim()) : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    /** HTTP GET through the tunnel. Reads until maxBytes / maxMs / EOF. */
    Res fetch(String host, int port, String path, long maxMs, long maxBytes) throws Exception {
        String http = "GET " + path + " HTTP/1.1\r\nHost: " + host
                + "\r\nUser-Agent: Mozilla/5.0 (Linux; Android 13)\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        long t0 = System.nanoTime();
        connectTarget(host, port, http.getBytes("UTF-8"));
        Res r = new Res();
        byte[] p = recv();
        if (p == null) {
            throw new IOException("no data");
        }
        r.ttfb = ms(t0);
        r.bytes = p.length;
        r.firstLen = p.length;
        r.status = parseStatus(p);
        long t1 = System.nanoTime();
        long last = t1;
        while (r.bytes < maxBytes && ms(t0) < maxMs) {
            try {
                p = recv();
            } catch (SocketTimeoutException e) {
                break;
            }
            if (p == null) {
                break;
            }
            r.bytes += p.length;
            last = System.nanoTime();
        }
        r.dlMs = (last - t1) / 1000000L;
        return r;
    }

    /** HTTPS request through the tunnel: TLS runs end-to-end inside the tunnel (certificate and hostname verified). */
    Res fetchTls(String host, int port, String method, String path, String hdrs, String body, long maxMs) throws Exception {
        long t0 = System.nanoTime();
        SSLEngine eng = SSLContext.getDefault().createSSLEngine(host, port);
        eng.setUseClientMode(true);
        try {
            SSLParameters sp = eng.getSSLParameters();
            sp.setEndpointIdentificationAlgorithm("HTTPS");
            eng.setSSLParameters(sp);
        } catch (Throwable e) {
            // very old Android: no hostname check available
        }
        int ps = eng.getSession().getPacketBufferSize();
        ByteBuffer netIn = ByteBuffer.allocate(ps * 2);
        ByteBuffer netOut = ByteBuffer.allocate(ps);
        ByteBuffer app = ByteBuffer.allocate(eng.getSession().getApplicationBufferSize());
        byte[] bb = body.getBytes("UTF-8");
        byte[] hb = (method + " " + path + " HTTP/1.1\r\nHost: " + host
                + "\r\nUser-Agent: Mozilla/5.0 (Linux; Android 13)\r\n" + hdrs
                + "Content-Length: " + bb.length + "\r\nConnection: close\r\n\r\n").getBytes("ISO-8859-1");
        ByteBuffer req = ByteBuffer.allocate(hb.length + bb.length);
        req.put(hb).put(bb).flip();
        boolean open = false;
        Res r = new Res();
        StringBuilder sb = new StringBuilder();
        eng.beginHandshake();
        while (true) {
            if (ms(t0) > maxMs) {
                throw new SocketTimeoutException("tls total");
            }
            SSLEngineResult.HandshakeStatus hs = eng.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                Runnable tk;
                while ((tk = eng.getDelegatedTask()) != null) {
                    tk.run();
                }
                continue;
            }
            if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP
                    || (hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING && req.hasRemaining())) {
                netOut.clear();
                SSLEngineResult w = eng.wrap(req, netOut);
                netOut.flip();
                if (netOut.hasRemaining()) {
                    byte[] d = new byte[netOut.remaining()];
                    netOut.get(d);
                    if (!open) {
                        connectTarget(host, port, d);
                        open = true;
                    } else {
                        sendFrame(d);
                    }
                }
                if (w.getStatus() == SSLEngineResult.Status.CLOSED) {
                    break;
                }
                continue;
            }
            netIn.flip();
            SSLEngineResult u = eng.unwrap(netIn, app);
            netIn.compact();
            if (u.bytesProduced() > 0) {
                app.flip();
                byte[] d = new byte[app.remaining()];
                app.get(d);
                app.clear();
                if (r.ttfb < 0) {
                    r.ttfb = ms(t0);
                    r.status = parseStatus(d);
                }
                r.bytes += d.length;
                sb.append(new String(d, "ISO-8859-1"));
                if (sb.length() >= 3000) {
                    break;
                }
            }
            SSLEngineResult.Status st = u.getStatus();
            if (st == SSLEngineResult.Status.CLOSED) {
                break;
            }
            if (st == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                throw new IOException("tls overflow");
            }
            if (st == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                byte[] c = recv();
                if (c == null) {
                    break;
                }
                if (netIn.remaining() < c.length) {
                    ByteBuffer nb = ByteBuffer.allocate(netIn.position() + c.length + ps);
                    netIn.flip();
                    nb.put(netIn);
                    netIn = nb;
                }
                netIn.put(c);
            }
        }
        if (r.ttfb < 0) {
            throw new IOException("no tls data");
        }
        r.text = sb.toString();
        return r;
    }

    void close() {
        try {
            if (sock != null) {
                sock.close();
            }
        } catch (Exception e) {
            // ignore
        }
    }
}
