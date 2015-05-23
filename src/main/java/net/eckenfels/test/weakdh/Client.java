package net.eckenfels.test.weakdh;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


/** Simple test client to connect to dhe512.zmap.io and read the HTML answer. */
public class Client
{
    static class DebugAlgorithmConstraints implements AlgorithmConstraints
    {

        @Override
        public boolean permits(Set<CryptoPrimitive> primitives,
                               String algorithm,
                               AlgorithmParameters parameters)
        {
            System.out.println("prim " + primitives + " " + algorithm + " with " + parameters);
            return true;
        }

        @Override
        public boolean permits(Set<CryptoPrimitive> primitives, Key key)
        {
            System.out.println("prim " + primitives + " " + key);
            return true;
        }

        @Override
        public boolean permits(Set<CryptoPrimitive> primitives,
                               String algorithm,
                               Key key,
                               AlgorithmParameters parameters)
        {
            System.out.println("prim " + primitives + " " + algorithm + " on " + key +" with " + parameters);
            return true;
        }

    }

    public static void main(String[] args) throws UnsupportedEncodingException, IOException, NoSuchAlgorithmException, KeyManagementException, NoSuchProviderException
    {
        System.out.printf("WeakDH Test: %s %s/%s on %s %s%n", System.getProperty("java.vm.name"),
                          System.getProperty("java.runtime.version"),
                          System.getProperty("java.vm.version"),
                          System.getProperty("os.name"),
                          System.getProperty("os.version"));
        System.out.printf("  disabledAlgorithms=%s ephemeralDHKeySize=%s%n",
                          Security.getProperty("jdk.tls.disabledAlgorithms"),
                          System.getProperty("jdk.tls.ephemeralDHKeySize", "N/A"));

        String mode = "default";
        if (args.length > 0)
        {
            mode = args[0];
        }

        SSLSocket s;
        if ("default".equalsIgnoreCase(mode))
        {
            SSLSocketFactory sf = (SSLSocketFactory)SSLSocketFactory.getDefault();
            System.out.printf("  Requesting default SF resulted in %s aka %s%n", sf.getClass().getName(), sf.toString());
            s = (SSLSocket)sf.createSocket("dhe512.zmap.io", 443);
        } else {
            String[] provider = mode.split(",");
            SSLContext ctx;
            if (provider.length == 2)
            {
                ctx = SSLContext.getInstance(provider[0], provider[1]);
            } else {
                ctx = SSLContext.getInstance(mode);
            }
            ctx.init(null,  null, null);
            System.out.printf("  Requesting %s resulted in %s of %s%n", mode, ctx.getClass().getName(), ctx.getProvider());
            SSLSocketFactory sf = (SSLSocketFactory)ctx.getSocketFactory();
            s = (SSLSocket)sf.createSocket("dhe512.zmap.io", 443);
        }

        configureDebugConstraints(s);
        sanitizeProtocols(s);

        s.startHandshake();

        System.out.printf("Cipher used %s %s%n---%n", s.getSession().getProtocol(), s.getSession().getCipherSuite());

        Thread printer = new InputStreamPrinterThread(s.getInputStream());
        printer.start();

        OutputStream out = s.getOutputStream();
        try /* TWR is Java 7 */ {
            out.write("GET / HTTP/1.0\n\r\n\r".getBytes("ISO-8859-1"));
            try { printer.join(10 * 1000); } catch (InterruptedException ex) { Thread.currentThread().interrupt(); }
        } finally {
            silentClose(out);
        }
    }

    private static void silentClose(Closeable resource)
    {
        try
        {
            if (resource != null)
                resource.close();
        } catch (Exception ignored) { /* nothing to recover */ }
    }

    private static void configureDebugConstraints(SSLSocket s)
    {
        SSLParameters p = s.getSSLParameters();
        p.setAlgorithmConstraints(new DebugAlgorithmConstraints());
        s.setSSLParameters(p);
    }

    private static void sanitizeProtocols(SSLSocket s)
    {
        List<String> supportedProt = Arrays.asList(s.getSupportedProtocols());
        List<String> enabledProt = Arrays.asList(s.getEnabledProtocols());

        List<String> wantedProt = Arrays.asList("TLSv1.2", "TLSv1.1", "TLSv1");

        try {
        wantedProt.retainAll(supportedProt); // does not work on IBM 6
        } catch (UnsupportedOperationException ignored) { }

        if (wantedProt.isEmpty())
        {
            throw new IllegalStateException("This implementation does not support safe TLS protocols: " + supportedProt);
        }

        s.setEnabledProtocols(wantedProt.toArray(new String[wantedProt.size()]));
        System.out.printf("  protocols old enabled %s supported %s and active %s%n", enabledProt, supportedProt, wantedProt);
    }

    static class InputStreamPrinterThread extends Thread
    {
        InputStream in;

        public InputStreamPrinterThread(InputStream in)
        {
            super("InputStreamPrinterThread");
            this.in = in;
        }

        @Override
        public void run()
        {
            try
            {
                BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
                String line;
                while ((line = reader.readLine()) != null)
                {
                    // very sophisticated json formatter:
                    line = line.replaceAll(",\"", ",\n  \"");
                    System.out.println(line);
                }
            }
            catch (Exception ex) { throw new RuntimeException(ex); }
            finally { try { in.close(); } catch (Exception ignored) { } }
        }
    }
}

