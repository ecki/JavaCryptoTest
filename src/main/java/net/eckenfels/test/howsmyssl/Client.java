package net.eckenfels.test.howsmyssl;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


/** Simple test client to connect to www.howsmyssl.com and read the API answer. */
public class Client
{
    public static void main(String[] args) throws UnsupportedEncodingException, IOException
    {
        System.out.printf("Howsmyssl Test: %s %s/%s on %s %s%n", System.getProperty("java.vm.name"),
                          System.getProperty("java.runtime.version"),
                          System.getProperty("java.vm.version"),
                          System.getProperty("os.name"),
                          System.getProperty("os.version"));

        SSLSocketFactory sf = (SSLSocketFactory)SSLSocketFactory.getDefault();

        SSLSocket s = (SSLSocket)sf.createSocket("www.howsmyssl.com", 443);
        //SSLSocket s = (SSLSocket)sf.createSocket(InetAddress.getByAddress(null, new byte[] {54,(byte)245,(byte)228,(byte)141})/*"www.howsmyssl.com""neskaya.eckenfels.net"*/, 443);
        //SSLSocket s = (SSLSocket)sf.createSocket(InetAddress.getByAddress("www.howsmyssl.com", new byte[] {54,(byte)245,(byte)228,(byte)141})/*"www.howsmyssl.com""neskaya.eckenfels.net"*/, 443);
        //SSLSocket s = (SSLSocket)sf.createSocket(InetAddress.getByAddress("54.245.228.141", new byte[] {54,(byte)245,(byte)228,(byte)141})/*"www.howsmyssl.com""neskaya.eckenfels.net"*/, 443);

        sanitizeProtocols(s);
        configureEndpointIdentification(s);

        s.startHandshake();

        System.out.printf("Cipher used %s %s%n---%n", s.getSession().getProtocol(), s.getSession().getCipherSuite());

        Thread printer = new InputStreamPrinterThread(s.getInputStream());
        printer.start();

        OutputStream out = s.getOutputStream();
        try /* TWR is Java 7 */ {
            out.write("GET https://www.howsmyssl.com/a/check HTTP/1.1\n\rHost: www.howsmyssl.com\n\r\n\r".getBytes("ISO-8859-1"));
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

    private static void configureEndpointIdentification(SSLSocket s)
    {
        try
        {
            SSLParameters p = s.getSSLParameters();
            String algo = p.getEndpointIdentificationAlgorithm();
            if (algo != null)
            {
                System.out.println("Unexpected: endpointIDAlgo: " + algo);
            }
            p.setEndpointIdentificationAlgorithm("https");
            //p.setServerNames(Collections.<SNIServerName>emptyList());
            //p.setServerNames(Arrays.asList(new SNIServerName()("www.howismyssl.com")));
            s.setSSLParameters(p);
            // TODO: assert?
        }
        catch (NoSuchMethodError nsm)
        {
            throw new IllegalStateException("Implementation does not allow to set endpoint id. Old Java?", nsm);
        }
        catch (IllegalArgumentException iae)
        {
            throw new IllegalStateException("Implementation does not allow to set endpoint id algorithm 'https'.", iae);
        }
    }

    private static void sanitizeProtocols(SSLSocket s)
    {
        List<String> supportedProt = Arrays.asList(s.getSupportedProtocols());
        List<String> enabledProt = Arrays.asList(s.getEnabledProtocols());

        List<String> wantedProt = Arrays.asList("TLSv1.2", "TLSv1.1", "TLSv1");

        wantedProt.retainAll(supportedProt);

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

