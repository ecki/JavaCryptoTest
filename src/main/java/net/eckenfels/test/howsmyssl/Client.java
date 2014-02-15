package net.eckenfels.test.howsmyssl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


/** Simple test client to connect to www.howsmyssl.com and read the API answer. */
public class Client
{
    public static void main(String[] args) throws UnsupportedEncodingException, IOException
    {
        System.out.println("Howsmyssl Test: " + System.getProperty("java.runtime.version")+"/"+System.getProperty("java.vm.version") + " " + System.getProperty("java.vm.name"));
        SSLSocketFactory sf = (SSLSocketFactory)SSLSocketFactory.getDefault();
        SSLSocket s = (SSLSocket)sf.createSocket("www.howsmyssl.com", 443);
        s.startHandshake();
        Thread printer = new InputStreamPrinterThread(s.getInputStream());
        OutputStream out = s.getOutputStream();
        out.write("GET https://www.howsmyssl.com/a/check HTTP/1.1\n\rHost: www.howsmyssl.com\n\r\n\r".getBytes("ISO-8859-1"));
        printer.start();
    }

    static class InputStreamPrinterThread extends Thread
    {
        InputStream in;

        public InputStreamPrinterThread(InputStream in)
        {
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
                    System.out.println(line);
            }
            catch (Exception ex) { throw new RuntimeException(ex); }
            finally { try { in.close(); } catch (Exception ignored) { } }
        }
    }
}

