package net.eckenfels.test.ssl;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;


/** Open simple HttpsUrlConnection. */
public class HttpsConnection
{

    public static void main(String[] args) throws IOException
    {
        URL url = new URL("https://dhe512.zmap.io/"); // test if jre accepts weakdh

        HttpsURLConnection c = (HttpsURLConnection)url.openConnection();
        c.setInstanceFollowRedirects(false);
        c.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());

        System.out.println(" last " + c.getLastModified() + " size " + c.getContentLength() + " with " + c.getCipherSuite());

        // try reading from stream
        InputStream is = c.getInputStream();
        is.read();
    }

}

