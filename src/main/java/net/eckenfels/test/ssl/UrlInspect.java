package net.eckenfels.test.ssl;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;


/**
 * Calculates various certificate fingerprints for testing.
 * <P>
 * Can be used to inspect and validate thumbprints, SKI and Public Key Pins.
 *
 * @author Bernd Eckenfels
 */
public class UrlInspect
{
    public static void main(String[] args) throws IOException, CertificateException
    {
        //sun.util.logging.PlatformLogger.getLogger("sun.net.www.protocol.http.HttpsURLConnection") .setLevel(Level.ALL);
        //System.out.println("pos=" + Security.insertProviderAt(new BouncyCastleProvider(), 2));

        // default URL or specify as first command argument an https URL
        // java UrlInspect https://scotthelme.co.uk/hpkp-http-public-key-pinning (require letsencrypt ca)
        // todo: https://pinningtest.appspot.com/
        // https://good.sca1a.amazontrust.com/ RSA 2048
        // https://good.sca3a.amazontrust.com/ ECC P-256ECC
        // https://good.sca3a.amazontrust.com/ ECC secp384r1
        URL url = new URL((args.length < 1)?"https://developer.google.com":args[0]);

        System.out.println("Connect to " + url + " ...");

        HttpURLConnection.setFollowRedirects(false);
        HttpsURLConnection c = (HttpsURLConnection)url.openConnection();
        c.setRequestMethod("HEAD"); // GET
        c.setDoOutput(false); c.setAllowUserInteraction(false);
        c.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0 URLInspect/1.0");
        c.setRequestProperty("Connection", "close");

        c.connect(); // throws SSL handshake exception

        // retrieve TLS info before reading response (which closes connection?)
        Certificate[] chain = c.getServerCertificates();
        String suite = c.getCipherSuite();

        // print response header
        System.out.printf("%n-- Server Response Header --%n%n");
        System.out.println("" + c.getHeaderField(null) + " (" + suite +")");
        for(Entry<String, List<String>> h : c.getHeaderFields().entrySet())
        {
            if (h.getKey() != null)
                System.out.println("  " + h.getKey() + ": " + h.getValue());
        }

        System.out.printf("%n-- Certificate Chain --%n%n");

        for(int i=0;i<chain.length;i++)
        {
            X509Certificate ca = (X509Certificate)chain[i];
            System.out.println("#"+i);
            System.out.println(" Subject " +ca.getSubjectDN().getName());
            Collection<List< ? >> alt = ca.getSubjectAlternativeNames();
            if (alt != null && !alt.isEmpty())
            {
                System.out.println("   Alternative Name: " + alt);
            }
            System.out.println(" Issuer " +ca.getIssuerDN().getName());
            System.out.println("  Signature " + ca.getSigAlgName() + " from:" +ca.getNotBefore() + " - " + ca.getNotAfter() + " Key " + ca.getPublicKey().getAlgorithm());
        }

        System.out.printf("%n-- Server Certificate --%n%n");

        X509Certificate server = (X509Certificate)chain[0];
        System.out.println("Subject " +server.getSubjectDN().getName());
        System.out.println("  v" + server.getVersion() + " serial " + server.getSerialNumber().toString(16));
        byte[] encoded = server.getEncoded();
        System.out.println("  Thumbprint SHA256 " + DigestUtils.sha256Hex(encoded));
        System.out.println("  Thumbprint SHA1   " + DigestUtils.sha1Hex(encoded));

        System.out.println("  Public Key: " + server.getPublicKey().toString());
        encoded = server.getPublicKey().getEncoded();
        System.out.println("  Public-Key-Pins: pin-sha256=\"" + org.apache.commons.codec.binary.Base64.encodeBase64String(DigestUtils.sha256(encoded))+ "\" (" + DigestUtils.sha256Hex(encoded) + ")");

        byte[] ext = server.getExtensionValue("2.5.29.14"); // SubjectKeyIdentifier
        if (ext != null)
        {
            ext = Arrays.copyOfRange(ext, ext.length - 20, ext.length);
            System.out.println("  SKI(SHA1) Ext  " + org.apache.commons.codec.binary.Hex.encodeHexString(ext));
        }

        // TODO: this poor man ASN non-parser works only for some RSA certs
        encoded = Arrays.copyOfRange(encoded, 24, encoded.length /*24+270*/);

        System.out.println("  SKI(SHA1) Calc " + DigestUtils.sha1Hex(encoded));

        ext = server.getExtensionValue("2.5.29.35"); // AuthorityKeyIdentifier
        if (ext != null)
        {
            ext = Arrays.copyOfRange(ext, ext.length - 20, ext.length);
            System.out.println("  AKI(SHA1) Ext  " + Hex.encodeHexString(ext));
        }

        encoded = chain[1].getPublicKey().getEncoded();
        // TODO: this poor man ASN non-parser works only for some RSA certs
        encoded = Arrays.copyOfRange(encoded, 24, encoded.length /*24+270*/);
        System.out.println("  AKI(SHA1) Calc " + DigestUtils.sha1Hex(encoded));

        System.out.println();
        System.out.println(" Issuer " +server.getIssuerDN().getName());
        System.out.println("  Signature " + server.getSigAlgName() + " from:" +server.getNotBefore() + " - " + server.getNotAfter());
    }
}



