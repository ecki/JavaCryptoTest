/*
 * KeystoreExploder.java
 *
 * created at 2017-06-10 by Bernd Eckenfels <bernd-2017eckenfels.net>
 *
 * License: ASL2.0
 */
package net.eckenfels.test.certpath;


import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Enumeration;


public class KeystoreExploder
{
    // RFC 7469
    static final String BEGIN = "-----BEGIN CERTIFICATE-----";
    static final String END = "-----END CERTIFICATE-----";


    public static void main(String[] args)
                    throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
    {
        if (args.length < 1)
        {
            System.err.println("ERROR: please specify a keystore file name (and optional target dir)");
            System.exit(2);
        }
        Path inFile = Paths.get(".").resolve(args[0]);
        Path dir = Paths.get(".");
        if (args.length >= 2)
        {
            dir = Paths.get(".").resolve(args[1]);
        }
        inFile = inFile.toAbsolutePath().normalize();
        dir = dir.toAbsolutePath().normalize();
        Files.createDirectories(dir);
        System.out.println("Writing " + inFile + " to " + dir + " directory ...");

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = new BufferedInputStream(new FileInputStream(inFile.toFile()));)
        {
            ks.load(in, null); // no password for JKS only
            Enumeration<String> en = ks.aliases();
            while (en.hasMoreElements())
            {
                String alias = en.nextElement();
                String name = saneFile(alias, ".crt");

                System.out.print("\"" + alias + "\" -> " + name + ": ");

                Certificate cs[] = ks.getCertificateChain(alias);
                if (cs == null)
                {
                    Certificate c = ks.getCertificate(alias);
                    if (c == null)
                    {
                        System.out.println(" skipped.");
                    }
                    cs = new Certificate[1];
                    cs[0] = c;
                }
                File f = dir.resolve(name).toFile();
                PrintWriter w = new PrintWriter(new FileOutputStream(f)); // TODO Enc?

                for (int i = 0; i < cs.length; i++)
                {
                    X509Certificate xc = (X509Certificate)cs[i];
                    PublicKey p = xc.getPublicKey();

                    w.println("Alias: " + sane(alias));
                    w.println("Subject: " + sane("" + xc.getSubjectDN()));
                    w.println("Serial: 0x" + xc.getSerialNumber().toString(16));
                    w.println("Valid: " + xc.getNotBefore() + " - " + xc.getNotAfter());
                    // w.println("Fingerprint: SHA1 " + );
                    w.println("Alg: " + sane(xc.getType()) + " " + keyInfo(p) + " "
                                    + sane(xc.getSigAlgName()));

                    w.println(BEGIN);

                    byte[] bs = cs[i].getEncoded();
                    Encoder enc = Base64.getMimeEncoder();
                    w.println(enc.encodeToString(bs));

                    w.println(END);
                }
                System.out.println(" " + cs.length + " certs written");
                w.close();
            }
        }
    }


    private static String keyInfo(PublicKey p)
    {
        if (p instanceof RSAPublicKey)
        {
            RSAPublicKey r = (RSAPublicKey)p;
            return sane(r.getAlgorithm()) + " " + r.getModulus().bitLength() + " ("
            + r.getPublicExponent().toString() + ")";
        }
        else if (p instanceof DSAPublicKey)
        {
            DSAPublicKey d = (DSAPublicKey)p;
            int len;
            if ( d.getParams() != null )
            {
                len = d.getParams().getP().bitLength();
            } else {
                len = d.getY().bitLength();
            }
            return sane(d.getAlgorithm()) + " " + len;
        }
        else if (p instanceof ECPublicKey)
        {
            ECPublicKey e = (ECPublicKey)p;
            ECParameterSpec s = e.getParams();
            if (s != null)
            {
                return sane(e.getAlgorithm()) + " " + s.getOrder().bitLength();
            }
            // fallthrough
        }
        return sane(p.getAlgorithm());
    }

    /** returns a sanitized relative file name ending in suffix */
    private static String saneFile(String str, String suffix)
    {
        char[] a = str.toCharArray();
        boolean changed = false;
        for (int i = 0; i < a.length; i++)
        {
            char c = a[i];
            if (c < ' ' || c == 128)
            {
                a[i] = '_';
                changed = true;
                continue;
            }
            // no surrogates or reserved
            if (c >= 0xD800 && c <= 0xf900)
            {
                a[i] = '_';
                changed = true;
                continue;
            }
            if (Character.isWhitespace(c) && c != ' ')
            {
                a[i] = ' ';
                changed = true;
                continue;
            }

            if ("<>:\"/\\|?*^~".indexOf(c) >= 0)
            {
                a[i] = '_';
                changed = true;
                continue;
            }
        }
        int maxLen = 128 - suffix.length();
        if (changed || a.length > maxLen)
        {
            System.out.println("Warning " + str);
            StringBuilder sb = new StringBuilder(128);
            sb.append(a, 0, Math.min(maxLen, a.length));
            sb.append(suffix);
            return sb.toString();
        }
        return str + suffix;
    }


    private static String sane(String s)
    {
        char[] a = s.toCharArray();
        boolean changed = false;
        for (int i = 0; i < a.length; i++)
        {
            char c = a[i];
            // no control chars
            if (c < ' ' || c == 128)
            {
                a[i] = '?';
                changed = true;
                continue;
            }
            // no surrogates or reserved
            if (c >= 0xD800 && c < 0xf900)
            {
                a[i] = '?';
                changed = true;
                continue;
            }
        }
        if (changed)
        {
            System.out.println("Warning " + s);
            return new String(a);
        }
        return s;
    }
}
