/*
 * CertExplorer.java
 *
 * created at 2ß17-06-10 by Bernd Eckenfels <bernd-2017@eckenfels.net>
 *
 * License: ASL2.0
 */
package net.eckenfels.test.certpath;


import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;


public class CertExplorer
{
    public static void main(String[] args)
                    throws IOException
    {
        Path dir = Paths.get(".");
        if (args.length > 0)
        {
            dir = Paths.get(".").resolve(args[0]);
        }
        dir = dir.normalize().toAbsolutePath();

        Object[] os = null;
        try (Stream<Path> fs = Files.walk(dir);)
        {
            os = fs.filter(CertExplorer::endsWithCrt).toArray();
        }
        for (Object o : os)
        {
            Path p = (Path)o;
            System.out.print("loading " + p + " ");
            try
            {
                try (InputStream in = Files.newInputStream(p))
                {
                    X509Certificate c = (X509Certificate)CertificateFactory.getInstance("X.509")
                                    .generateCertificate(in);
                    System.out.println(" " + c.getSubjectDN());
                }
            }
            catch (Exception e)
            {
                System.out.println("???" + e);
                e.printStackTrace();
            }
        }
    }


    static boolean endsWithCrt(Path f)
    {
        return (f.toString().endsWith(".crt") || f.toString().endsWith(".cer"));
    }

}
