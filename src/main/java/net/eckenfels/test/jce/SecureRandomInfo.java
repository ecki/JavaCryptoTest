package net.eckenfels.test.jce;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Set;

public class SecureRandomInfo
{
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, SecurityException, IOException
    {
        System.out.printf("SecureRandom Info: %s %s/%s on %s %s%n", System.getProperty("java.vm.name"),
                          System.getProperty("java.runtime.version"),
                          System.getProperty("java.vm.version"),
                          System.getProperty("os.name"),
                          System.getProperty("os.version"));

        System.out.printf("%nSystem and Security Properties:%n");
        System.out.printf(" - %-30s = %s%n", "securerandom.source", Security.getProperty("securerandom.source"));
        System.out.printf(" - %-30s = %s%n", "securerandom.strongAlgorithms", Security.getProperty("securerandom.strongAlgorithms"));
        System.out.printf(" - %-30s = %s%n", "java.security.egd", System.getProperty("java.security.egd"));
        System.out.printf(" - %-30s = %s%n", "java.security.debug", System.getProperty("java.security.debug"));

        // BC's PRNGs are not JCE provider registered
        // BouncyCastleProvider bc = new BouncyCastleProvider();
        // Security.addProvider(bc);

        System.out.printf("%nRegistered Providers:%n");
        Provider[] ps = Security.getProviders();
        for(int i=0;i<ps.length;i++)
        {
            Provider p = ps[i];
            Set<Service> services = p.getServices();
            for(Service s : services) {
                if ("SecureRandom".equalsIgnoreCase(s.getType())) {
                    String name = s.toString();
                    System.out.print(" - " + name);
                    if (!name.endsWith("\n")) System.out.println();
                }
            }
        }

        /*
        Set<String> algs = Security.getAlgorithms("SecureRandom");
        for(String a : algs) {
            SecureRandom r = SecureRandom.getInstance(a);
            System.out.println(" - " + r.getAlgorithm() + " " + r.getProvider().getName());
        }
        */

        System.out.printf("%nDefault Implmentations for different retrieval methods:%n");

        SecureRandom s = new SecureRandom();
        System.out.println(" - new SecureRandom()              = " + s.getAlgorithm() + " " + s.getProvider().getName());
        System.out.print(gp(s));
        s.nextInt();

        // use reflection to check if JDK8 static accessor for strong PRNG is present
        SecureRandom strong = null;
        try {
            Method m = SecureRandom.class.getMethod("getInstanceStrong", new Class<?>[0]);
            try {
                strong = (SecureRandom)m.invoke(s, new Object[0]);
                System.out.println(" - SecureRandom.getInstanceStrong  = " + strong.getAlgorithm() + " " + strong.getProvider().getName());
                System.out.print(gp(strong));
                strong.nextInt();
            } catch (Exception ignored) { }
        } catch (NoSuchMethodException ignored) { }


        System.in.read();

        System.out.printf("%nBenchmarking...%n");
        // use reflection to check if JDK8 static accessor for strong PRNG is present

        // speed compare
        long start = System.nanoTime();
        s = SecureRandom.getInstance("Windows-PRNG");
        long end = System.nanoTime();
        System.out.printf(s.getAlgorithm() + " " + s.getProvider().getName() + " : Seeded in %.3f ms.%n", (end - start) / 1000000.0d);
        for(int i=0;i<3;i++)
        {
            start = System.nanoTime();
            s.nextInt();
            end = System.nanoTime();
            System.out.printf(s.getAlgorithm() + " " + s.getProvider().getName() + " : nextInt() in %.3f ms.%n", (end - start) / 1000000.0d);
        }


        start = System.nanoTime();
        for(int i=0;i<10000;i++)
        {
            s = SecureRandom.getInstance("Windows-PRNG");
            s.nextInt();
        }
        end = System.nanoTime();
        System.out.printf("Windows-PRNG 10000*int Took %.3f ms with instantiation/seeding.%n", (end - start) / 1000000d);

        s = SecureRandom.getInstance("Windows-PRNG");
        start = System.nanoTime();
        for(int i=0;i<10000;i++)
        {
            s.nextInt();
        }
        end = System.nanoTime();
        System.out.printf("Windows-PRNG 10000*int Took %.3f ms without instantiation/seeding%n", (end - start) / 1000000.0);


        s = SecureRandom.getInstance("SHA1PRNG");
        for(int i=0;i<3;i++)
        {
            start = System.nanoTime();
            s.nextInt();
            end = System.nanoTime();
            System.out.printf(s.getAlgorithm() + " " + s.getProvider().getName() + " : " + s.getClass().getCanonicalName() + " nextInt() in %.3f ms.%n", (end - start) / 1000000.0d);
        }

        start = System.nanoTime();
        for(int i=0;i<10000;i++)
        {
            s = SecureRandom.getInstance("SHA1PRNG");
            s.nextInt();
        }
        end = System.nanoTime();
        System.out.printf("SHA1PRNG 10000*int Took %.3f ms with instantiation/seeding.%n", (end - start) / 1000000.0);

        s = SecureRandom.getInstance("SHA1PRNG");
        start = System.nanoTime();
        for(int i=0;i<10000;i++)
        {
            s.nextInt();
        }
        end = System.nanoTime();
        System.out.printf("SHA1PRNG 10000*int Took %.3f ms without instantiation/seeding.%n", (end - start) / 1000000.0d);

        start = System.nanoTime();
        for(int i=0;i<10000;i++)
        {
            s = new SecureRandom();
            s.nextInt();
        }
        end = System.nanoTime();
        System.out.printf(s.getAlgorithm() + " 10000*int Took %.3f ms with instantiation/seeding.%n", (end - start) / 1000000.0);

        s = new SecureRandom();
        start = System.nanoTime();
        for(int i=0;i<10000;i++)
        {
            s.nextInt();
        }
        end = System.nanoTime();
        System.out.printf(s.getAlgorithm() + " 10000*int Took %.3f ms without instantiation/seeding.%n", (end - start) / 1000000.0d);

        System.in.read();
    }

    private static String gp(SecureRandom sr)
    {
        try {
            Method m = SecureRandom.class.getMethod("getParameters", new Class<?>[0]);
            Object param = m.invoke(sr, new Object[0]);
            return "  params: " + param + "\n\r";
    } catch (Exception ignored) { return ""; }
    }

}
