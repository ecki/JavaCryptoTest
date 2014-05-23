package net.eckenfels.test.jce;

import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class SecureRandomInfo
{
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, SecurityException
    {
        // print out the type of the default random
        SecureRandom s = new SecureRandom();
        System.out.println("new SecureRandom()              " + s.getAlgorithm() + " " + s.getProvider().getName());

        // use reflection to check if JDK8 static accessor for strong PRNG is present
        try {
            Method m = s.getClass().getMethod("getInstanceStrong", new Class<?>[0]);
            try {
                SecureRandom strong = (SecureRandom)m.invoke(s, new Object[0]);
                System.out.println("SecureRandom.getInstanceStrong  " + strong.getAlgorithm() + " " + strong.getProvider().getName());
            } catch (Exception ignored) { }
        } catch (NoSuchMethodException ignored) { }


        // speed compare
        long start = System.nanoTime();
        s = SecureRandom.getInstance("Windows-PRNG");
        long end = System.nanoTime();
        System.out.printf("Windows-PRNG " + s.getAlgorithm() + " " + s.getProvider().getName() + " : " + s.getClass().getCanonicalName() + " Seeded in %.3f ms.%n", (end - start) / 1000000.0d);
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
    }

}
