package net.eckenfels.test.jce;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class SecureRandomInfo
{
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException
    {
        SecureRandom s = new SecureRandom();
        System.out.println("Default      " + s.getAlgorithm() + " " + s.getProvider().getName());

        // speed compare
        s = SecureRandom.getInstance("Windows-PRNG");
        long start = System.currentTimeMillis();
        s.nextBoolean();
        long end = System.currentTimeMillis();
        System.out.println("Windows-PRNG " + s.getAlgorithm() + " " + s.getProvider().getName() + " : " + s.getClass().getCanonicalName() + " Seeded in " + (end - start) + "ms");


        start = System.currentTimeMillis();
        for(int i=0;i<10000;i++)
        {
            s = SecureRandom.getInstance("Windows-PRNG");
            s.nextInt();
        }
        end = System.currentTimeMillis();
        System.out.println("Windows-PRNG 10000*int Took " + (end - start) + "ms with instantiation/seeding");

        start = System.currentTimeMillis();
        for(int i=0;i<10000;i++)
        {
            s.nextInt();
        }
        end = System.currentTimeMillis();
        System.out.println("Windows-PRNG 10000*int Took " + (end - start) + "ms without instantiation/seeding");


        s = SecureRandom.getInstance("SHA1PRNG");
        start = System.currentTimeMillis();
        s.nextBoolean();
        end = System.currentTimeMillis();
        System.out.println("SHA1PRNG " + s.getAlgorithm() + " " + s.getProvider().getName() + " : " + s.getClass().getCanonicalName() + " Seeded in " + (end - start) + "ms");

        start = System.currentTimeMillis();
        for(int i=0;i<10000;i++)
        {
            s = SecureRandom.getInstance("SHA1PRNG");
            s.nextInt();
        }
        end = System.currentTimeMillis();
        System.out.println("SHA1PRNG 10000*int Took " + (end - start) + "ms with instantiation/seeding");

        start = System.currentTimeMillis();
        for(int i=0;i<10000;i++)
        {
            s.nextInt();
        }
        end = System.currentTimeMillis();
        System.out.println("SHA1PRNG 10000*int Took " + (end - start) + "ms without instantiation/seeding");
    }

}
