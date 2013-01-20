package net.eckenfels.test.jce;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.SecureRandom;
import java.security.Security;

public class JCEProviderInfo
{
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException
    {
        //System.setProperty("java.security.egd", "test");

        Provider[] ps = Security.getProviders();
        for(Provider p : ps)
        {
            System.out.println("--- " + p.getName() + " " + p.getVersion() + " " + p.getInfo());
            for(Service s : p.getServices())
                //if (s.getType().equals("SecureRandom"))
                    System.out.println("  " + s.getType() + "." + s.getAlgorithm() +  " : " + s.getClassName() + " (" + s.getProvider().getName() + ") " + s.toString());
        }

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
