package net.eckenfels.test.jce;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.spec.DHParameterSpec;

public class DHGeneratorInfo {
    public static void main (String[] args) throws Exception
    {
        System.out.printf("JCE Provider Info: %s %s/%s on %s %s%n%n", System.getProperty("java.vm.name"),
                          System.getProperty("java.runtime.version"),
                          System.getProperty("java.vm.version"),
                          System.getProperty("os.name"),
                          System.getProperty("os.version"));


        long t1 = System.nanoTime();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(2048);
        KeyPair key = keyGen.generateKeyPair();

        long t2 = System.nanoTime();

        System.out.printf("  generated key in %.3fms: %s%n", ((t2-t1)/1000000.0), key.getPublic());

        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DiffieHellman");
        for (int i = 16*1024 ; i>=512; i -= 64)
        {
            try {
                paramGen.init (i);
            } catch (InvalidParameterException e) {
                continue;
            }
            System.out.printf("Largest Parameter: size=%d %s@%s%n%n", i, paramGen.getAlgorithm(), paramGen.getProvider());

            final long t0 = System.nanoTime();

            final AlgorithmParameters p = paramGen.generateParameters();

            t1 = System.nanoTime();

            final DHParameterSpec dhs = p.getParameterSpec(DHParameterSpec.class);
            System.out.printf("  generated parameter in %.3fs: %s%n%n", ((t1-t0)/1000000000.0), p);

            keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dhs);
            key = keyGen.generateKeyPair();

            t2 = System.nanoTime();

            System.out.printf("  generated key in %.3fms: %s%n", ((t2-t1)/1000000.0), key.getPublic());
            break;
        }
    }
}
