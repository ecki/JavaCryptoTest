package net.eckenfels.test.jce;

import static org.junit.Assert.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;


public class HashOverflowTest
{
    @Test
    public void testSHA1AllRegisteredProviders() throws NoSuchAlgorithmException
    {
        final String DIGEST = "SHA-1";

        Provider[] providers = Security.getProviders("MessageDigest." + DIGEST);
        if (providers == null)
        {
            fail("No Security Provider is implementing the MessageDigest." + DIGEST + " algorithm.");
        }

        for(Provider p : providers)
        {
            Service service = p.getService("MessageDigest", DIGEST);
            if (service == null)
            {
                fail("Provider " + p + " does not define the expected service.");
            }

            System.out.print("Testing algorithm " + service + ": ");
            MessageDigest digest = MessageDigest.getInstance(DIGEST, p);

            String hashString = feedData(digest, 1024*1024, 257*1024, 5*1024);

            assertEquals(digest.toString() + " failed test vector", "6938f23e29e7d3dcd100d0ed2df9d6593113718f", hashString);
        }
        System.out.println("Done.");
    }

    private String feedData(MessageDigest digest, int bufSize, int bufCount, int hashStep)
    {
        long start = System.nanoTime();
        byte[] buf = new byte[bufSize];
        for(int i=0;i<bufCount;i++)
        {
            digest.update(buf);
            if (i % hashStep == 0) System.out.print(".");
        }
        byte[] hash = digest.digest();
        long end = System.nanoTime();
        String hashString = DatatypeConverter.printHexBinary(hash).toLowerCase();
        System.out.printf("%n %s %s in %.03fs%n", digest, hashString, (end - start)/1000000000.0);
        return hashString;
    }
}



