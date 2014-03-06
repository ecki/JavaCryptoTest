package net.eckenfels.test.jce;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;

public class JCEProviderInfo
{
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException
    {
        Provider[] ps = Security.getProviders();
        for(Provider p : ps)
        {
            System.out.printf("--- Provider %s %s%n    info %s%n", p.getName(), p.getVersion(), p.getInfo());
            for(Service s : p.getServices())
            {
                    System.out.printf(" + %s.%s : %s (%s)%n  tostring=%s%n", s.getType(), s.getAlgorithm(), s.getClassName(), s.getProvider().getName(), s.toString());
            }
        }
    }

}
