/*
 * HmacInfo.java
 *
 * created at 02.06.2015 by Eckenfel <b.eckenfels@seeburger.de>
 *
 * Copyright (c) SEEBURGER AG, Germany. All Rights Reserved.
 */
package net.eckenfels.test.jce;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;


public class HmacInfo
{

    public static void main(String[] args) throws NoSuchAlgorithmException
    {
        // TODO: ask providers
        List<String> macs = Arrays.asList("HmacMD5", "HmacSHA1", "HmacSHA256", "HmacSHA384", "HmacSHA512", "HmacSHA224");
        for(String m : macs)
        {
            debugMac(m);
        }
    }

    private static void debugMac(String n) throws NoSuchAlgorithmException
    {
        Mac m;
        try
        {
            KeyGenerator g = KeyGenerator.getInstance(n);
            m = Mac.getInstance(n);
            System.out.printf("%-10s L = %d KL = %d%n", n, m.getMacLength(), g.generateKey().getEncoded().length);
        } catch (NoSuchAlgorithmException nsa) {
            System.out.printf("%-10s %s%n", n, nsa.toString());
        }
    }

}

