/*
 * BrokenCert.java
 *
 * created at 2017-06.26 by Bernd Eckenfel <b.eckenfels@seeburger.de>
 *
 * Copyright (c) SEEBURGER AG, Germany. All Rights Reserved.
 */
package net.eckenfels.test.certpath;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;


/** Playground to create non-canonical X.509 test certs. */
public class BrokenCert
{
    public static final int BOOLEAN             = 0x01;
    public static final int INTEGER             = 0x02;
    public static final int BIT_STRING          = 0x03;
    public static final int OCTET_STRING        = 0x04;
    public static final int NULL                = 0x05;
    public static final int OBJECT_IDENTIFIER   = 0x06;
    public static final int EXTERNAL            = 0x08;
    public static final int ENUMERATED          = 0x0a;
    public static final int SEQUENCE            = 0x10;
    public static final int SET                 = 0x11;

    public static final int NUMERIC_STRING      = 0x12;
    public static final int PRINTABLE_STRING    = 0x13;
    public static final int T61_STRING          = 0x14;
    public static final int VIDEOTEX_STRING     = 0x15;
    public static final int IA5_STRING          = 0x16;
    public static final int UTC_TIME            = 0x17;
    public static final int GENERALIZED_TIME    = 0x18;

    public static final int CONSTRUCTED         = 0x20;
    public static final int APPLICATION         = 0x40;
    public static final int TAGGED              = 0x80;

    private static final String RSA = "06092A864886F70D010105"; // 1.2.840.113549.1.1.5 sha1WithRSAEncryption
    private static final String PUBKEY = "30819f300d06092a864886f70d010101050003818d003081890281810081633f519bf5ba3bb6dbe7c0f1df888003fea42593293acb6e8a1f4febe94543bf42183e78f08c7e5f17d78b40d6d481a922ee2e6665a24094ea754499ff33c21c5694245142ed3e746c18d2636c59ae62d9e554f449e381f128574e318601e5ced4856eff78d8d42be56c8f0f84950e71345a77c8f555b1944773f56ff5c15b0203010001";
    private static final String PRIVKEY = "30820275020100300d06092a864886f70d01010105000482025f3082025b0201000281810081633f519bf5ba3bb6dbe7c0f1df888003fea42593293acb6e8a1f4febe94543bf42183e78f08c7e5f17d78b40d6d481a922ee2e6665a24094ea754499ff33c21c5694245142ed3e746c18d2636c59ae62d9e554f449e381f128574e318601e5ced4856eff78d8d42be56c8f0f84950e71345a77c8f555b1944773f56ff5c15b020301000102818042ded767c7320da9350d9c4e64f38169a026e8111f688ca17d24d7a007ae0d054180d864d93e816e0299a0e5b082175c57dcdcba906370a2ee13eabda4d5779adb9c9cef44ba54260afb7d31eb07e5e96e96dadaec4c7234e29a0ad46464fd43493edea153419db53809ae8d0fca50e3c30945dd4e6638a32e39e71592ad3dd9024100bdf54ce7ec20a99c3f3782844880a8c202a5737abe7528e7d5492bb8227c057ce68e588914b4de8f37f350547f4025d2a259cef7dbf15fe69d3977b1d353daf7024100ae5f0974fe18f41cb744beb711f739a58b903dee144edd21e4311e8d8054f50dbed11bedc172276e1fad76985f385430b0cd6eb1037d3e96dc522fef66c46fbd024042ab09ffc7aebaf85c7385fa195c165e69015a6334def7a94e00ed3825da332edfd80b98a8ccc5e3abf658361fa70adf3f1d97f70399565820cc1f8728ad2087024057354edc854ce3a20d02c3c379a7c4dc07bdff4b383aed1bcb2dc9d30950f43288b1ba9f2175bf44b37124f436034d10010ced847873463f5b377ba3e728ed9d02401576e2555bd0652cdd6356523a94dc9890ca0e54f01605a2b52cffb7d43df0bd227cdf4ff3ad74c44bcd2034ec5c41d9e350863a0095c74ec38272ca2c4905f0";

    interface Encodeable
    {
        public byte[] getEncoded() throws IOException;
    }

    static class Seq implements Encodeable
    {
        ArrayList<Encodeable> members = new ArrayList<>();
        public void add(Encodeable e)
        {
            members.add(e);
        }

        @Override
        public byte[] getEncoded() throws IOException
        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            for(Encodeable m : members)
                bos.write(m.getEncoded());
            bos.close();
            byte[] content = bos.toByteArray();
            bos = new ByteArrayOutputStream();
            bos.write(SEQUENCE | CONSTRUCTED);
            if (content.length < 128) {
                bos.write(content.length); // < 128
            } else if (content.length < 256) {
                bos.write(0x81);
                bos.write(content.length);
            } else {
                bos.write(0x82);
                bos.write((content.length / 256));
                bos.write((content.length % 256));
            }
            bos.write(content);
            bos.close();
            return bos.toByteArray();
        }
    }

    static class Bits implements Encodeable
    {
        byte[] bits;

        public Bits(byte[] bits)
        {
            this.bits = bits;
        }

        @Override
        public byte[] getEncoded() throws IOException
        {
            byte[] bs;
            int o;
            int len = bits.length + 1;
            if (len < 128) {
                bs = new byte[len + 2];
                bs[1] = (byte)len ;
                o = 3;
            } else if (len < 256) {
                bs = new byte[len + 3];
                bs[1] = (byte)0x81;
                bs[2] = (byte)len;
                o = 4;
            } else {
                bs = new byte[len + 4];
                bs[1] = (byte)0x82;
                bs[2] = (byte)(len / 256);
                bs[3] = (byte)(len % 256);
                o = 5;
            }
            bs[0] = BIT_STRING;
            bs[o-1] = (byte)0;
            System.arraycopy(bits, 0, bs, o, bits.length);
            return bs;
        }
    }

    protected static class Validity implements Encodeable
    {
        @Override
        public byte[] getEncoded() throws IOException
        {
            Seq seq = new Seq();
            Raw notBefore = new Raw("170b313631323331303030305a"); // 16-12-31 00:00 Z
            Raw notAfter = new Raw("170b313831323331303030305a");  // 18-12-31 00:00 Z
            seq.add(notBefore);
            seq.add(notAfter);
            return seq.getEncoded();
        }

    }

    static class Printable implements Encodeable
    {
        String text;
        public Printable(String text)
        {
            this.text = text;
        }

        @Override
        public byte[] getEncoded() throws IOException
        {
            byte[] bs = new byte[text.length() + 2];
            bs[0] = PRINTABLE_STRING;
            bs[1] = (byte)text.length(); // < 128
            System.arraycopy(text.getBytes(StandardCharsets.US_ASCII), 0, bs, 2, text.length());
            return bs;
        }

    }

    static class Name implements Encodeable
    {
        String name;
        public Name(String cn)
        {
            this.name = cn;
        }

        @Override
        public byte[] getEncoded() throws IOException
        {
            Seq rdn = new Seq();
            Set rdnset = new Set();
            Seq ava = new Seq();
            ava.add(new Raw("0603550403")); // 2.5.4.3 commonName
            ava.add(new Printable(name));
            rdnset.add(ava);
            rdn.add(rdnset);
            return rdn.getEncoded();
        }
    }

    static class Set implements Encodeable
    {
        ArrayList<Encodeable> members = new ArrayList<>();
        public void add(Encodeable e)
        {
            members.add(e);
        }

        @Override
        public byte[] getEncoded() throws IOException
        {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            for(Encodeable m : members)
                bos.write(m.getEncoded());
            bos.close();
            byte[] content = bos.toByteArray();
            bos = new ByteArrayOutputStream();
            bos.write(SET | CONSTRUCTED);
            if (content.length < 128) {
                bos.write(content.length); // < 128
            } else if (content.length < 256) {
                bos.write(0x81);
                bos.write(content.length);
            } else {
                bos.write(0x82);
                bos.write((content.length / 256));
                bos.write((content.length % 256));
            }
            bos.write(content);
            bos.close();
            return bos.toByteArray();
        }
    }


    static class AlgId implements Encodeable
    {
        Seq seq = new Seq();

        public AlgId(String oid)
        {
            seq.add(new Raw(oid));
            seq.add(new Null());
        }

        @Override
        public byte[] getEncoded() throws IOException
        {
            return seq.getEncoded();
        }

    }

    static class Null implements Encodeable
    {
        byte[] content = new byte[2];

        public Null()
        {
            content[0] = NULL;
            content[1] = 0;
        }

        @Override
        public byte[] getEncoded() throws IOException
        {
            return content;
        }

    }


    static class Raw implements Encodeable
    {
        byte[] content;

        public Raw(byte[] r)
        {
            content = r;
        }

        public Raw(String r)
        {
            content = fromHex(r);
        }

        @Override
        public byte[] getEncoded() throws IOException
        {
            return content;
        }

    }


    static class Int implements Encodeable
    {
        byte[] number;

        public Int(String hex)
        {
            number = fromHex(hex);
        }

        @Override
        public byte[] getEncoded()
        {
            byte[] buf = new byte[number.length+2];
            buf[0] = (byte)INTEGER;
            buf[1] = (byte)(number.length & 0x7F);
            System.arraycopy(number, 0, buf, 2, number.length);
            return buf;
        }
    }


    static class Tagged implements Encodeable
    {
        private int no;
        private Encodeable content;

        public Tagged(int no, Encodeable content)
        {
            this.no = no;
            this.content = content;
        }

        @Override
        public byte[] getEncoded() throws IOException
        {
            byte[] bs = content.getEncoded();
            byte[] buf = new byte[bs.length+2];
            buf[0] = (byte)(CONSTRUCTED | TAGGED | no); // < 31
            buf[1] = (byte)((bs.length & 0x7F));
            System.arraycopy(bs, 0, buf, 2, bs.length);
            return buf;
        }
    }


    private static void dump(byte[] encoded)
    {
        for(int i=0; i< encoded.length; i++)
        {
            System.out.printf("%02x",  (encoded[i] & 0xff));
            if (i % 16 == 15)
                System.out.println();
            else
                System.out.print(" ");
        }
    }

    public static byte[] fromHex(String hex)
    {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                            + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    private static byte[] createSig(String algHex, byte[] der) throws GeneralSecurityException
    {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(fromHex(PRIVKEY));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pk = kf.generatePrivate(spec);

        Signature rsa = Signature.getInstance("SHA1withRSA");
        rsa.initSign(pk);
        rsa.update(fromHex(algHex));
        rsa.update(der);
        return rsa.sign();
    }

    private static void createKey() throws NoSuchAlgorithmException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        kpg.generateKeyPair();
        KeyPair kp = kpg.generateKeyPair();
        System.out.println("pub key:");
        dump(kp.getPublic().getEncoded());
        System.out.println("priv key:");
        dump(kp.getPrivate().getEncoded());
        System.out.println();

//        pub key:
//            30 81 9f 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01
//            05 00 03 81 8d 00 30 81 89 02 81 81 00 81 63 3f
//            51 9b f5 ba 3b b6 db e7 c0 f1 df 88 80 03 fe a4
//            25 93 29 3a cb 6e 8a 1f 4f eb e9 45 43 bf 42 18
//            3e 78 f0 8c 7e 5f 17 d7 8b 40 d6 d4 81 a9 22 ee
//            2e 66 65 a2 40 94 ea 75 44 99 ff 33 c2 1c 56 94
//            24 51 42 ed 3e 74 6c 18 d2 63 6c 59 ae 62 d9 e5
//            54 f4 49 e3 81 f1 28 57 4e 31 86 01 e5 ce d4 85
//            6e ff 78 d8 d4 2b e5 6c 8f 0f 84 95 0e 71 34 5a
//            77 c8 f5 55 b1 94 47 73 f5 6f f5 c1 5b 02 03 01
//            00 01
//        priv key:
//            30 82 02 75 02 01 00 30 0d 06 09 2a 86 48 86 f7
//            0d 01 01 01 05 00 04 82 02 5f 30 82 02 5b 02 01
//            00 02 81 81 00 81 63 3f 51 9b f5 ba 3b b6 db e7
//            c0 f1 df 88 80 03 fe a4 25 93 29 3a cb 6e 8a 1f
//            4f eb e9 45 43 bf 42 18 3e 78 f0 8c 7e 5f 17 d7
//            8b 40 d6 d4 81 a9 22 ee 2e 66 65 a2 40 94 ea 75
//            44 99 ff 33 c2 1c 56 94 24 51 42 ed 3e 74 6c 18
//            d2 63 6c 59 ae 62 d9 e5 54 f4 49 e3 81 f1 28 57
//            4e 31 86 01 e5 ce d4 85 6e ff 78 d8 d4 2b e5 6c
//            8f 0f 84 95 0e 71 34 5a 77 c8 f5 55 b1 94 47 73
//            f5 6f f5 c1 5b 02 03 01 00 01 02 81 80 42 de d7
//            67 c7 32 0d a9 35 0d 9c 4e 64 f3 81 69 a0 26 e8
//            11 1f 68 8c a1 7d 24 d7 a0 07 ae 0d 05 41 80 d8
//            64 d9 3e 81 6e 02 99 a0 e5 b0 82 17 5c 57 dc dc
//            ba 90 63 70 a2 ee 13 ea bd a4 d5 77 9a db 9c 9c
//            ef 44 ba 54 26 0a fb 7d 31 eb 07 e5 e9 6e 96 da
//            da ec 4c 72 34 e2 9a 0a d4 64 64 fd 43 49 3e de
//            a1 53 41 9d b5 38 09 ae 8d 0f ca 50 e3 c3 09 45
//            dd 4e 66 38 a3 2e 39 e7 15 92 ad 3d d9 02 41 00
//            bd f5 4c e7 ec 20 a9 9c 3f 37 82 84 48 80 a8 c2
//            02 a5 73 7a be 75 28 e7 d5 49 2b b8 22 7c 05 7c
//            e6 8e 58 89 14 b4 de 8f 37 f3 50 54 7f 40 25 d2
//            a2 59 ce f7 db f1 5f e6 9d 39 77 b1 d3 53 da f7
//            02 41 00 ae 5f 09 74 fe 18 f4 1c b7 44 be b7 11
//            f7 39 a5 8b 90 3d ee 14 4e dd 21 e4 31 1e 8d 80
//            54 f5 0d be d1 1b ed c1 72 27 6e 1f ad 76 98 5f
//            38 54 30 b0 cd 6e b1 03 7d 3e 96 dc 52 2f ef 66
//            c4 6f bd 02 40 42 ab 09 ff c7 ae ba f8 5c 73 85
//            fa 19 5c 16 5e 69 01 5a 63 34 de f7 a9 4e 00 ed
//            38 25 da 33 2e df d8 0b 98 a8 cc c5 e3 ab f6 58
//            36 1f a7 0a df 3f 1d 97 f7 03 99 56 58 20 cc 1f
//            87 28 ad 20 87 02 40 57 35 4e dc 85 4c e3 a2 0d
//            02 c3 c3 79 a7 c4 dc 07 bd ff 4b 38 3a ed 1b cb
//            2d c9 d3 09 50 f4 32 88 b1 ba 9f 21 75 bf 44 b3
//            71 24 f4 36 03 4d 10 01 0c ed 84 78 73 46 3f 5b
//            37 7b a3 e7 28 ed 9d 02 40 15 76 e2 55 5b d0 65
//            2c dd 63 56 52 3a 94 dc 98 90 ca 0e 54 f0 16 05
//            a2 b5 2c ff b7 d4 3d f0 bd 22 7c df 4f f3 ad 74
//            c4 4b cd 20 34 ec 5c 41 d9 e3 50 86 3a 00 95 c7
//            4e c3 82 72 ca 2c 49 05 f0
    }



    public static void main(String[] args) throws IOException, GeneralSecurityException
    {
        //createKey();

        Seq top = new Seq();
        Seq tbsCert = new Seq();
        /* [0]version */tbsCert.add(new Tagged(0, new Int("02"))); // [0]2(v3)
        /* serial */    tbsCert.add(new Int("42"));     // broken 0x0066
        /* signature */ tbsCert.add(new AlgId(RSA));      // RSAwithSHA1/NULL
        /* issuer */    tbsCert.add(new Name("subject"));  // cn=issuer
        /* validity */  tbsCert.add(new Validity());      // 2016-2018
        /* subject */   tbsCert.add(new Name("subject")); // cn=subject
        /* pk info */   tbsCert.add(new Raw(PUBKEY));     // RSA 1024 (createKey())

        top.add(tbsCert);
        top.add(new AlgId(RSA));

        byte[] sig = createSig(RSA, tbsCert.getEncoded());
        top.add(new Bits(sig)); // TODO: does not work yet

        byte[] result = top.getEncoded();
        dump(result);
        System.out.println();

        String cer =  "-----BEGIN CERTIFICATE-----\r\n"
                       +Base64.getMimeEncoder().encodeToString(result)
                     +"\r\n-----END CERTIFICATE-----";

        System.out.println(cer);

        Files.write(Paths.get("target", "out.cer"), cer.getBytes(StandardCharsets.US_ASCII));

        System.out.println();
    }

}



