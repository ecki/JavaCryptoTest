package net.eckenfels.test.ssl;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.X509Certificate;


/** World most ugly SSL Client simulator. */
public class SimpleBIOSSLClient
{
    public enum Direction {
        IN("<<<"), OUT(">>>");

        String dir;
        Direction(String dir) { this.dir = dir; }
        public String toString() { return dir; }
    }

    private static final byte CONTENTTYPE_CHANGECIPHERSPEC = (byte)20;
    private static final byte CONTENTTYPE_ALERT = (byte) 21;
    private static final byte CONTENTTYPE_HANDSHAKE = (byte) 22;

    // some really silly session state
    protected static boolean outEnc;
    protected static boolean inEnc;
    protected static X509Certificate cert;


    public static void main(String[] args) throws IOException
    {
        SocketChannel c = SocketChannel.open();
        c.configureBlocking(true);
        c.connect(new InetSocketAddress("173.194.35.178", 443)); // google.com
        //c.connect(new InetSocketAddress("localhost", 1234));

        // NB: all following code assumes all records are received complete and
        // all (even multiple) fit into a single 10k read
        ByteBuffer buf = ByteBuffer.allocate(10240);

        constructClientHello(buf, "test.de");
        printRecords(Direction.OUT, buf); buf.flip();
        c.write(buf);

        buf.clear();
        c.read(buf);
        buf.flip();
        printRecords(Direction.IN, buf);

        buf.clear();
        c.read(buf);
        buf.flip();
        printRecords(Direction.IN, buf);

        buf.clear();
        c.read(buf);
        buf.flip();
        printRecords(Direction.IN, buf);

        constructClientKEX(buf);
        printRecords(Direction.OUT, buf); buf.flip();
        c.write(buf);

        buf.clear();
        c.read(buf);
        buf.flip();
        printRecords(Direction.IN, buf);
    }


    private static void constructClientKEX(ByteBuffer buffer)
    {

        byte[] encrypted = createEncryptedPreMaster(false);


        buffer.clear();
        buffer.put(CONTENTTYPE_HANDSHAKE);
        buffer.putShort((short) 0x301); // TLSv1 3.1
        buffer.putShort((short)(encrypted.length + 6));    // record length

        buffer.put(HandshakeType.client_key_exchange.code());


        buffer.put((byte) 0); // Length uint24
        buffer.putShort((short)(encrypted.length + 2));

        buffer.putShort((short)encrypted.length);
        buffer.put(encrypted);

        buffer.put(CONTENTTYPE_CHANGECIPHERSPEC);
        buffer.putShort((short)0x301);
        buffer.putShort((short)1);

        buffer.put((byte)1); // change cipher

        // encrypted Finished 12 bytes
        buffer.put(CONTENTTYPE_HANDSHAKE);
        buffer.putShort((short)0x301);
        buffer.putShort((short)36);

        for (int i=0;i<36;i++)
            buffer.put((byte)0);

        buffer.flip();
    }


    private static byte[] createEncryptedPreMaster(boolean fake)
    {
        if (fake)
        {
            // we do not have to do this calculation to force server to think
            int len = ((RSAPublicKey)cert.getPublicKey()).getModulus().bitLength() / 8;
            return new byte[len];
        }

        byte[] preMaster = new byte[48];
        preMaster[0]=(byte)3; preMaster[1]=(byte)1;
        SecretKey preMasterKey = new SecretKeySpec(preMaster, "RAW");
        Cipher rsa;
        try {
            rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.WRAP_MODE, cert.getPublicKey(), new SecureRandom());
            return rsa.wrap(preMasterKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new RuntimeException("Problem", e);
        }
    }


    private static void printRecords(Direction direction, ByteBuffer buf)
    {
        while(buf.hasRemaining())
        {
            byte type = buf.get();
            byte v1 = buf.get(); byte v2=buf.get();
            int len = buf.getShort();

            ByteBuffer data = buf.asReadOnlyBuffer();
            buf.position(buf.position() + len);
            data.limit(data.position() + len);

            System.out.println(direction + " Record type=" + type + " version=" + v1 +"." + v2 + " len=" + len);

            switch (type)
            {
                case CONTENTTYPE_HANDSHAKE:
                    printHandshakeRecord(data, ((direction == Direction.IN)?inEnc:outEnc));
                    break;
                case CONTENTTYPE_ALERT:
                    printAlertRecord(data);
                    break;
                case CONTENTTYPE_CHANGECIPHERSPEC:
                    System.out.println("  Change Cipher Spec");
                    printRecordBytes(data);
                    if (direction == Direction.OUT)
                        outEnc = true;
                    else
                        inEnc = true;
                    break;
                default:
                    printRecordBytes(data);
                    break;
            }
        }
    }

    static void printRecordBytes(ByteBuffer buf)
    {
        int rlen = buf.limit() - buf.position();
        byte[] bytes = new byte[rlen];
        buf.get(bytes);
        System.out.println("    bytes=" + dumpBytes(bytes));
    }

    static String dumpBytes(byte[] bytes){
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < bytes.length; i++)
            b.append(String.format("%02x ", bytes[i]));
        return b.toString();
    }


    static void printAlertRecord(ByteBuffer buf)
    {
        int rlen = buf.limit();
        System.out.println("  Alert len=" + rlen);
        byte warnError = buf.get();
        byte alertCode = buf.get();

        String alertLevel;
        switch(warnError)
        {
        case 1:
            alertLevel = "warning(1)";
            break;
        case 2:
            alertLevel = "fatal(2)";
            break;
        default:
            alertLevel = "AlertLevel(" + warnError +")";
            break;
        }

        AlertType alertType = AlertType.getTypeByCode(alertCode);
        if (alertType != null)
            System.out.println("    " + alertLevel + " " + alertType);
        else
            System.out.println("    " + alertLevel + " AlerType(" + alertCode + ")");

        if (buf.hasRemaining())
            printRecordBytes(buf);
    }

    static void printHandshakeRecord(ByteBuffer buf, boolean enc)
    {
        while(buf.hasRemaining())
        {

            if (enc)
            {
                System.out.println("  Handshake Encrypted");
                printRecordBytes(buf);
                continue;
            }

            byte typeByte = buf.get();
            HandshakeType type = HandshakeType.getTypeByCode(typeByte);
            buf.get(); short len = buf.getShort(); // uint24

            ByteBuffer data = buf.asReadOnlyBuffer();
            data.limit(len + data.position());
            buf.position(buf.position() + len);

            if (type != null)
            {
                type.parse(data);
            } else {
                System.out.println("  Handshake type=" + typeByte);
                printRecordBytes(data);
            }
        }
    }

    static void constructClientHello(ByteBuffer buffer, String hostname)
    {
        byte[] hostnameBytes = null;
        try { hostnameBytes = hostname.getBytes("UTF8"); } catch (Exception ignored) { }

        buffer.clear();
        buffer.put(CONTENTTYPE_HANDSHAKE);
        buffer.putShort((short) 0x301); // TLSv1 3.1
        buffer.putShort((short) (85+((hostnameBytes!=null)?hostnameBytes.length+11:0))); // length

        buffer.put(HandshakeType.client_hello.code());

        buffer.put((byte) 0); // Length uint24
        buffer.putShort((short) (81+((hostnameBytes!=null)?hostnameBytes.length+11:0)));

        buffer.putShort((short) 0x301); // TLSv1 3.1

        buffer.putInt(0xffffffff); // unix timestamp
        buffer.putInt(0x11223344); // random 28 bytes
        buffer.putInt(0x11223344); // random
        buffer.putInt(0x11223344); // random
        buffer.putInt(0x11223344); // random
        buffer.putInt(0x11223344); // random
        buffer.putInt(0x11223344); // random
        buffer.putInt(0x11223344); // random

        buffer.put((byte) 0); // sessionid length = 0

        buffer.putShort((short) 42); // 42 = 21 ciphers
        buffer.putShort((short) 0x0a); // TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)
        buffer.putShort((short) 0x07); // TLS_RSA_WITH_IDEA_CBC_SHA (0x0007)
        buffer.putShort((short) 0x05); // TLS_RSA_WITH_RC4_128_SHA (0x0005)
        buffer.putShort((short) 0x04); // TLS_RSA_WITH_RC4_128_MD5 (0x0004)

        // DHE does not work
        buffer.putShort((short) 0x39); // TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
        buffer.putShort((short) 0x13); // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA (0x0013)
        buffer.putShort((short) 0x66); // TLS_DHE_DSS_WITH_RC4_128_SHA (0x0066)
        buffer.putShort((short) 0x65);
        buffer.putShort((short) 0x64);
        buffer.putShort((short) 0x63);
        buffer.putShort((short) 0x62);
        buffer.putShort((short) 0x61);
        buffer.putShort((short) 0x60);
        buffer.putShort((short) 0x15);
        buffer.putShort((short) 0x12);
        buffer.putShort((short) 0x09);
        buffer.putShort((short) 0x14);
        buffer.putShort((short) 0x11);
        buffer.putShort((short) 0x08);
        buffer.putShort((short) 0x06);
        buffer.putShort((short) 0x03);

        buffer.put((byte) 1); // number of compression options
        buffer.put((byte) 0); // 0=nocompression
        //buffer.put((byte) 1); // 1=deflate

        // SNI rfc3546
        if (hostnameBytes != null && hostnameBytes.length > 0)
        {
            buffer.putShort((short)(hostnameBytes.length+9)); // length

            buffer.putShort((short)0); // ExtensionType server_name(0)
            buffer.putShort((short)(hostnameBytes.length+5)); // len

            buffer.putShort((short)(hostnameBytes.length+3)); // len
            buffer.put((byte)0); // name_type hostname(0)
            buffer.putShort((short)(hostnameBytes.length)); // HostName opaque length
            buffer.put(hostnameBytes);
        }

        buffer.flip();
    }

}

