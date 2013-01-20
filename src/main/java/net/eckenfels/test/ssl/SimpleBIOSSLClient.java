package net.eckenfels.test.ssl;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;


/** World most ugly SSL Client simulator. */
public class SimpleBIOSSLClient
{
    private static final byte CONTENTTYPE_CHANGECIPHERSPEC = (byte)20;
    private static final byte CONTENTTYPE_ALERT = (byte) 21;
    private static final byte CONTENTTYPE_HANDSHAKE = (byte) 22;


    public static void main(String[] args) throws IOException
    {
        SocketChannel c = SocketChannel.open();
        c.configureBlocking(true);
        c.connect(new InetSocketAddress("173.194.35.178", 443)); // google.com

        // NB: all following code assumes all records are received complete and
        // all (even multiple) fit into a single 10k read
        ByteBuffer buf = ByteBuffer.allocate(10240);

        constructClientHello(buf, "test.de");
        printRecords(">>>", buf); buf.flip();
        c.write(buf);

        buf.clear();
        c.read(buf);
        buf.flip();
        printRecords("<<<", buf);

        constructClientKEX(buf);
        printRecords(">>>", buf); buf.flip();
        c.write(buf);

        buf.clear();
        c.read(buf);
        buf.flip();
        printRecords("<<<", buf);
    }


    private static void constructClientKEX(ByteBuffer buffer)
    {
        buffer.clear();
        buffer.put(CONTENTTYPE_HANDSHAKE);
        buffer.putShort((short) 0x301); // TLSv1 3.1
        buffer.putShort((short)134);    // record length

        buffer.put(HandshakeType.client_key_exchange.getCode());

        buffer.put((byte) 0); // Length uint24
        buffer.putShort((short)130);

        // TODO: sent a PKCS#1 RSA enctypted PreMasterSecret(short version, byte[46] random)
        for (int i=0;i<130;i++)
            buffer.put((byte)0);

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


    private static void printRecords(String marker, ByteBuffer buf)
    {
        while(buf.hasRemaining())
        {
            byte type = buf.get();
            int len;
            System.out.println(marker + "Record type=" + type + " version=" + buf.get() +"." + buf.get() + " len=" + (len = buf.getShort()));
            switch (type)
            {
                case CONTENTTYPE_HANDSHAKE:
                    printHandshakeRecord(buf, len);
                    break;
                case CONTENTTYPE_ALERT:
                    printAlertRecord(buf, len);
                    break;
                case CONTENTTYPE_CHANGECIPHERSPEC:
                    System.out.println("  Change Cipher Spec");
                    printRecordBytes(buf, len);
                    break;
                default:
                    printRecordBytes(buf, len);
                    break;
            }
        }
    }

    private static void printRecordBytes(ByteBuffer buf, int len)
    {
        System.out.print("    bytes=");
        for (int i = 0; i < len; i++)
            System.out.printf("%02x ", buf.get());
        System.out.println();
    }

    private static void printAlertRecord(ByteBuffer buf, int len)
    {
        System.out.println("  Alert len=" + len);
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

        len-=2;
        if (len > 0)
            printRecordBytes(buf, len);
    }

    private static void printHandshakeRecord(ByteBuffer buf, int len)
    {
        byte typeByte = buf.get();
        HandshakeType type = HandshakeType.getTypeByCode(typeByte);
        if (type != null)
            System.out.println("  Handshake " + type);
        else
            System.out.println("  Handshake type=" + typeByte);

        len-=1;
        if (len > 0)
            printRecordBytes(buf, len);
    }

    private static void constructClientHello(ByteBuffer buffer, String hostname)
    {
        byte[] hostnameBytes = null;
        try { hostnameBytes = hostname.getBytes("ASCII"); } catch (Exception ignored) { }

        buffer.clear();
        buffer.put(CONTENTTYPE_HANDSHAKE);
        buffer.putShort((short) 0x301); // TLSv1 3.1
        buffer.putShort((short) (85+((hostnameBytes!=null)?hostnameBytes.length+9:0))); // length

        buffer.put(HandshakeType.client_hello.getCode());

        buffer.put((byte) 0); // Length uint24
        buffer.putShort((short) (81+((hostnameBytes!=null)?hostnameBytes.length+9:0)));

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
        // buffer.putShort((short)0x39); // TLS_RSA_WITH_RC4_128_SHA

        buffer.putShort((short) 0x16);
        buffer.putShort((short) 0x13);
        buffer.putShort((short) 0x0a);
        buffer.putShort((short) 0x66);
        buffer.putShort((short) 0x07);
        buffer.putShort((short) 0x05);
        buffer.putShort((short) 0x04);
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
            buffer.putShort((short)(hostnameBytes.length+7)); // length

            buffer.putShort((short)0); // ExtensionType server_name(0)
            buffer.putShort((short)(hostnameBytes.length+3)); // len

            buffer.put((byte)0); // name_type hostname(0)
            buffer.putShort((short)(hostnameBytes.length)); // HostName opaque length
            buffer.put(hostnameBytes);
        }

        buffer.flip();
    }

}

