package net.eckenfels.test.ssl;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;


public class SimpleBIOSSLClient
{
    private static final byte CONTENTTYPE_ALERT = (byte) 21;
    private static final byte CONTENTTYPE_HANDSHAKE = (byte) 22;
    private static final byte HANDSHAKETPE_CLIENTHELLO = (byte) 1;

    public static void main(String[] args) throws IOException
    {
        SocketChannel c = SocketChannel.open();
        c.configureBlocking(true);
        c.connect(new InetSocketAddress("www.gmail.com", 443));

        // following code assumes all records are received complete and
        // all (even multiple) fit into a single 2k read
        ByteBuffer buf = ByteBuffer.allocate(2048);

        constructClientHello(buf);
        c.write(buf);

        buf.clear();
        int eof = c.read(buf);
        buf.flip();

        printRecords(buf);
    }

    private static void printRecords(ByteBuffer buf)
    {
        while(buf.hasRemaining()) {
            byte type = buf.get();
            System.out.println("Record type=" + type);
            System.out.println("  protocol version=" + buf.get() +"." + buf.get());
            int len = buf.getShort();
            System.out.println("  len=" + len);
            switch (type)
                {
                case CONTENTTYPE_HANDSHAKE:
                    printHandshakeRecord(buf, len);
                    break;
                case CONTENTTYPE_ALERT:
                    printAlertRecord(buf, len);
                    break;
                default:
                    printRecordBytes(buf, len);
                    break;
                }
        }
    }

    private static void printRecordBytes(ByteBuffer buf, int len)
    {
        System.out.print("  bytes=");
        for (int i = 0; i < len; i++)
            System.out.printf("%02x ", buf.get());
        System.out.println();
    }

    private static void printAlertRecord(ByteBuffer buf, int len)
    {
        System.out.println("  Alert len=" + len);
        printRecordBytes(buf, len);
    }

    private static void printHandshakeRecord(ByteBuffer buf, int len)
    {
        byte type = buf.get();
        switch(type)
        {
        case HANDSHAKETPE_CLIENTHELLO:
            System.out.println("  ClientHello");
            break;
        default:
            System.out.println("  Handshake type=" + type);
        }
        printRecordBytes(buf, len - 1);
    }

    static void constructClientHello(ByteBuffer buffer)
    {
        buffer.clear();
        buffer.put(CONTENTTYPE_HANDSHAKE);
        buffer.putShort((short) 0x301); // TLSv1 3.1
        buffer.putShort((short) 85); // length

        buffer.put(HANDSHAKETPE_CLIENTHELLO);
        buffer.put((byte) 0); // Length uint24
        buffer.putShort((short) 81);
        buffer.putShort((short) 0x301); // TLSv1 3.1

        buffer.putInt(0xffffffff); // timestamp
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
        buffer.put((byte) 0); // 0=nocompression, 0xff=compression

        buffer.flip();
    }

}
