package net.eckenfels.test.ssl;

import static net.eckenfels.test.ssl.SimpleBIOSSLClient.dumpBytes;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

public enum HandshakeType
{
    /* based on http://www.rfc-editor.org/rfc/rfc6066.txt#page4 */
     hello_request(0), client_hello(1),

     server_hello(2) {
         public void parse(ByteBuffer buf)
         {
             int rlen = buf.limit() - buf.position();
             System.out.println("  Handshake " + name() + " len=" + rlen);


             System.out.println("    Version=" + buf.get() + "." + buf.get());

             byte[] random = new byte[32];
             buf.get(random);

             int sessionlen = (buf.get() & 255);
             byte[] sessionid = new byte[sessionlen];
             buf.get(sessionid);

             short suite = buf.getShort();
             int compression = (buf.get() & 255);

             System.out.println("    serverrandom=" + dumpBytes(random));
             System.out.println("    session  =" + sessionlen + "/"+ dumpBytes(sessionid));
             System.out.println("    suite=" + suite + " compression=" + compression);

             if (buf.hasRemaining())
                 SimpleBIOSSLClient.printRecordBytes(buf);
         }
     },

     certificate(11) {
         public void parse(ByteBuffer buf)
         {
             int rlen = buf.limit() - buf.position();
             System.out.println("  Handshake " + name() + " len=" + rlen);

             buf.get(); short llen = buf.getShort(); // uint24

             System.out.println("    listlen=" + llen);

             rlen-=6;
             rlen-=llen;

             while(llen > 0)
             {
                 buf.get(); short clen = buf.getShort(); // uint24
                 byte[] cert = new byte[clen];
                 buf.get(cert);
                 //System.out.println("    Cert=" + clen + "/" + dumpBytes(cert));
                 X509Certificate c = null;
                 try {
                     c = X509Certificate.getInstance(cert);
                 } catch (CertificateException e) {
                     // TODO Auto-generated catch block
                     e.printStackTrace();
                 }
                 System.out.println("      DN=" + c.getSubjectDN().getName());
                 if (SimpleBIOSSLClient.cert == null) SimpleBIOSSLClient.cert = c;
                 llen-=3;
                 llen-=clen;
             }

             if (buf.hasRemaining())
                 SimpleBIOSSLClient.printRecordBytes(buf);
         }
     },

     server_key_exchange (12),
     certificate_request(13), server_hello_done(14),
     certificate_verify(15), client_key_exchange(16),
     finished(20), certificate_url(21), certificate_status(22);


    private static Map<Byte, HandshakeType> codeValueMap = new HashMap<Byte, HandshakeType>(20);

    static
    {
        for (HandshakeType type : HandshakeType.values())
        {
            codeValueMap.put(Byte.valueOf(type.code), type);
        }
    }

    public static HandshakeType getTypeByCode(byte code)
    {
        return codeValueMap.get(Byte.valueOf((byte)code));
    }


    private byte code;

    private HandshakeType(int code)
    {
        this.code = (byte)code;
    }

    public byte code()
    {
        return code;
    }

    public void parse(ByteBuffer buf)
    {
        int rlen = buf.limit() - buf.position();
        System.out.println("  Handshake " + name() + " len=" + rlen);
        if (buf.hasRemaining())
            SimpleBIOSSLClient.printRecordBytes(buf);
    }
}
