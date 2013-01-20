package net.eckenfels.test.ssl;

import java.util.HashMap;
import java.util.Map;


public enum HandshakeType
{
    /* based on http://www.rfc-editor.org/rfc/rfc6066.txt#page4 */
     hello_request(0), client_hello(1), server_hello(2),
     certificate(11), server_key_exchange (12),
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

    public byte getCode()
    {
        return code;
    }

    private byte code;

    private HandshakeType(int code)
    {
        this.code = (byte)code;
    }
}
