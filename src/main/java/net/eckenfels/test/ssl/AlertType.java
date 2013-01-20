package net.eckenfels.test.ssl;

import java.util.HashMap;
import java.util.Map;

/* based on http://www.rfc-editor.org/rfc/rfc6066.txt */
public enum AlertType
{
    close_notify(0),
    unexpected_message(10),
    bad_record_mac(20),
    decryption_failed(21),
    record_overflow(22),
    decompression_failure(30),
    handshake_failure(40),
    /* 41 is not defined, for historical reasons */
    bad_certificate(42),
    unsupported_certificate(43),
    certificate_revoked(44),
    certificate_expired(45),
    certificate_unknown(46),
    illegal_parameter(47),
    unknown_ca(48),
    access_denied(49),
    decode_error(50),
    decrypt_error(51),
    export_restriction(60),
    protocol_version(70),
    insufficient_security(71),
    internal_error(80),
    user_canceled(90),
    no_renegotiation(100),
    unsupported_extension(110),           /* new */
    certificate_unobtainable(111),        /* new */
    unrecognized_name(112),               /* new */
    bad_certificate_status_response(113), /* new */
    bad_certificate_hash_value(114);      /* new */

    private static Map<Byte, AlertType> codeValueMap = new HashMap<Byte, AlertType>(100);
    static {
        for (AlertType type : AlertType.values())
        {
            codeValueMap.put(Byte.valueOf(type.code), type);
        }
    }

    public static AlertType getTypeByCode(byte code)
    {
        return codeValueMap.get(Byte.valueOf(code));
    }

    private byte code;
    private AlertType(int code)
    {
        this.code = (byte)code;
    }

    public byte getCode()
    {
        return code;
    }
}
