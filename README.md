JavaCryptoTest
==============

Assorted test code for JCE and JSSE

## JCE Provider Info

Dumps all registered crypto providers

    java -cp target/classes net.eckenfels.test.jce.JCEProviderInfo

## SHA-1 Hash Overflow test

Run the JUnit test for net.eckenfels.test.jce.HashOVerflowTest to verify SHA-1 test vectors
for 257GB null bytes (see http://comments.gmane.org/gmane.comp.encryption.gpg.devel/18244)

## Simple BlockingIO SSL Client

This class can be used to simulate SSL Handshakes (with and without local crypto).

    java -cp target/classes net.eckenfels.test.ssl.SimpleBIOSSLClient [<hostname> [<portnum> [<snihostname>]]]

 - _hostname_ defaults to `173.194.35.178` (google.com)
 - _portnum_ defaults to `443` (https)
 - _snihostname_ defaults to `null` (do not send)

## SSLServerSocket test code

This class can be used to test aspects around ciphersuites and handshakes of the JSSE SSLServerSocket

    java -cp target/classes net.eckenfels.test.ssl.JSSESocketServer

It will isten to 0.0.0.0:1234 to one SSL connection, print out all handshake events,
after 30 seconds disable all handshake ciphers, and then after 30 more seconds exit the test.

## SSLSocketFactory validation with howsmyssl.com

https://howsmyssl.com is a Site for testing Web Browsers and other SSL/TLS clients for
ciphers and other settings. The `net.eckenfels.test.howsmyssl.Client` class opens
a SSL connection with the default provider of the VM and outputs the result from this web site.

This code contains optionally hints on how to configure the supported SSL protocols as well
as setting the endpoint identification (required by raw sockets to defend against MITM attacks).

Example:

    c:\> java -cp target\classes net.eckenfels.test.howsmyssl.Client
    Howsmyssl Test: Java HotSpot(TM) 64-Bit Server VM 1.8.0-b129/25.0-b69 on Windows 7 6.1
    Cipher used TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    HTTP/1.1 200 OK
    Content-Length: 1578
    Connection: close
    Content-Type: application/json
    Date: Sat, 15 Feb 2014 23:53:35 GMT
    Strict-Transport-Security: max-age=631138519; includeSubdomains

    {"given_cipher_suites":["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
      "TLS_RSA_WITH_AES_128_CBC_SHA256",
      "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
      "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
      "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
      "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
      "TLS_RSA_WITH_AES_128_CBC_SHA",
      "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
      "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
      "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
      "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
      "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
      "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
      "TLS_RSA_WITH_RC4_128_SHA",
      "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
      "TLS_ECDH_RSA_WITH_RC4_128_SHA",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
      "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
      "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
      "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
      "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
      "TLS_RSA_WITH_RC4_128_MD5",
      "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"],
      "ephemeral_keys_supported":true,
      "session_ticket_supported":false,
      "tls_compression_supported":false,
      "unknown_cipher_suite_supported":false,
      "beast_vuln":false,
      "able_to_detect_n_minus_one_splitting":false,
      "insecure_cipher_suites":{},
      "tls_version":"TLS 1.2",
      "rating":"Improvable"}

## PRNG Info
Simple PRNG SecureRandom timings:

    java -cp target/classes net.eckenfels.test.jce.SecureRandomInfo
    new SecureRandom()              SHA1PRNG SUN
    SecureRandom.getInstanceStrong  Windows-PRNG SunMSCAPI
    Windows-PRNG SunMSCAPI : java.security.SecureRandom Seeded in 5,441 ms.
    Windows-PRNG SunMSCAPI : java.security.SecureRandom nextInt() in 6,619 ms.
    Windows-PRNG SunMSCAPI : java.security.SecureRandom nextInt() in 0,144 ms.
    Windows-PRNG SunMSCAPI : java.security.SecureRandom nextInt() in 0,112 ms.
    Windows-PRNG 10000*int Took 901,402 ms with instantiation/seeding.
    Windows-PRNG 10000*int Took 797,608 ms without instantiation/seeding
    SHA1PRNG SUN : java.security.SecureRandom Seeded in 0,247 ms.
    SHA1PRNG SUN : java.security.SecureRandom nextInt() in 315,138 ms.
    SHA1PRNG SUN : java.security.SecureRandom nextInt() in 0,058 ms.
    SHA1PRNG SUN : java.security.SecureRandom nextInt() in 0,049 ms.
    SHA1PRNG 10000*int Took 329,125 ms with instantiation/seeding.
    SHA1PRNG 10000*int Took 7,351 ms without instantiation/seeding.

## DH Info
A simple example to generate DH domain parameters and a secret key (including
finding the largest prime length supported and timing)

    JCE Provider Info: Java HotSpot(TM) 64-Bit Server VM 1.8.0_25-b18/25.25-b02 on Windows 7 6.1
    Largest Parameter: 2048 DiffieHellman@SunJCE version 1.8
      generated parameter in 11,461s: SunJCE Diffie-Hellman Parameters:
    p:
        f9ab8671 299984dd 0698288e 93ae3ad5 50c37ddc 980ff37a aa6730f8 e8fda9f7
        b0302620 631ccc35 fef21b76 d11c5587 4d344be4 001edff5 6772529b 1db917d4
        286de70a ead5acc7 a213f746 74a146e3 aea675e4 c02cac33 b5e634fe b2bdf148
        d83397de 6bee0a97 cab3b9d3 614d5503 b25f2034 6dc77d71 8d58323a 44156aa5
        c826b152 352e64fa e5b3baa2 8e1b3566 7dcc7ddc 5a15d28d 0993f16a 92b9c788
        e0293247 931f9dfa 418a0be2 7590d332 7c6a8958 f84df718 e364904d 89fc5f7c
        e77e6675 2c879718 87fdcc3e ef7c9356 9373b79e 3a731bb0 744b4fca 24718505
        9fff6738 7793faba aad924f1 11445a9b cd7e59b4 c60da8b8 0b128774 4598686d
    g:
        d9ed5134 0651dffb 45d911b3 f465a999 a04e86f0 829fce3a dff2ddaf b6400ab3
        117bc045 637c12ac 18256a8a 3e63dd73 2d9ec12b 978d6dc6 566e732c f6cc2246
        d1a7039d a39fde7e e2958ac9 06f8f1ff f4270a51 d8465fe5 1271c940 6485cfa4
        2317aadf 6318b0a5 d7a971cd 0e1a18d7 43d8ff32 65788c34 647e4ed3 dce95464
        4d588c68 6bacedcf de62b333 ce40af65 e6f7ea4e 5f393769 0bd56ce0 cda82589
        67e3db24 354f3143 d6cbe514 f272a45f d8bfebea 7b4a7d27 8bbf12ba cd7c746c
        7e3a9659 b40acf7e 89c58c00 dcb8f875 41afaeaa 5fdd3e88 4dc204f3 d41590f3
        5f808ffd b1f08826 3b5d0155 a88a26f7 9f7aae75 1ea8bd7b 99a62335 7e97f91f
    l:
        2047
      generated key in 189,545ms: SunJCE Diffie-Hellman Public Key:
    y:
        3fd4b877 3fc42a2e a630991c c3f92d83 fce8e804 98d33bfe 44bb9d19 4c1f934d
        dd5c55f8 32d98f70 fd74b759 d39491c7 5a19680d c9e75380 75a29d25 52dda40c
        4a97bf5b 1202b9e5 6377e5a7 79dc5c1f 2b35e8d7 46136d31 35aa8f9d 9e4e1dd0
        1021c81b 875b8d4f 3e6b3444 45fbed69 c4f14851 cf656c61 699c2ebc 9450a132
        f8ec7c6f c7711d04 650eed3d 70651f7b ef37bcc7 f6300337 717e65b5 244459ec
        a01aa71a 9787a8b2 b40dc37b 0b6ef5c1 ed6ee1ee 522ede72 b08cbf09 1b44d6a4
        96f87b9b 38143d20 d42260c8 3a79ef3e bcf3c801 083bfc34 3785f514 53e03e82
        73c7a843 47a86c90 e28e1227 a93bd541 93b8484a 124c36ef d98839f1 887bf70d
    p:
        f9ab8671 299984dd 0698288e 93ae3ad5 50c37ddc 980ff37a aa6730f8 e8fda9f7
        b0302620 631ccc35 fef21b76 d11c5587 4d344be4 001edff5 6772529b 1db917d4
        286de70a ead5acc7 a213f746 74a146e3 aea675e4 c02cac33 b5e634fe b2bdf148
        d83397de 6bee0a97 cab3b9d3 614d5503 b25f2034 6dc77d71 8d58323a 44156aa5
        c826b152 352e64fa e5b3baa2 8e1b3566 7dcc7ddc 5a15d28d 0993f16a 92b9c788
        e0293247 931f9dfa 418a0be2 7590d332 7c6a8958 f84df718 e364904d 89fc5f7c
        e77e6675 2c879718 87fdcc3e ef7c9356 9373b79e 3a731bb0 744b4fca 24718505
        9fff6738 7793faba aad924f1 11445a9b cd7e59b4 c60da8b8 0b128774 4598686d
    g:
        d9ed5134 0651dffb 45d911b3 f465a999 a04e86f0 829fce3a dff2ddaf b6400ab3
        117bc045 637c12ac 18256a8a 3e63dd73 2d9ec12b 978d6dc6 566e732c f6cc2246
        d1a7039d a39fde7e e2958ac9 06f8f1ff f4270a51 d8465fe5 1271c940 6485cfa4
        2317aadf 6318b0a5 d7a971cd 0e1a18d7 43d8ff32 65788c34 647e4ed3 dce95464
        4d588c68 6bacedcf de62b333 ce40af65 e6f7ea4e 5f393769 0bd56ce0 cda82589
        67e3db24 354f3143 d6cbe514 f272a45f d8bfebea 7b4a7d27 8bbf12ba cd7c746c
        7e3a9659 b40acf7e 89c58c00 dcb8f875 41afaeaa 5fdd3e88 4dc204f3 d41590f3
        5f808ffd b1f08826 3b5d0155 a88a26f7 9f7aae75 1ea8bd7b 99a62335 7e97f91f
    l:
        2047
