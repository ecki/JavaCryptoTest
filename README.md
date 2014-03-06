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
    Default      SHA1PRNG SUN
    Windows-PRNG Windows-PRNG SunMSCAPI : java.security.SecureRandom Seeded in 11ms
    Windows-PRNG 10000*int Took 1461ms with instantiation/seeding
    Windows-PRNG 10000*int Took 1090ms without instantiation/seeding
    SHA1PRNG SHA1PRNG SUN : java.security.SecureRandom Seeded in 80ms
    SHA1PRNG 10000*int Took 267ms with instantiation/seeding
    SHA1PRNG 10000*int Took 4ms without instantiation/seeding
