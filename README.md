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
