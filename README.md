JavaCryptoTest
==============

Assorted test code for JCE and JSSE


## Simple BlockingIO SSL Client
This class can be used to simulate SSL Handshakes (with and without local crypto).

    java -cp target/classes net.eckenfels.test.ssl.SimpleBIOSSLClient [<hostname> [<portnum> [<snihostname>]]]

 - _hostname_ defaults to `173.194.35.178` (google.com)
 - _portnum_ defaults to `443` (https)
 - _snihostname_ defaults to `null` (do not send)
