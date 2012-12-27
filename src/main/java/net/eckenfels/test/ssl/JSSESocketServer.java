package net.eckenfels.test.ssl;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;


/**
 * Simple SSL Socket Server (single threaded) for experimenting with JSSE SSL sessions.
 *
 * @author Bernd Eckenfels
 */
public class JSSESocketServer
{
	private final static String PASS = "changeit";

    /**
     * Main method to start socket server.
     * <P>
     * Does not use any parameters, but yo ucan use the system property to debug the
     * various JCE and JSSE layers: <code>-Djavax.net.debug=ssl,keymanager</code>
     */
    public static void main(String[] args) throws IOException, InterruptedException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, CertificateException, NoSuchProviderException, SignatureException
    {
        System.out.println("Setting up Test-SSL Server with JSSE");


        System.out.println("o Creating Key Manager with temporary self signed cert.");

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
        kmf.init(genKeyStore(), PASS.toCharArray());
        KeyManager[] keyManagers = kmf.getKeyManagers();
        X509KeyManager km = (X509KeyManager) keyManagers[0];
        System.out.println("  keymanager.length=" + keyManagers.length + " keyManager[0]=" + km.toString());

        System.out.println("o Creating empty trust manager.");
        // empty trust manager
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(emptyKeystore());
        TrustManager[] trustManagers = tmf.getTrustManagers();
        X509TrustManager tm = (X509TrustManager)trustManagers[0];
        System.out.println("  trustManager.length=" + trustManagers.length + " trustManager[0]=" + tm.toString());

        System.out.println("o Creating SSL Context.");
        // get a new uninitialized context
        javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("SSL");
        ctx.init(keyManagers, trustManagers, new SecureRandom());

        System.out.println("o Creating SSLServerSocketFactory");
        SSLServerSocketFactory ssf = (SSLServerSocketFactory)ctx.getServerSocketFactory();

        System.out.println("  ssf default=" + dump(ssf.getDefaultCipherSuites()));

        System.out.println("o Creating SSLServerSocket.");
        SSLServerSocket server = (SSLServerSocket) ssf.createServerSocket(1234);

        System.out.println("  Listening on " + server.getLocalSocketAddress());
        // the following list unfortunatelly contains more ciphers than will be accepted (for example if no server key is present).
        System.out.println("  Enabled: ciphers=" + dump(server.getEnabledCipherSuites()) + " protos=" + dump(server.getEnabledProtocols()));

        SSLSocket sock = (SSLSocket) server.accept();

        HandshakeCompletedListener listener = new HandshakeCompletedListener() {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent event)
            {
                System.out.println("[" + Thread.currentThread().getName() + "] Completed socket=" + event.getSocket() + " session=" + event.getSession());
            }
        };
        sock.addHandshakeCompletedListener(listener);

        System.out.println("o Accepted client " + sock.getRemoteSocketAddress());

        System.out.println("o Starting initial handshake.");
        sock.startHandshake();
        System.out.println("  After handshake, usedCipher=" + sock.getSession().getCipherSuite());
        System.out.println("  enabled=" + dump(sock.getEnabledCipherSuites()));


        System.out.println("o Reading for 30s");
        readBackground(sock);
        Thread.sleep(30*1000);

        System.out.println("o Disabling ciphers... ");
        sock.setEnabledCipherSuites(new String[0]); // null not possible in sun.security.ssl.CipherSuiteList.<init>

        System.out.println("o Reading for 30s");
        Thread.sleep(30*1000);

        System.out.println("o Done.");
        System.exit(0);
    }


    /**
     * Drain and dump input Stream of SSL Socket.
     * <P>
     * This is needed to allow multiple SSL Handshakes (renegotiation after initial handshake).
     *
     * @param sock
     */
    private static void readBackground(final SSLSocket sock)
    {
    	Runnable run = new Runnable() {
    		SSLSocket s = sock;
    		@Override
    		public void run()
    		{
    			InputStream in;
    			try {
    				in = s.getInputStream();

    				int c;
    				while((c = in.read()) >= 0)
    				{
    					System.out.println(" read " + c);
    				}
    			} catch (IOException e) {
    				e.printStackTrace();
    			}
    		}
    	};
    	new Thread(run, "Reader " + sock).start();
	}

    /** Print String Array. */
    private static String dump(String[] strings) {
        StringBuilder sb = new StringBuilder(100);
        for(String s : strings)
        {
            sb.append(s).append(',');
        }
        return sb.substring(0,sb.length()-1);
    }


    /** Generate KeyStore with temporary self signed certificate in memory. */
    private static KeyStore genKeyStore() throws NoSuchAlgorithmException, IOException, CertificateException, InvalidKeyException, NoSuchProviderException, SignatureException, KeyStoreException, UnrecoverableKeyException
    {
        // http://www.mayrhofer.eu.org/create-x509-certs-in-java
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024, new SecureRandom());
        KeyPair keypair = keyGen.generateKeyPair();
        PrivateKey privKey = keypair.getPrivate();
        PublicKey pubKey = keypair.getPublic();

        // http://stackoverflow.com/questions/1615871/creating-an-x509-certificate-in-java-without-bouncycastle
        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + 7  * 86400000l);
        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name("cn=test");

        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
        info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
        info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
        info.set(X509CertInfo.KEY, new CertificateX509Key(pubKey));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

        // Sign the cert to identify the algorithm that's used.
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privKey, "SHA1withRSA");

        // Update the algorith, and resign.
        algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        cert = new X509CertImpl(info);
        cert.sign(privKey, "SHA1withRSA");
        Certificate[] certs = new X509CertImpl[1];
        certs[0] = cert;

        // http://www.coderanch.com/t/133048/Security/programmatically-create-keystore-import-certificate
        KeyStore ks = emptyKeystore();
        ks.setKeyEntry("sslkey", privKey, PASS.toCharArray(), certs);

        printKeys(ks);

        return ks;
    }


    /**
     * Print out all keys aliases in a KeyStore according
     * to the algorithm of SunX509KeyManagerImpl.
     *
     * @param ks keystore to list
     */
    private static void printKeys(KeyStore ks)
            throws KeyStoreException, NoSuchAlgorithmException,
            UnrecoverableKeyException
    {
        for (Enumeration<String> aliases = ks.aliases(); aliases.hasMoreElements(); )
        {
            String alias = aliases.nextElement();
            try
            {
            	System.out.println("printKeys: try " + alias);
            	if (!ks.isKeyEntry(alias))
            	{
            		System.out.println("printKeys " + alias + " is not a KeyEntry.");
            		continue;
            	}
            	Key key = ks.getKey(alias, PASS.toCharArray());
            	if (key instanceof PrivateKey == false)
            	{
            		System.out.println("printKeys  " + alias + " is not a Instance of PrivateKey but " + key.getClass().getName());
            		continue;
            	}

            	Certificate[]  certs = ks.getCertificateChain(alias);
            	if ((certs == null) || (certs.length == 0) || !(certs[0] instanceof X509Certificate))
            	{
            		System.out.println("printKeys  " + alias + " has no X509Certificate(chain)");
            		continue;
            	}

            	if (!(certs instanceof X509Certificate[]))
            	{
            		Certificate[] tmp = new X509Certificate[certs.length];
            		System.arraycopy(certs, 0, tmp, 0, certs.length);
            		certs = tmp;
            	}
            	System.out.println("printKeys certificate " + alias + " " + certs);
            }
            catch (Exception ex)
            {
            	System.out.println("printKeys  " + alias + " ignored because of exception " + ex);
            }
        }
    }

    /** Create empty in-memory JKS implementation. */
    private static KeyStore emptyKeystore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null,null);
        return ks;
    }

}
