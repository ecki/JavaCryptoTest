/**
 * Package to test some aspects of Java Cryptography API/Extension.
 * <P>
 * {@link net.eckenfels.test.jce.HashOverflowTest} is a Junit test case  based on a bug
 * report (SHA-1 counter overflow in GnuPG/libcrypt) and used to verify the test vectors (for 257GB nul data)
 * with JCE as well as BC. Note: runtime can be up to hours.
 * <P>
 * {@link net.eckenfels.test.jce.JCEProviderInfo} can be used to list the JCE providers and their capabilities in a JRE.
 *
 * @author Bernd Eckenfels
 */
package net.eckenfels.test.jce;
