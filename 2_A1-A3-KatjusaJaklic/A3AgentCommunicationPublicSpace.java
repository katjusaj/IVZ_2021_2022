package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * TASK:
 * We want to send a large chunk of data from Alice to Bob while maintaining its integrity and considering
 * the limitations of communication channels -- we have three such channels:
 * - Alice to Bob: an insecure channel, but has high bandwidth and can thus transfer large files
 * - Alice to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * - Bob to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * <p>
 * The plan is to make use of the public-space technique:
 * - Alice creates the data and computes its digest
 * - Alice sends the data to Bob, and sends the encrypted digest to Public Space
 * - Channel between Alice and Public space is secured with ChaCha20-Poly1305 (Alice and Public space share
 * a ChaCha20 key)
 * - Public space forwards the digest to Bob
 * - The channel between Public Space and Bob is secured but with AES in GCM mode (Bob and Public space share
 * an AES key)
 * - Bob receives the data from Alice and the digest from Public space
 * - Bob computes the digest over the received data and compares it to the received digest
 * <p>
 * Further instructions are given below.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3AgentCommunicationPublicSpace {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // Create a ChaCha20 key that is used by Alice and the public-space
        // Create an AES key that is used by Bob and the public-space
        final Key key1 = KeyGenerator.getInstance("ChaCha20").generateKey();
        final Key key2 = KeyGenerator.getInstance("AES").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // a payload of 200 MB
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);

                // Alice sends the data directly to Bob
                send("bob", data);

                // The channel between Alice and Bob is not secured
                // Alice then computes the digest of the data and sends the digest to public-space
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] digest = digestAlgorithm.digest(data);
                final Cipher encrypt = Cipher.getInstance("ChaCha20-Poly1305");
                final byte[] nonce = new byte[12];
                IvParameterSpec iv = new IvParameterSpec(nonce);
                encrypt.init(Cipher.ENCRYPT_MODE, key1, iv);
                final byte[] cDigest = encrypt.doFinal(digest);

                // The channel between Alice and the public-space is secured with ChaCha20-Poly1305
                // Use the key that you have created above.
                send("public-space", cDigest);
            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {
                // Receive the encrypted digest from Alice and decrypt ChaCha20 and
                // the key that you share with Alice
                final byte[] receivedD = receive("alice");
                final byte[] nonce = new byte[12];
                IvParameterSpec iv2 = new IvParameterSpec(nonce);
                final Cipher decrypt = Cipher.getInstance("ChaCha20-Poly1305");
                decrypt.init(Cipher.DECRYPT_MODE, key1, iv2);
                final byte[] dDigest = decrypt.doFinal(receivedD);

                // Encrypt the digest with AES-GCM and the key that you share with Bob and
                // send the encrypted digest to Bob
                final Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                encrypt.init(Cipher.ENCRYPT_MODE, key2);
                final byte[] cDigest = encrypt.doFinal(dDigest);
                final byte[] iv3 = encrypt.getIV();

                send("bob", cDigest);
                send("bob", iv3);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive the data from Alice and compute the digest over it using SHA-256
                final byte[] receivedData = receive("alice");
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] digestAlice = digestAlgorithm.digest(receivedData);

                // Receive the encrypted digest from the public-space, decrypt it using AES-GCM
                // and the key that Bob shares with the public-space
                final byte[] receivedDigest = receive("public-space");
                final byte[] iv3 = receive("public-space");
                final GCMParameterSpec specs = new GCMParameterSpec(128, iv3);
                final Cipher decryptBob = Cipher.getInstance("AES/GCM/NoPadding");
                decryptBob.init(Cipher.DECRYPT_MODE, key2, specs);
                final byte[] dDigest = decryptBob.doFinal(receivedDigest);

                // Compare the computed digest and the received digest and print the string
                // "data valid" if the verification succeeds, otherwise print "data invalid"
                boolean valid = compare(digestAlice, dDigest);
                if(valid) {
                    System.out.println("data valid");
                }
                else {
                    System.out.println("data invalid");
                }
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }

    public static boolean compare(byte[] d1, byte[] d2) {
        //compare all bytes
        if (d1 == d2)
            return true;
        if (d1 == null || d2 == null)
            return false;

        int length = d1.length;
        if (d2.length != length)
            return false;

        byte result = 0;
        for (int i = 0; i < length; i++) {
            result |= d1[i] ^ d2[i];
        }
        return result == 0;
    }
}
