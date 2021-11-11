package isp.rsa;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Assuming Alice and Bob know each other's public key, secure the channel using a
 * RSA. Then exchange ten messages between Alice and Bob.
 *
 * (The remaining assignment(s) can be found in the isp.steganography.ImageSteganography
 * class.)
 */
public class A1AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {
        final String algorithm = "RSA/ECB/OAEPPadding";
        final String message = "Hi Bob, is almost November.";
        final String messageBob = "Hi Alice, I miss you.";

        // Create two public-secret key pairs
        final KeyPair alice_kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bob_kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for(int i=0; i<5; i++) {
                    // pošiljanje
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                    final Cipher rsaEnc = Cipher.getInstance(algorithm);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, bob_kp.getPublic());
                    final byte[] ct = rsaEnc.doFinal(pt);

                    send("bob", ct);

                    // prejemanje
                    final byte[] ct2 = receive("bob");

                    final Cipher rsaDec = Cipher.getInstance(algorithm);
                    rsaDec.init(Cipher.DECRYPT_MODE, alice_kp.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(ct2);
                    final String message2 = new String(decryptedText, StandardCharsets.UTF_8);
                    System.out.println(i+1+" Alice received message: "+message2);
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for(int i=0; i<5; i++) {
                    // pošiljanje
                    final byte[] pt1 = messageBob.getBytes(StandardCharsets.UTF_8);

                    final Cipher rsaEnc = Cipher.getInstance(algorithm);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, alice_kp.getPublic());
                    final byte[] ct1 = rsaEnc.doFinal(pt1);

                    send("alice", ct1);

                    //prejemanje
                    final byte[] ct = receive("alice");

                    final Cipher rsaDec = Cipher.getInstance(algorithm);
                    rsaDec.init(Cipher.DECRYPT_MODE, bob_kp.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(ct);
                    final String message2 = new String(decryptedText, StandardCharsets.UTF_8);
                    System.out.println(i+1+" Bob received message: " + message2);
                }

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
