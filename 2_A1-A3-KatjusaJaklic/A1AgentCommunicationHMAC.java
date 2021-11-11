package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemted with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                for(int i=0; i<5; i++){
                    // pošiljanje
                    final Mac alice = Mac.getInstance("HmacSHA256");
                    alice.init(key);

                    final String text = "I hope you get this message intact. Kisses, Alice.";
                    final byte[] tag1 = alice.doFinal(text.getBytes(StandardCharsets.UTF_8));
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    System.out.println("[Sending message from Alice] "+text);
                    final String messageHmacAsString = Agent.hex(tag1);
//                    System.out.println("HMAC: " + messageHmacAsString);
                    send("bob", pt);
                    send("bob", tag1);

                    //prejemanje in avtentikacija
                    final byte[] text2 = receive("bob");
                    final byte[] tag2 = receive("bob");
                    final byte[] tag12 = alice.doFinal(text2);
                    System.out.println("Alice's authentication: " + verify3(tag2, tag12, key));
                }

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                for(int i=0; i<5; i++) {
                    // preverjanje
                    final Mac bob = Mac.getInstance("HmacSHA256");
                    bob.init(key);
                    final byte[] text = receive("alice");
                    final byte[] tag1 = receive("alice");
                    final byte[] tag2 = bob.doFinal(text);
                    System.out.println("Bob's authentication: " + verify3(tag1, tag2, key));

                    //pošiljanje
                    final String text2 = "Kiss. Bob";
                    final byte[] tag21 = bob.doFinal(text2.getBytes(StandardCharsets.UTF_8));
                    final byte[] pt2 = text2.getBytes(StandardCharsets.UTF_8);
                    System.out.println("[Sending message from Bob] "+text2);
                    final String messageHmacAsString = Agent.hex(tag21);
//                    System.out.println("HMAC: " + messageHmacAsString);
                    send("alice", pt2);
                    send("alice", tag21);

                }

            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    public static boolean verify3(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {

        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }
}
