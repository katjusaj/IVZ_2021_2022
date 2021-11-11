package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using a
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                for(int i=0; i<5; i++) {
                    // pošiljanje
                    // payload
                    System.out.println(i+1);
                    final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    // encrypt
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
//                    System.out.printf("CT:  %s%n", Agent.hex(ct));
                    // IV
                    final byte[] iv = alice.getIV();
                    //                System.out.printf("IV:  %s%n", Agent.hex(iv));
                    System.out.println("[Message from Alice] "+ text);
                    send("bob", ct);
                    send("bob", iv);

                    //prejemanje
                    final byte[] messageBob = receive("bob");
                    final byte[] ivBob = receive("bob");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, ivBob);
                    alice.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = alice.doFinal(messageBob);
                    System.out.println("[Received message from Bob] "+ new String(pt2));
//                    System.out.printf("PT:  %s%n", Agent.hex(pt2));
//                    System.out.printf("MSG: %s%n", new String(pt2, StandardCharsets.UTF_8));

                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 5; i++) {
                    // prejemanje
                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final byte[] messageAlice = receive("alice");
                    final byte[] ivAlice = receive("alice");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, ivAlice);

                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(messageAlice);
//                    System.out.printf("PT:  %s%n", Agent.hex(pt2));
//                    System.out.printf("MSG: %s%n", new String(pt2, StandardCharsets.UTF_8));
                    System.out.println("[Received message from Alice] "+ new String(pt2));

                    // pošiljanje
                    // payload
                    System.out.println(i+1);
                    final String text = "Kiss. Bob.";
                    bob.init(Cipher.ENCRYPT_MODE, key, specs);
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    // encrypt
                    final byte[] ct = bob.doFinal(pt);
//                    System.out.printf("CT:  %s%n", Agent.hex(ct));
                    // IV
                    final byte[] iv = bob.getIV();
                    //                System.out.printf("IV:  %s%n", Agent.hex(iv));
                    System.out.println("[Message from Bob] "+ text);
                    send("alice", ct);
                    send("alice", iv);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
