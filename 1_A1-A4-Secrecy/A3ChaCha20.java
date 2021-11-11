package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                final int counter = 0;
                final byte[] nonce = new byte[12];

                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Recall, ChaCha2 requires that you specify the nonce and the counter explicitly.
                 */

                for(int i=0; i<10; i++) {
                    //pošiljanje 1
                    System.out.println(i+1);
                    System.out.println("[SENDING MESSAGE FROM ALICE] " + message);
                    final byte[] pt = message.getBytes(); //pretvorba v byte
//                    System.out.println("[PT] " + Agent.hex(pt)); // v standarden output
                    final Cipher encrypt = Cipher.getInstance("ChaCha20");
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter)); // z encrypt s keyom
                    final byte[] cipherText = encrypt.doFinal(pt); //izhod je byte array
                    final byte[] iv = encrypt.getIV();
                    send("bob", cipherText);
                    send("bob", iv);
//                    System.out.println("[CT] " + Agent.hex(cipherText));

                    //prejemanje 2
                    final Cipher decrypt = Cipher.getInstance("ChaCha20");
                    final byte[] receivedMessage = receive("bob");
                    final byte[] ivR = receive("bob");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
                    final byte[] dt = decrypt.doFinal(receivedMessage);
//                    System.out.println("[PT] " + Agent.hex(dt));
                    System.out.println("[RECEIVED MESSAGE FROM BOB] " + new String(dt));

                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final int counter = 0;
                final byte[] nonce = new byte[12];

                for(int i=0; i<10; i++) {
                    // prejemanje 2
                    final Cipher decrypt = Cipher.getInstance("ChaCha20");
                    final byte[] receivedMessage = receive("alice");
                    final byte[] iv = receive("alice");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
                    final byte[] dt = decrypt.doFinal(receivedMessage);
//                    System.out.println("[PT] " + Agent.hex(dt));
                    System.out.println("[RECEIVED MESSAGE FROM ALICE] " + new String(dt));

                    //pošiljanje 1
                    final String message = "Thanks. Love, Bob.";
                    System.out.println("[SENDING MESSAGE FROM BOB] " + message);
                    final byte[] pt = message.getBytes(); //pretvorba v byte
//                    System.out.println("[PT] " + Agent.hex(pt)); // v standarden output
                    final Cipher encrypt = Cipher.getInstance("ChaCha20");
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter)); // z encrypt s keyom
                    final byte[] cipherText = encrypt.doFinal(pt); //izhod je byte array
                    final byte[] ivS = encrypt.getIV();
                    send("alice", cipherText);
                    send("alice", ivS);
//                    System.out.println("[CT] " + Agent.hex(cipherText));
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
