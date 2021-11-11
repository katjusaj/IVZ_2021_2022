package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();
        final String signingAlgorithm = "SHA256withECDSA";
        final String keyAlgorithm = "EC";

        // Create key pairs
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm);
        final KeyPair kpAlice = kpg.generateKeyPair();
        final KeyPair kpBob = kpg.generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // create a message
                final String message = "Sign this message.";
                System.out.println("Message from Alice: "+message);

                //sign a message
                final Signature signer = Signature.getInstance(signingAlgorithm);
                signer.initSign(kpAlice.getPrivate());
                //load a message into the signature object and sign it
                signer.update(message.getBytes(StandardCharsets.UTF_8));
                final byte[] signature = signer.sign();
                System.out.println("Signature: " + Agent.hex(signature));

                // and send the message, signature pair to bob
                for(int i=0; i<10; i++) {
                    send("bob", message.getBytes());
                    send("bob", signature);
                }
                // receive the message signarure pair, verify the signature
                // repeat 10 times
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // repeat 10 times
                for(int i=0; i<10; i++) {
                    final byte[] receivedMessage = receive("alice");
                    final byte[] receivedSignature = receive("alice");
                    System.out.println("Bob received a message: " + hex(receivedMessage));
                    System.out.println("Bob received Alice's siganture: " + Agent.hex(receivedSignature));

                    // verify
                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(kpAlice.getPublic());

                    verifier.update(receivedMessage);

                    if (verifier.verify(receivedSignature))
                        System.out.println("Valid signature.");
                    else
                        System.err.println("Invalid signature.");

                }

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}