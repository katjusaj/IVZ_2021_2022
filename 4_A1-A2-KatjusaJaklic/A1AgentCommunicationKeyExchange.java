package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

/*
 * Implement a key exchange between Alice and Bob using public-key encryption.
 * Once the shared secret is established, send an encrypted message from Alice to Bob using
 * AES in GCM.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // generate keypair for alice
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                final KeyPair keyPairAlice = kpg.generateKeyPair();

                // send public key to bob
                send("bob", keyPairAlice.getPublic().getEncoded());
                print("Alice's contribution: A = g^a = %s",
                        hex(keyPairAlice.getPublic().getEncoded()));

                // receive and decrypt shared secret
                byte[] receivedCipherSecret = receive("bob");
                final Cipher decrypt = Cipher.getInstance("RSA/ECB/OAEPPadding");
                decrypt.init(Cipher.DECRYPT_MODE, keyPairAlice.getPrivate());
                final byte[] receivedSecret = decrypt.doFinal(receivedCipherSecret);
                print("Alice decrypted shared secret: "+ hex(receivedSecret));

                //send an encrypted message from Alice to Bob using AES in GCM
                final SecretKeySpec aesKey = new SecretKeySpec(receivedSecret, 0, 16, "AES");
                final String message = "Hi Bob, this is Alice.";
                print("Message from Alice: "+ message);
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] ct = aes.doFinal(pt);
                final byte[] iv = aes.getIV();
                send("bob", ct);
                send("bob", iv);

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // receive public key from alice
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("alice"));
                final RSAPublicKey alicePK = (RSAPublicKey) KeyFactory.getInstance("RSA")
                        .generatePublic(keySpec);
                print("Bob received Alice's contribution: A = g^a = %s",
                        hex(alicePK.getEncoded()));

                // shared secret - 16 bytes česarkoli
                // generate a shared AES key
//                final byte[] sharedSecret = dh.generateSecret();
//                print("Shared secret: g^ab = B^a = %s", hex(sharedSecret));
                SecureRandom rnd = new SecureRandom();
                byte[] sharedSecret = new byte[16];
                rnd.nextBytes(sharedSecret);
                print("Shared secret: g^ab = B^a = %s", hex(sharedSecret));

                final Cipher encrypt = Cipher.getInstance("RSA/ECB/OAEPPadding");
                encrypt.init(Cipher.ENCRYPT_MODE, alicePK);
                print("Encrypted shared secret: %s,", hex(encrypt.doFinal(sharedSecret)));
                send("alice", encrypt.doFinal(sharedSecret));

                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");

                // receive message from alice
                final byte[] ct = receive("alice");
                final byte[] iv = receive("alice");
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                final byte[] pt = aes.doFinal(ct);
                print("PT: " + pt);
                final String message = new String(pt, StandardCharsets.UTF_8);
                print("Message: " +  message);



            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}