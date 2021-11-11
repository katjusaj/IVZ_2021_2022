package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;
import fri.isp.Pair;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static fri.isp.Agent.hex;

public class M1 {
    public static Key createAESKey(PublicKey pk, PrivateKey sk) throws Exception {
        // 1.1 create AES key with ECDH
        final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
        dh.init(sk);
        dh.doPhase(pk, true);

        final byte[] sharedSecret = dh.generateSecret();
        final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
 
        return aesKey;
    }

    public static Pair<byte[], byte[]> encrypt(String message, Key key) throws Exception {
        // 1.2 takes a message and a key and return ct and iv
        final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, key);

        final byte[] ct = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));
        final byte[] iv = aes.getIV();

        Pair<byte[], byte[]> pair = new Pair<>(ct, iv);

        return pair;
    }


    public static String decrypt(byte[] ct, byte[] iv, Key key) throws Exception {
        // 1.3 takes ct, iv and key and returns pt as string
        final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        final byte[] pt = aes.doFinal(ct);

        print("I got: %s", new String(pt, StandardCharsets.UTF_8))

        return new String(pt, StandardCharsets.UTF_8);
    }

    public static Key createMACKey(Key aesKey) throws Exception {
        // 2.1 takes AES key and returns HMAC-SHA256 key
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey.getEncoded(), "HmacSHA256");
        return secretKeySpec;
    }

    public static byte[] mac(PublicKey pk, byte[] ct, byte[] iv, Key key) throws Exception {
        // 2.2 computes mac from pk, ct, iv and key
        final Mac compMac = Mac.getInstance("HmacSHA256");
        Key MACkey = createMACKey(key);
        compMac.init(MACkey);
        byte[] pt = (decrypt(ct, iv, key)).getBytes();
        final byte[] tag = compMac.doFinal(pt);

        return tag;
    }

    public static boolean verifyMac(PublicKey pk, byte[] ct, byte[] iv, Key key, byte[] tag) throws Exception {
        byte[] tag1 = mac(pk, ct, iv, key);
        byte[] tag2 = tag;

        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }

    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // 1.4 message exchange, Alice starts, each sends 11 messages: initial ECDH value and 10 two-part messages 
        // send("bob", "hello".getBytes()); 
        // send("bob", "world".getBytes());
        
        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                //ECDH value send and received
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);
                final KeyPair keyPair = kpg.generateKeyPair();
                send("bob", keyPair.getPublic().getEncoded());

                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("bob"));
                final ECPublicKey bobPK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
                
                Key aesKeyAlice = createAESKey(bobPK, 0, 16, "AES");

                for(int i=0; i<10; i++) {
                    String message = "This is alice "+i+".";
                    Pair<byte[], byte[]> messagePair = encrypt(message, aesKeyAlice);

                    send("bob", messagePair.first); 
                    send("bob", messagePair.second);
                }

                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                //ECDH value received and send
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("alice"));
                final ECPublicKey alicePK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
                final ECParameterSpec dhParamSpec = alicePK.getParams();

                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(dhParamSpec);
                final KeyPair keyPair = kpg.generateKeyPair();
                send("alice", keyPair.getPublic().getEncoded());

                Key aesKeyBob = createAESKey(alicePK, 0, 16, "AES");

                for(int i=0; i<10; i++) {
                    byte[] messageAlice = receive("alice");
                    byte[] ivAlice = receive("alice");

                    String message = "This is bob "+i+".";
                    Pair<byte[], byte[]> messagePair = encrypt(message, aesKeyBob);

                    send("alice", messagePair.first); 
                    send("alice", messagePair.second);

                }
        

            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    /**
     * A useful utility function that converts bytes to an ECPublicKey instance.
     *
     * @param bytes to convert
     * @return ECPublicKey instance
     * @throws Exception if given bytes do not represent a valid key
     */
    private static ECPublicKey bytesToPK(byte[] bytes) throws Exception {
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(bytes));
    }
}
