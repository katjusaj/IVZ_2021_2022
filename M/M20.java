package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;
import fri.isp.Pair;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
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

public class M20 {
    public static Key createAESKey(PublicKey pk, PrivateKey sk) throws Exception {
        final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
        dh.init(sk);
        dh.doPhase(pk, true);

        final byte[] sharedSecret = dh.generateSecret();
        System.out.println("Shared secret: %s" + hex(sharedSecret));

        final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
        System.out.println(aesKey);
        return aesKey;
    }

    public static Pair<byte[], byte[]> encrypt(String message, Key key) throws Exception {
        final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");

        encrypt.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = encrypt.getIV();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        encrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] cipherText = encrypt.doFinal(message.getBytes());
        System.out.println("[CT] " + Agent.hex(cipherText));

        Pair<byte[], byte[]> returnPair = new Pair<>(cipherText, iv);
        System.out.println("FIRST: " + Agent.hex(returnPair.first));
        System.out.println("SECOND: " + Agent.hex(returnPair.second));

        return returnPair;
    }

    public static String decrypt(byte[] ct, byte[] iv, Key key) throws Exception {
        final Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        decrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);

        final byte[] dt = decrypt.doFinal(ct);
        System.out.println("[PTr] " + Agent.hex(dt));

        return new String(dt);
    }

    public static Key createMACKey(Key aesKey) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey.getEncoded(), "HmacSHA256");
        return secretKeySpec;
    }

    public static byte[] mac(PublicKey pk, byte[] ct, byte[] iv, Key key) throws Exception {
        byte[] sendValues = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, sendValues, 0, iv.length);
        System.arraycopy(ct, 0, sendValues, iv.length, ct.length);
        System.out.printf("[TAG1+PT]  %s%n", Agent.hex(sendValues));

        Key MACkey = createMACKey(key);
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(MACkey);
        final byte[] tag1 = mac.doFinal(sendValues);

        return tag1;
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

        final String signingAlgorithm = "SHA256withRSA";

        final Signature signer = Signature.getInstance(signingAlgorithm);
        final Signature verifier = Signature.getInstance(signingAlgorithm);


        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                //RSA KEY
                final KeyPairGenerator kpgA = KeyPairGenerator.getInstance("RSA");
                final KeyPair aliceKP = kpgA.generateKeyPair();
                send("bob", aliceKP.getPublic().getEncoded());
                System.out.println("ALI RSA" + aliceKP.getPublic().getEncoded());
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("bob"));
                final RSAPublicKey bobPK = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);

                //INITIAL EC KEY
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);
                KeyPair keyPairAlice = kpg.generateKeyPair();
                send("bob", keyPairAlice.getPublic().getEncoded());
                print("First ECDH: %s", hex(keyPairAlice.getPublic().getEncoded()));
                X509EncodedKeySpec keySpecc = new X509EncodedKeySpec(receive("bob"));
                ECPublicKey bobPKK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpecc);

                //INITIAL AES KEY
                Key alicesAES = createAESKey(bobPKK, keyPairAlice.getPrivate());

                for(int i = 0; i < 1; i++) {
                    //SEND MESSAGE
                    String message = "Alice to Bob: "  + i;
                    Pair<byte[], byte[]> encryptedMessageA = encrypt(message, alicesAES);
                    send("bob", encryptedMessageA.first);
                    send("bob", encryptedMessageA.second);

                    if (i == 0) {
                        //SEND SIGNATURE MESSAGE
                        signer.initSign(aliceKP.getPrivate());
                        signer.update(encryptedMessageA.first);
                        byte[] signature1 = signer.sign();
                        send("bob", signature1);
                    }

                    //RECEIVE BOBS MESSAGE
                    byte[] bobsMessage = receive("bob");
                    byte[] bobsIV = receive("bob");
                    System.out.println("FIRSTr: " + Agent.hex(bobsMessage));
                    System.out.println("SECONDr: " + Agent.hex(bobsIV));

                    if (i == 0) {
                        //CHECK SIGNATURE
                        byte[] messageSig = receive("bob");
                        System.out.println("Signature2: " + Agent.hex(messageSig));
                        verifier.initVerify(bobPK);
                        verifier.update(bobsMessage);
                        if (!(verifier.verify(messageSig)))
                            System.out.println("Invalid signature.");
                        else
                            System.out.println("Valid signature.");
                    }

                    //DECRYPT
                    String answer = decrypt(bobsMessage, bobsIV, alicesAES);
                    System.out.println(answer);

                    //SEND N-TH ECDH KEY
                    keyPairAlice = kpg.generateKeyPair();
                    send("bob", keyPairAlice.getPublic().getEncoded());
                    print("%d ECDH: %s", i, hex(keyPairAlice.getPublic().getEncoded()));
                    keySpecc = new X509EncodedKeySpec(receive("bob"));
                    bobPKK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpecc);

                    //NEW AES KEY
                    alicesAES = createAESKey(bobPKK, keyPairAlice.getPrivate());
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                //RSA KEY
                final KeyPairGenerator kpgB = KeyPairGenerator.getInstance("RSA");
                final KeyPair bobKP = kpgB.generateKeyPair();
                send("alice", bobKP.getPublic().getEncoded());
                System.out.println("BOB RSA" + bobKP.getPublic().getEncoded());
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("alice"));
                final RSAPublicKey bobPK = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);

                //INITIAL EC KEY
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);
                KeyPair keypairBob = kpg.generateKeyPair();
                send("alice", keypairBob.getPublic().getEncoded());
                print("First ECDH: %s", hex(keypairBob.getPublic().getEncoded()));
                X509EncodedKeySpec keySpecc = new X509EncodedKeySpec(receive("alice"));
                ECPublicKey alicePKK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpecc);

                //INITIAL AES KEY
                Key bobsAES = createAESKey(alicePKK, keypairBob.getPrivate());

                for(int i = 0; i < 1; i++) {
                    //SEND MESSAGE
                    String message = "Bob to Alice: " + i;
                    Pair<byte[], byte[]> encryptedMessageA = encrypt(message, bobsAES);
                    send("alice", encryptedMessageA.first);
                    send("alice", encryptedMessageA.second);

                    if (i == 0) {
                        //SEND SIGNATURE MESSAGE
                        signer.initSign(bobKP.getPrivate());
                        signer.update(encryptedMessageA.first);
                        byte[] signature1 = signer.sign();
                        send("alice", signature1);
                    }

                    //RECEIVE FROM ALICE
                    byte[] alicesMessage = receive("alice");
                    byte[] alicesIV = receive("alice");
                    System.out.println("FIRSTr: " + Agent.hex(alicesMessage));
                    System.out.println("SECONDr: " + Agent.hex(alicesIV));

                    if (i == 0) {
                        //CHECK SIGNATURE
                        byte[] messageSig = receive("alice");
                        System.out.println("Signature1: " + Agent.hex(messageSig));
                        verifier.initVerify(bobPK);
                        verifier.update(alicesMessage);
                        if (!(verifier.verify(messageSig)))
                            System.out.println("Invalid signature.");
                        else
                            System.out.println("Valid signature.");
                    }

                    //DECRYPT
                    String answer = decrypt(alicesMessage, alicesIV, bobsAES);
                    System.out.println(answer);


                    //SEND N-TH ECDH KEY
                    keypairBob = kpg.generateKeyPair();
                    send("alice", keypairBob.getPublic().getEncoded());
                    print("%d ECDH: %s", i, hex(keypairBob.getPublic().getEncoded()));
                    keySpecc = new X509EncodedKeySpec(receive("alice"));
                    alicePKK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpecc);

                    //NEW AES KEY
                    bobsAES = createAESKey(alicePKK, keypairBob.getPrivate());
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
