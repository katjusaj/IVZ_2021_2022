package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class HandsOnAssignment {

    //Alice->Bob (confidentiality & integrity) AES/GCM will be used
    public static String[] METHOD1 = {"AES", "AES/GCM/NoPadding"};

    //Bob->Alice (confidentiality, integrity & non-repudiation AES/CTR for encryption & SHA256withRSA for signing will be used
    public static String[] METHOD2 = {"AES", "AES/CTR/NoPadding"};

    //BOB signature method
    public static String[] METHOD3 = {"RSA", "SHA256withRSA"};

    public static void main(String[] args) throws Exception {

        //pre-shared keys
        final Key alice2bobKey = KeyGenerator.getInstance(METHOD1[0]).generateKey();

        final Key bob2AliceKey = KeyGenerator.getInstance(METHOD2[0]).generateKey();

        //bob's signature key pair
        final KeyPair keyPairBob = KeyPairGenerator.getInstance(METHOD3[0]).generateKeyPair();
        final PublicKey pkBob = keyPairBob.getPublic();
        final PrivateKey skBob = keyPairBob.getPrivate();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                //send data 2 bob
                final byte[] dataForBob = "The package is in room 102.".getBytes(StandardCharsets.UTF_8);

                final Cipher alice = Cipher.getInstance(METHOD1[1]);
                alice.init(Cipher.ENCRYPT_MODE, alice2bobKey);
                final byte[] ctForBob = alice.doFinal(dataForBob);
                final byte[] ivForBob = alice.getIV();

                send("bob", ctForBob);
                send("bob", ivForBob);

                //receive data from bob
                final byte[] ctFromBob = receive("bob");
                final byte[] ivFromBob = receive("bob");
                final byte[] signatureFromBob = receive("bob");

                //first check the signature
                final Signature verifier = Signature.getInstance(METHOD3[1]);
                verifier.initVerify(pkBob);
                verifier.update(ctFromBob);
                if(verifier.verify(signatureFromBob)) print("Valid signature");
                else print("Invalid signature");

                //finally decrypt the message
                final Cipher alice2 = Cipher.getInstance(METHOD2[1]);
                final IvParameterSpec ivParameterSpec = new IvParameterSpec(ivFromBob);
                alice2.init(Cipher.DECRYPT_MODE, bob2AliceKey, ivParameterSpec);

                final byte[] ptFromBob = alice2.doFinal(ctFromBob);
                print("Bob's response is: %s", new String(ptFromBob, StandardCharsets.UTF_8));
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                //receive message from alice
                final byte[] ctFromAlice = receive("alice");
                final byte[] ivFromAlice = receive("alice");

                final Cipher bob = Cipher.getInstance(METHOD1[1]);
                final GCMParameterSpec  gcmParameterSpec = new GCMParameterSpec(128, ivFromAlice);

                bob.init(Cipher.DECRYPT_MODE, alice2bobKey, gcmParameterSpec);

                final byte[] ptFromAlice = bob.doFinal(ctFromAlice);
                print(new String(ptFromAlice, StandardCharsets.UTF_8));

                //send response 2 alice
                final byte[] dataForAlice = "Acknowledged".getBytes(StandardCharsets.UTF_8);

                final Cipher bob2 = Cipher.getInstance(METHOD2[1]);
                bob2.init(Cipher.ENCRYPT_MODE, bob2AliceKey);
                final byte[] ctForAlice = bob2.doFinal(dataForAlice);
                final byte[] ivForAlice = bob2.getIV();

                //sign the data
                final Signature signer = Signature.getInstance(METHOD3[1]);
                signer.initSign(skBob);
                signer.update(ctForAlice);
                final byte[] signature = signer.sign();

                send("alice", ctForAlice);
                send("alice", ivForAlice);
                send("alice", signature);

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
