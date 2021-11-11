package isp.secrecy;

import fri.isp.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Arrays;

/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of th last three bytes,
 * have been set to 0.
 * <p>
 * The length of DES key is 8 bytes.
 * <p>
 * To manually specify a key, use the class {@link javax.crypto.spec.SecretKeySpec})
 */
public class A4ExhaustiveSearch {
    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        // TODO
        // set a poorly chosen key - all bytes except the last three are 0 (00000---)
        byte[] key_byte = new byte[8];
        for(int i=0; i<5; i++) {
            key_byte[i] = 0;
        }
//        for(int i=5; i<8; i++) {
//            key_byte[i] = (byte)((i*7)-20); // da dobim 3 random številke: 15, 22, 29
//        }
        key_byte[5] = 14;
        key_byte[6] = 45;
        key_byte[7] = 3;
        final Key key = new SecretKeySpec(key_byte, "DES");

        // encrypt message
        final byte[] pt = message.getBytes(); //pretvorba v byte
        final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, key); // z encrypt s keyom
        final byte[] cipherText = encrypt.doFinal(pt); //izhod je byte array
        final byte[] iv = encrypt.getIV();
        System.out.println("[MESSAGE SENT] " + message);
        System.out.println("[KEY] " + Arrays.toString(key_byte));
//        System.out.println("[MESSAGE IN BYTES] " + Arrays.toString(pt));
        System.out.println("[CIPHER TEXT] " + Arrays.toString(cipherText));

        //brute force key search
        byte[] find_key = bruteForceKey(cipherText, message);

    }

    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        // TODO
        // what i know as an attacker: message, DES, key is 00000---
        // if i know only the last 3 numbers are not 0, i need to check for those 3 all the possible numbers from
        // 11111111: -128 - 127
        byte[] new_key_byte = new byte[8];
        for(int i=0; i<5; i++) {
            new_key_byte[i] = 0;
        }
        int j = 5;
        int k = 6;
        int l = 7;
        for(int i=-128; i<128; i++) {
            new_key_byte[j] = (byte)i;

                for(int ii=-128; ii<128; ii++){
                    new_key_byte[k] = (byte)ii;

                    for(int iii=-128; iii<128; iii++){
                        new_key_byte[l] = (byte)iii;

                        final Key key = new SecretKeySpec(new_key_byte, "DES");
                        final byte[] pt = message.getBytes(); //pretvorba v byte
                        final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
                        encrypt.init(Cipher.ENCRYPT_MODE, key); // z encrypt s keyom
                        final byte[] cipherText = encrypt.doFinal(pt); //izhod je byte array

                        if(Agent.hex(cipherText).equals(Agent.hex(ct))) {
                            System.out.println("BRUTE FORCE ATTACK FOUND THE KEY: " + Arrays.toString(new_key_byte));
                            return new_key_byte;
                        }

                    }
                }
        }

        return null;
    }
}
