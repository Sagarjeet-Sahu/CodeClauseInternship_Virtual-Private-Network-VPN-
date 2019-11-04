// @ Author: Xinxing Guo 931201-9756
// @ Project: KTH IK2206 Internet Security and Privacy VPN Project
// @ Time: 5-December-2018
// @ Name: Task4 HandshakeCrypto
/** ---------------------------------------------------------------------*/

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
//
public class HandshakeCrypto {

    //Encryption
    public static byte[] encrypt(byte[] plaintext, Key key)  throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] textEncrypted = cipher.doFinal(plaintext);
        return textEncrypted;
    }

    //Decryption
    public static byte[] decrypt(byte[] ciphertext, Key key)  throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] textDecrypted = cipher.doFinal(ciphertext);
        return textDecrypted;
    }

    //Extract a public key from a certificate file
    public static PublicKey getPublicKeyFromCertFile(String certfile) throws IOException, CertificateException{
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(certfile);
        X509Certificate cert = (X509Certificate)certificateFactory.generateCertificate(fis);
        PublicKey pubkey = cert.getPublicKey();
        return pubkey;

    }

    //extract a private key from a key file
    /** --Juli and Berk helped with this part*/
    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Path path = Paths.get(keyfile);
        byte[] privKeyByteArray = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);

    }
}


