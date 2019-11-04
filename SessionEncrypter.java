
//import session_keys.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Base64;

/** ---------------------------------------------------------------------**/
public class SessionEncrypter {

    private Cipher cipher;
    private SessionKey key;
    private byte[] IV;

    public SessionEncrypter(Integer keylength) throws Exception {

        cipher = Cipher.getInstance("AES/CTR/NOPadding");
        key = new SessionKey(keylength);
        //Initiate Cipher
        cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey());
        IV = cipher.getIV();

    }

    public String encodeKey() {
        return key.encodeKey();
    }

    public SessionKey getKey() {
        return key;
    }

    public String encodeIV() {
        return Base64.getEncoder().encodeToString(IV);
    }

    public String encrypt_string(String str) throws IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        String outStr = Base64.getEncoder().encodeToString((cipher.doFinal(str.getBytes("UTF-8"))));

        return outStr;
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output) throws Exception {
        return new CipherOutputStream(output, cipher);

    }

}