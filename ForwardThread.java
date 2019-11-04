/**
 * ForwardThread handles the TCP forwarding between a socket input stream (source)
 * and a socket output stream (destination). It reads the input stream and forwards
 * everything to the output stream. If some of the streams fails, the forwarding
 * is stopped and the parent thread is notified to close all its connections.
 */

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ForwardThread extends Thread
{
private static final int READ_BUFFER_SIZE = 8192;
private SecretKey secretKey;
private IvParameterSpec IV;
private int a;
private int b;
private Cipher cipher;
 
    InputStream mInputStream = null;
    OutputStream mOutputStream = null;
 
    ForwardServerClientThread mParent = null;
 
    /**
     * Creates a new traffic forward thread specifying its input stream,
     * output stream and parent thread
     */
    public ForwardThread(ForwardServerClientThread aParent, InputStream aInputStream, OutputStream aOutputStream,int a, int b, SecretKey secretKey, IvParameterSpec IV)
    {
        mInputStream = aInputStream;
        mOutputStream = aOutputStream;
        mParent = aParent;
        this.a = a;
        this.b = b;
        this.secretKey = secretKey;
        this.IV = IV;

    }
 
    /**
     * Runs the thread. Until it is possible, reads the input stream and puts read
     * data in the output stream. If reading can not be done (due to exception or
     * when the stream is at his end) or writing is failed, exits the thread.
     */
    public void run() {
        byte[] buffer = new byte[READ_BUFFER_SIZE];
        if ((a == 0 && b == 0) || (a == 1 && b == 1)) {
            try {
                while (true) {
                    mOutputStream = StreamEncrypt(mOutputStream, secretKey, IV);
                    int bytesRead = mInputStream.read(buffer);
                    if (bytesRead == -1)
                        break; // End of stream is reached --> exit the thread
                    mOutputStream.write(buffer, 0, bytesRead);
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            }
        } else {
            try {
                while (true) {
                    mInputStream = StreamDecrypt(mInputStream, secretKey, IV);
                    int bytesRead = mInputStream.read(buffer);
                    if (bytesRead == -1)
                        break; // End of stream is reached --> exit the thread
                    mOutputStream.write(buffer, 0, bytesRead);
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            }
        }
        mParent.connectionBroken();
    }

    CipherOutputStream StreamEncrypt(OutputStream output, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        CipherOutputStream openCipherInputStream = new CipherOutputStream(output, cipher);
        return openCipherInputStream;
    }


    CipherInputStream StreamDecrypt(InputStream input, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        CipherInputStream openCipherInputStream = new CipherInputStream(input, cipher);
        return openCipherInputStream;
    }
}
