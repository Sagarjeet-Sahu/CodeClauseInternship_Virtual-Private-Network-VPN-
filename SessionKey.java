// @ Author: Xinxing Guo 931201-9756
// @ Project: KTH IK2206 Internet Security and Privacy VPN Project
// @ Time: 18-November-2018
// @ Name: Task1 Session Keys
/* This task is about creating encryption keys, and converting the keys to a
 * portable format that can, for instance, be communicated over the network.
 */
/** ---------------------------------------------------------------------**/
//package task1_sessionkey;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class SessionKey {
    //static SessionKey key;
    private SecretKey secretKey;

    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keylength);
        secretKey = keyGenerator.generateKey();
        //System.out.println(secretKey);
    }

    public SessionKey(String encodedkey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedkey);
        secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        //System.out.println(encodedkey);
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public String encodeKey () {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    //First way to check the quality of Keys Manually input the length of AES
//	public static void main(String[] args) throws NoSuchAlgorithmException {
//		System.out.println("Please input the length of Key:");
//		Scanner input = new Scanner(System.in);
//		int length = input.nextInt();
//		System.out.println("Create Key1, length:"+length);
//		SessionKey key1 = new SessionKey(length);
//		System.out.println("Create Key2 from encoded Key1");
//		SessionKey key2 = new SessionKey(key1.encodeKey());
//		System.out.println("Compare the two keys to check if they are equal.");
//		System.out.println("The result is:");
//		if (key1.getSecretKey().equals(key2.getSecretKey())) {
//			System.out.println("Pass");
//		}
//		else {
//			System.out.println("Fail");
//		}
//		
// Second way to check the quality of Keys Automatically set length of AES
    public static void main(String[] args) throws NoSuchAlgorithmException {
        SessionKey key1 = new SessionKey(128);
        SessionKey key2 = new SessionKey(key1.encodeKey());
        if (key1.getSecretKey().equals(key2.getSecretKey())) {
            System.out.println("Pass");
        }
        else {
            System.out.println("Fail");
        }

    }

}
