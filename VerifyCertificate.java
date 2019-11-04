import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class VerifyCertificate {
    private X509Certificate CA;
    private X509Certificate USER;

    public VerifyCertificate(FileInputStream ca, FileInputStream user) throws Exception {
        BufferedInputStream bis1 = new BufferedInputStream(ca);
        BufferedInputStream bis2 = new BufferedInputStream(user);
        CertificateFactory cf1 = CertificateFactory.getInstance("X.509");
        CertificateFactory cf2 = CertificateFactory.getInstance("X.509");
        while (bis1.available() > 0) {
            this.CA = (X509Certificate) cf1.generateCertificate(bis1);
        }
        while (bis2.available() > 0) {
            this.USER = (X509Certificate) cf2.generateCertificate(bis2);
        }
        System.out.println(CA.getSubjectDN().getName());
        System.out.println(USER.getSubjectDN().getName());
        try{
            CA.checkValidity();
            CA.verify(CA.getPublicKey());
            USER.checkValidity();
            USER.verify(CA.getPublicKey());
            System.out.println("PASS");
        }catch (Exception ignore) {
            System.out.println("Fault.");
            try {
                CA.checkValidity();
            } catch (Exception ignored) {
                System.out.println("CA certificate is currently invalid.");
            }
            try {
                CA.verify(CA.getPublicKey());
            } catch (Exception ignored) {
                System.out.println("CA certificate was not signed using the private key that corresponds to the specified public key.");
            }
            try {
                USER.checkValidity();
            } catch (Exception ignored) {
                System.out.println("User certificate is currently invalid.");
            }
            try {
                USER.verify(CA.getPublicKey());
            } catch (Exception ignored) {
                System.out.println("User certificate was not signed using the private key that corresponds to the specified public key.");
            }
        }

    }
    public static void main(String arg[]) throws Exception {
        String file1,file2;
        file1=arg[0];
        file2=arg[1];
        FileInputStream ca = new FileInputStream(file1);

        FileInputStream user = new FileInputStream(file2);
        new VerifyCertificate(ca,user);
    }
}
