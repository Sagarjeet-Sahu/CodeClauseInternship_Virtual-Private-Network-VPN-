/**
 * Port firstReceiveServering client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * See original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */


import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class ForwardClient
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;

    private static SecretKey secretKey;
    private static IvParameterSpec IV;

    private static void doHandshake() throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        /* Connect to forward server server */
        System.out.println("Connect to " + arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        /* This is where the handshake should take place */

        System.out.println("client hello");

        HandshakeMessage firstHello = new HandshakeMessage();
        firstHello.putParameter("MessageType", "ClientHello");
        firstHello.putParameter("Certificate", encodeCertificate(arguments.get("usercert")));
        firstHello.send(socket);

        System.out.println("hello from server");

        HandshakeMessage firstReceiveServer = new HandshakeMessage();
        firstReceiveServer.recv(socket);
        if (firstReceiveServer.getParameter("MessageType").equals("ServerHello")) {
            X509Certificate userCert = decodeCertificate(firstReceiveServer.getParameter("Certificate"));
            try {
                userCert.verify(HandshakeCrypto.getPublicKeyFromCertFile(arguments.get("cacert")));
            } catch (Exception e) {
                e.printStackTrace();
            }

            System.out.println("verify pass, forward message");

            HandshakeMessage ToServer = new HandshakeMessage();
            ToServer.putParameter("MessageType", "Forward");
            ToServer.putParameter("TargetHost", arguments.get("targethost"));
            ToServer.putParameter("TargetPort", arguments.get("targetport"));
            ToServer.send(socket);

            //session from server

            HandshakeMessage fromServer = new HandshakeMessage();
            fromServer.recv(socket);
            if (fromServer.getParameter("MessageType").equals("Session")) {
                byte[] keyDecode = Base64.getDecoder().decode(fromServer.getParameter("SessionKey"));
                byte[] keyDecrypt  = HandshakeCrypto.decrypt(keyDecode, HandshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key")));
                secretKey = new SecretKeySpec(keyDecrypt, 0, keyDecrypt.length, "AES");
                byte[] IVDecode = Base64.getDecoder().decode(fromServer.getParameter("SessionIV"));
                byte[] IVDecrypt = HandshakeCrypto.decrypt(IVDecode, HandshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key")));
                IV = new IvParameterSpec(IVDecrypt);
                serverHost = fromServer.getParameter("ServerHost");
                serverPort = Integer.parseInt(fromServer.getParameter("ServerPort"));

                socket.close();

                /*
                 * Fake the handshake result with static parameters.
                 */

                /* This is to where the ForwardClient should connect.
                 * The ForwardServer creates a socket
                 * dynamically and communicates the address (hostname and port number)
                 * to ForwardClient during the handshake (ServerHost, ServerPort parameters).
                 * Here, we use a static address instead.
                 */

            }
            else System.out.println("handeshakesessionwrong");
        }else System.out.println("handshakehellowrong");
    }

    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }
        
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static public void startForwardClient() throws IOException, CertificateException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;
        
        /* Create a new socket. This is to where the user should connect.
         * ForwardClient sets up port forwarding between this socket
         * and the ServerHost/ServerPort learned from the handshake */
        listensocket = new ServerSocket();
        /* Let the system pick a port number */
        listensocket.bind(null); 
        /* Tell the user, so the user knows where to connect */ 
        tellUser(listensocket);

        Socket clientSocket = listensocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        log("Accepted client from " + clientHostPort);
            
        forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort, secretKey,IV);
        forwardThread.start();
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");        
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        startForwardClient();
    }
    public static String encodeCertificate(String name) throws CertificateException, FileNotFoundException {
        FileInputStream file = new FileInputStream(name);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) f.generateCertificate(file);
        return Base64.getEncoder().encodeToString(certificate.getEncoded());

    }

    public static X509Certificate decodeCertificate(String cert) throws CertificateException {
        byte[] a = Base64.getDecoder().decode(cert);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(a);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
        return certificate;
    }


}
