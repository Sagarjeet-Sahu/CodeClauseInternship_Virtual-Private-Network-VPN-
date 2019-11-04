/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;


    private ServerSocket handshakeSocket;
    
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;

    private SecretKey secretKey;
    private IvParameterSpec IV;
    
    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws UnknownHostException, IOException, Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* This is where the handshake should take place */

        System.out.println("hello from client");

        HandshakeMessage firstReceiveClient = new HandshakeMessage();
        firstReceiveClient.recv(clientSocket);
        if (firstReceiveClient.getParameter("MessageType").equals("ClientHello")) {
            X509Certificate userCert = decodeCertificate(firstReceiveClient.getParameter("Certificate"));
            try {
                userCert.verify(HandshakeCrypto.getPublicKeyFromCertFile(arguments.get("cacert")));
            } catch (Exception e) {
                e.printStackTrace();
            }

            System.out.println("verify pass, hello send");

            HandshakeMessage secondHello = new HandshakeMessage();
            secondHello.putParameter("MessageType", "ServerHello");
            secondHello.putParameter("Certificate", encodeCertificate(arguments.get("usercert")));
            secondHello.send(clientSocket);


            System.out.println("forward from client");

            HandshakeMessage fromClient = new HandshakeMessage();
            fromClient.recv(clientSocket);
            if (fromClient.getParameter("MessageType").equals("Forward")) {
                targetHost = fromClient.getParameter("TargetHost");
                targetPort = Integer.parseInt(fromClient.getParameter("TargetPort"));

                System.out.println("receive forward, start session");

                HandshakeMessage toClient = new HandshakeMessage();
                toClient.putParameter("MessageType", "Session");
                SessionEncrypter secretKey = new SessionEncrypter(128);
                this.secretKey = secretKey.getKey().getSecretKey();
                String IV = secretKey.encodeIV();
                this.IV = new IvParameterSpec(Base64.getDecoder().decode(IV));
                byte[] encryptedSessionKey = HandshakeCrypto.encrypt(Base64.getDecoder().decode(secretKey.encodeKey()), userCert.getPublicKey());
                toClient.putParameter("SessionKey", Base64.getEncoder().encodeToString(encryptedSessionKey));
                byte[] encryptedIV = HandshakeCrypto.encrypt(Base64.getDecoder().decode(IV), userCert.getPublicKey());
                toClient.putParameter("SessionIV", Base64.getEncoder().encodeToString(encryptedIV));

                toClient.putParameter("ServerHost", Handshake.serverHost);
                toClient.putParameter("ServerPort", Integer.toString(Handshake.serverPort));
                toClient.send(clientSocket);

                listenSocket = new ServerSocket();
                listenSocket.bind(new InetSocketAddress(Handshake.serverHost, Handshake.serverPort));

            }
        }
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
        throws Exception
    {
 
        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
            throw new IOException("Unable to bind to port " + port + ": " + ioe);
        }

        log("Nakov Forward Server started on TCP port " + port);
 
        // Accept client connections and process them until stopped
        while(true) {
            ForwardServerClientThread forwardThread;
            
            doHandshake();

            forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort,this.secretKey,this.IV);
            forwardThread.start();
        }
    }
 
    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
        throws Exception
    {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);
        
        ForwardServer srv = new ForwardServer();
        srv.startForwardServer();
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
