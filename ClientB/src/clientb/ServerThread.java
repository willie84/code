

package clientb;

import java.security.SignatureException;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.OpenOption;
import java.nio.file.Files;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.Writer;
import java.io.PrintWriter;
import java.io.FileWriter;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openpgp.PGPException;

public class ServerThread extends Thread
{
    ClientB cb;
    ObjectInputStream oin;
    ObjectOutputStream out;
    PGPKeys PGPkeys;
    //PGPKeys PGPprivkeys;
    String fileToBeEnc;
    ServerSocket serverSocket;
    Socket socket;
    private boolean asciiArmored=true;
    private boolean integrityCheck=true;
    
    
    public ServerThread(ClientB cb) {
        this.cb = cb;
        
        try{
            // create server object(client can act as a server) with specific port number
            serverSocket = new ServerSocket(Settings.port);
            //socket = new Socket(Settings.ip_Address,Settings.port);
            //client acting as a server
            cb.jtaCertificate.append("Awaiting for client A \n");
            start();
            
        }catch(Exception e){
            e.printStackTrace();
        }
    }
    
    public void sendFileMessage(String fileToBeEnc) throws FileNotFoundException, PGPException {
        try {
            FileOutputStream fos = new FileOutputStream("EncryptedMessage.txt");
            PGPEncryption.EncrypFile(fileToBeEnc, fos, PGPkeys.getReceiverPub(), PGPkeys.getSenderPub(), PGPkeys.getSenderPriv(), asciiArmored, integrityCheck);
            File myFile = new File("EncryptedMessage.txt");
            byte[] content = Files.readAllBytes(myFile.toPath());
            out.writeObject(content);
            myFile.delete();
        } catch (IOException ex) {
            Logger.getLogger(ServerThread.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void sendMessage( String msg) {
        try {
            FileWriter write = new FileWriter("input.txt");
            try (PrintWriter print_line = new PrintWriter(write)) {
                print_line.printf("%s" + "%n" , msg);
            }
            
            FileOutputStream fos = new FileOutputStream("EncryptedMessage.txt");
            PGPEncryption.EncrypFile("input.txt",fos,PGPkeys.getReceiverPub(),PGPkeys.getSenderPub(),PGPkeys.getSenderPriv(),asciiArmored,integrityCheck);
            
            File file = new File("input.txt");
            file.delete();
            File myFile = new File ("EncryptedMessage.txt");
            byte[] content = Files.readAllBytes(myFile.toPath());
            out.writeObject(content);
            myFile.delete();
        }
        catch (IOException | PGPException e) {
            e.printStackTrace();
        }
    }
    
    @Override
    public void run() {
        boolean sendcert = true;
        while (true) {
            try {
                this.socket = this.serverSocket.accept();
                this.cb.jtaCertificate.append("Client B connected to Client A \n");
                //input and output readers;
                InputStream is = socket.getInputStream();
                OutputStream os = socket.getOutputStream();
                if (sendcert) {
                    File myFile = new File("clientB.p12");
                    out = new ObjectOutputStream(os);
                    byte[] content = Files.readAllBytes(myFile.toPath());
                    out.writeObject(content);
                    cb.jtaCertificate.append("Sending clientB certificate \n");
                    cb.jtaCertificate.append("Sending complete \n");
                    sendcert = false;
                }
                cb.jtaCertificate.append("Awaiting ClientA's certificate \n");
                File myFile = new File("clientA.p12");
                oin = new ObjectInputStream(is);
                byte[] content = (byte[]) oin.readObject();
                Files.write(myFile.toPath(), content, new OpenOption[0]);
                cb.jtaCertificate.append("receiving clientA's certificate \n");
                cb.jtaCertificate.append("receiving complete \n");
                cb.jtaCertificate.append("verifying clientA's certificate using CA's public key \n");
                if (LoadAndVerifyRecCert()) {
                    cb.jtaCertificate.append("verification successful \n");
                    PGPkeys = new PGPKeys();
                    openReader(is, os);

                } else {
                    cb.jtaCertificate.append("verification failed \n");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
    }
    
    private void openReader(final InputStream is, final OutputStream os) {
        try {
            oin = new ObjectInputStream(is);
            out = new ObjectOutputStream(os);
            MsgRecThread mrt = new MsgRecThread(this.cb,oin,out);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private boolean LoadAndVerifyRecCert() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, NoSuchProviderException, SignatureException {
        final KeyStore bK = KeyStore.getInstance("PKCS12");
        bK.load(new FileInputStream(new File("CAPubKey.p12")), new char[0]);
        final X509Certificate Cert = (X509Certificate)bK.getCertificate("CAPubKey");
        if (Cert == null) {
            throw new RuntimeException("Got null cert from keystore!");
        }
        final KeyStore aKs = KeyStore.getInstance("PKCS12");
        aKs.load(new FileInputStream(new File("clientA.p12")), new char[0]);
        final X509Certificate aCert = (X509Certificate)aKs.getCertificate("Client A");
        if (aCert == null) {
            throw new RuntimeException("Got null cert from keystore!");
        }
        aCert.verify(Cert.getPublicKey());
        return true;
    }


    
    public class MsgRecThread extends Thread
{
    ClientB cb;
    ObjectInputStream oin;
    ObjectOutputStream out;
    
    public MsgRecThread(final ClientB cb, final ObjectInputStream oin, final ObjectOutputStream out) {
        this.cb = cb;
        this.oin = oin;
        this.out = out;
        this.start();
    }
    
    @Override
    public void run() {
        while (true) {
            try {
                
                    File myFile = new File("ecryptedreceieved.txt");
                    byte[] content = (byte[])this.oin.readObject();
                    Files.write(myFile.toPath(), content);
                    try (final Scanner myReader = new Scanner(myFile)) {
                        while (myReader.hasNextLine()) {
                            String data = myReader.nextLine();
                            this.cb.jtaRecEnc.append("\n");
                            this.cb.jtaRecEnc.append(data);
                        }
                        myReader.close();
                    }
                    catch (Exception e) {
                        e.printStackTrace();
                    }               
            }
            catch (Exception e2) {
                e2.printStackTrace();
                continue;
            }
        }
    }
}
}
