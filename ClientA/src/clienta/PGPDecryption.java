
package clienta;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;
import javax.swing.JOptionPane;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

/**
 *
 * @author Gerald Joshua
 */
public class PGPDecryption {

    static void decryptFile(ClientA ca, InputStream in, PGPPublicKey senderPub, PGPPrivateKey senderPriv) throws IOException, PGPException {
        
        in = PGPUtil.getDecoderStream(in);
 
        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof  PGPEncryptedDataList) {
            
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }
 
        //
        // find the secret key
        //
        Iterator it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;  
        
        PGPPublicKeyEncryptedData pbe = null;
 
        while (sKey==null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();
            
            sKey = senderPriv;
        }
// 
        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }
 
        JcaPGPObjectFactory plainFact = null;
        InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
        plainFact = new JcaPGPObjectFactory(clear);
 
        Object message = plainFact.nextObject();
        String outputFilename = "DecryptedFile.txt";
        if (message instanceof PGPCompressedData){
                PGPCompressedData cData = (PGPCompressedData)message;

                JcaPGPObjectFactory of = null;

                InputStream compressedStream = new BufferedInputStream(cData.getDataStream());
                of = new JcaPGPObjectFactory(compressedStream);

                message = of.nextObject();

                if (message instanceof PGPOnePassSignatureList){
                    PGPOnePassSignature onePassSignature = ((PGPOnePassSignatureList)message).get(0);

                   
                    //USE THE BELOW TO CHECK FOR A FAILING SIGNATURE VERIFICATION
                    //THE CERTIFICATE MATCHING THE KEY ID MUST BE IN THE PUBLIC KEY RING.
                    //long fakeKeyId = 3008998260528343108L;
                    //PGPPublicKey publicKey = pgpPub.getPublicKey(fakeKeyId);

                    //PGPPublicKey publicKey = pgpPub.getPublicKey(onePassSignature.getKeyID());

                    onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), ca.PGPkeys.getReceiverPub());

                    message = of.nextObject();
                    PGPLiteralData ld = (PGPLiteralData)message;
                    

                    //THE OUTPUT FILENAME WILL BE BASED ON THE INPUT PARAMETER VALUE TO THIS METHOD.
                    //IF YOU WANT TO KEEP THE ORIGINAL FILENAME, UNCOMMENT THE FOLLOWING LINE.
                    /*if (ld.getFileName() != null && !ld.getFileName().isEmpty())
                        outputFilename = ld.getFileName();*/
                    
                    try(OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFilename))){
                        InputStream dIn = ld.getInputStream();

                        int ch;
                        while ((ch = dIn.read()) >= 0){
                            onePassSignature.update(((byte)ch));
                            outputStream.write((byte)ch);
                        }
                        outputStream.close();
                    }

                    PGPSignatureList pgpSignatureList = (PGPSignatureList)of.nextObject();
                    PGPSignature pgpSignature = pgpSignatureList.get(0);

                    if(onePassSignature.verify(pgpSignature)){
                        ca.signaturePast(true);
                        System.out.println("Signature verified");
                    }
                    else{
                        ca.signaturePast(false);
                        System.out.println("Signature verification failed");

                        //YOU MAY OPT TO DELETE THE OUTPUT FILE IN THE EVENT THAT VERIFICATION FAILS.
                        //FILE DELETION HAPPENS FURTHER DOWN IN THIS METHOD
                        //AN ALTERNATIVE IS TO LOG THESE VERIFICATION FAILURE MESSAGES, BUT KEEP THE OUTPUT FILE FOR FURTHER ANALYSIS
                        //deleteOutputFile = true;
                    }

                }
                else if (message instanceof PGPLiteralData)
                {
                    PGPLiteralData ld = (PGPLiteralData)message;

                    writeLiteralData(ld, outputFilename);
                }
            }
            else if (message instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData)message;

                writeLiteralData(ld, outputFilename);
            }
            else if (message instanceof PGPOnePassSignatureList)
            {
                ca.justSignedOrTypeUnknown(true);
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            }
            else
            {
                ca.justSignedOrTypeUnknown(false);
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected())
            {
                if (!pbe.verify())
                {
                    ca.integrityCheck(false);
                    System.err.println("message failed integrity check");

                    //YOU MAY OPT TO DELETE THE OUTPUT FILE IN THE EVENT THAT THE INTEGRITY PROTECTION CHECK FAILS.
                    //FILE DELETION HAPPENS FURTHER DOWN IN THIS METHOD.
                    //AN ALTERNATIVE IS TO LOG THESE VERIFICATION FAILURE MESSAGES, BUT KEEP THE OUTPUT FILE FOR FURTHER ANALYSIS
                    //deleteOutputFile = true;
                }
                else
                {
                    ca.integrityCheck(true);
                    System.err.println("message integrity check passed");
                }
            }
            else
            {
                ca.integrityCheck();
                System.err.println("no message integrity check");
            }
        

        //DELETE THE FILE IN THE EVENT THAT SIGNATURE VERIFICATION OR INTEGRITY PROTECTION CHECK HAS FAILED.
        //FILE DELETION IS SET TO FALSE BY DEFAULT.


    }
    
    private static void writeLiteralData(PGPLiteralData ld, String outputFilename) {
        InputStream unc = ld.getInputStream();
        try {
            OutputStream fOut = new BufferedOutputStream(new FileOutputStream(outputFilename));

            Streams.pipeAll(unc, fOut);

            fOut.close();
        }
        catch(FileNotFoundException ex){
            System.out.println(ex.getMessage());
        }
        catch(IOException ex){
            System.out.println(ex.getMessage());
        }
    }
    
}
