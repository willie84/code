
package clienta;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

/**
 *
 * @author Gerald Joshua
 */
public class PGPEncryption {


    



    static void EncrypFile(String fileName, OutputStream out, PGPPublicKey receiverPub, PGPPublicKey senderPub, PGPPrivateKey senderPriv, boolean armor, boolean withIntegrityCheck) throws PGPException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        
        File unencryptedFile = new File(fileName);

        if (out == null)
            throw new IllegalArgumentException("outputStream is null");
        if (fileName == null || fileName.isEmpty())
            throw new IllegalArgumentException("Unencrypted filename is missing");
        if (!unencryptedFile.exists())
            throw new IllegalArgumentException("Unencrypted file is missing");

        if (armor) {
            out = new ArmoredOutputStream(out);
        }
 
        //SIGNATURE GENERATION OBJECTS
        
        PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(receiverPub.getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));
        pgpSignatureGenerator.init(PGPSignature.BINARY_DOCUMENT, senderPriv);

        Iterator it = senderPub.getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
//
            signatureSubpacketGenerator.setSignerUserID(false, (String) it.next() );
            pgpSignatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());
        }
        
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));//PGPEncryptedDataGenerator cPk = PGPEncryptedData.CAST5, withIntegrityCheck,new SecureRandom(), "BC");
        //cPk.addMethod(new JcePBEKeyEncryptionMethodGenerator(encKey).setProvider("BC")););
        encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(receiverPub).setProvider("BC"));
        OutputStream encryptedOut = encryptedDataGenerator.open(out, new byte[1 << 16]);
 
        //COMPRESSED GENERATOR OBJECTS            
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

        OutputStream compressedOut = compressedDataGenerator.open(encryptedOut);

        BCPGOutputStream bcpgOutputStream = new BCPGOutputStream(compressedOut);

        pgpSignatureGenerator.generateOnePassVersion(false).encode(bcpgOutputStream);
        
        //LITERAL DATA GENERATOR OBJECTS
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();

        OutputStream literalOut = literalDataGenerator.open(bcpgOutputStream, PGPLiteralData.BINARY, unencryptedFile);
        FileInputStream in = new FileInputStream(unencryptedFile);

        int ch;
        while ((ch = in.read()) > 0) {
            literalOut.write(ch);
            pgpSignatureGenerator.update((byte) ch);
        }

        pgpSignatureGenerator.generate().encode(bcpgOutputStream);
        literalOut.close();
        bcpgOutputStream.close();
        in.close();

        compressedDataGenerator.close();

        encryptedOut.close();
        compressedOut.close();

        if (armor) {
            out.close();
        }
    }

    static void EncrypFile(ClientA aThis, String inputtxt, FileOutputStream fos, PGPPublicKey receiverPub, PGPPublicKey senderPub, PGPPrivateKey senderPriv, boolean asciiArmored, boolean integrityCheck) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    
    
}
