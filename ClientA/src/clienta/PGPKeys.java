
package clienta;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Date;
import java.util.Iterator;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/**
 *
 * @author Gerald Joshua
 */
public class PGPKeys {
    
    private PGPPublicKey senderPub;
    private PGPPublicKey receiverPub;
    private PGPPrivateKey senderPriv;
    
    
    public PGPKeys() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, PGPException, NoSuchProviderException, UnrecoverableKeyException, InvalidKeySpecException {
        receiverPubKey();
        SenderpublicKey();
        findSecretKey();
        
        
    
    }

    public PGPPublicKey getSenderPub() {
        return senderPub;
    }

    public void setSenderPub(PGPPublicKey senderPub) {
        this.senderPub = senderPub;
    }

    public PGPPublicKey getReceiverPub() {
        return receiverPub;
    }

    public void setReceiverPub(PGPPublicKey receiverPub) {
        this.receiverPub = receiverPub;
    }

    public PGPPrivateKey getSenderPriv() {
        return senderPriv;
    }

    public void setSenderPriv(PGPPrivateKey senderPriv) {
        this.senderPriv = senderPriv;
    }
    
    private void findSecretKey()
        throws IOException, PGPException, NoSuchProviderException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, InvalidKeySpecException
    {
        KeyStore bKs = KeyStore.getInstance("PKCS12");
        bKs.load(new FileInputStream(new File("PrivatekeyA.p12")),"client".toCharArray());
        
        Key key = bKs.getKey("PrivateKey", "client".toCharArray());
        if (key == null) {
            throw new RuntimeException("Got null key from keystore!");

        }
        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) key;
        RSAPrivateCrtKeyParameters PrivateKeyA = new RSAPrivateCrtKeyParameters(privKey.getModulus(), privKey.getPublicExponent(), privKey.getPrivateExponent(), privKey.getPrimeP(), privKey.getPrimeQ(), privKey.getPrimeExponentP(), privKey.getPrimeExponentQ(), privKey.getCrtCoefficient());
        PrivateKey PrivKeyA = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(PrivateKeyA.getModulus(), PrivateKeyA.getPublicExponent(),PrivateKeyA.getExponent(), PrivateKeyA.getP(), PrivateKeyA.getQ(),PrivateKeyA.getDP(), PrivateKeyA.getDQ(), PrivateKeyA.getQInv()));
        
        PGPPrivateKey Priv = new JcaPGPKeyConverter().setProvider("BC").getPGPPrivateKey(getSenderPub(), PrivKeyA);
        setSenderPriv(Priv);
        
         
    }
    
    private void SenderpublicKey() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, PGPException {
        KeyStore bKs = KeyStore.getInstance("PKCS12");
        bKs.load(new FileInputStream(new File("clientA.p12")), new char[0]);
	X509Certificate aCert = (X509Certificate) bKs.getCertificate("Client A");
        if (aCert == null) {
            throw new RuntimeException("Got null cert from keystore!");
        }
        PGPPublicKey key = new JcaPGPKeyConverter().setProvider("BC").getPGPPublicKey(PGPPublicKey.RSA_GENERAL, aCert.getPublicKey(), new Date());
        
        setSenderPub(key);    
    }
    
    private void receiverPubKey() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, PGPException {
        KeyStore K = KeyStore.getInstance("PKCS12");
        K.load(new FileInputStream(new File("clientB.p12")),new char[0]);
	X509Certificate bCert = (X509Certificate) K.getCertificate("Client B");
        if (bCert == null) {
            throw new RuntimeException("Got null cert from keystore!");
        }
        PGPPublicKey key = new JcaPGPKeyConverter().setProvider("BC").getPGPPublicKey(PGPPublicKey.RSA_GENERAL, bCert.getPublicKey(), new Date());
        setReceiverPub(key);
    }
    
    public static PGPPublicKey readPublicKey(String filePath) throws IOException, PGPException {
        FileInputStream in = new FileInputStream(filePath);
       PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());

        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();

                if (key.isEncryptionKey())
                {
                    return key;
                    
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }
    
    public static PGPPrivateKey readsecretKey(String filePath) throws IOException, PGPException {
       FileInputStream in = new FileInputStream(filePath);
       PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());

        Iterator keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext())
            {
                PGPSecretKey key = (PGPSecretKey)keyIter.next();
                
                if (key.isSigningKey())
                {
                    return key.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("client".toCharArray()));
//                    Iterator userIdIter = key.getUserIDs();
//                    while(userIdIter.hasNext()){
//                        String userId = (String)userIdIter.next();
//                        if (userId.equals("client A"))
//                            return key.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("client".toCharArray()));
//                    }
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring."); 
    }
    
    
    
}
