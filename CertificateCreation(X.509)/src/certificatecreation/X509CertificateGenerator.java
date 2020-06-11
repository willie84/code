
package certificatecreation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Date;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


/**
 *
 * @author Gerald Joshua
 * Creating client A and B certificate and storing Private and public keys in  PKCS files ( needs more cleaning up) 
 */
public class X509CertificateGenerator {
    /** This holds the certificate of the CA used to sign the new certificate. */
    private X509Certificate caCert;
    /** This holds the private key of the CA used to sign the new certificate.*/
    private RSAPrivateCrtKeyParameters caPrivateKey;
    
    public X509CertificateGenerator(String caFile, String caPassword, String caAlias)throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException {	
		
	//logger.info("Loading CA certificate and private key from file '" + caFile + "', using alias '" + caAlias + "' with "
        ///		+ (this.useBCAPI ? "Bouncycastle lightweight API" : "JCE API"));
        //loading CA privateKey and Certificate
        KeyStore caKs = KeyStore.getInstance("PKCS12");
        caKs.load(new FileInputStream(new File("selfsigned.jks")), caPassword.toCharArray());
                //String caAlias = "tomcat";
        
        //load the key entry from the keystore
        Key key = caKs.getKey(caAlias, caPassword.toCharArray());
        if (key == null) {
            throw new RuntimeException("Got null key from keystore!");

        }
        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) key;
        caPrivateKey = new RSAPrivateCrtKeyParameters(privKey.getModulus(), privKey.getPublicExponent(), privKey.getPrivateExponent(), privKey.getPrimeP(), privKey.getPrimeQ(), privKey.getPrimeExponentP(), privKey.getPrimeExponentQ(), privKey.getCrtCoefficient());

        // get the certificate
        caCert = (X509Certificate) caKs.getCertificate(caAlias);
        if (caCert == null) {
            throw new RuntimeException("Got null cert from keystore!");
        }
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load (null, null);
        store.setCertificateEntry("CAPubKey", caCert);
        FileOutputStream fOut1 = new FileOutputStream("CAPubKey.p12");
        store.store(fOut1, new char[0]);
        //logger.debug("Successfully loaded CA key and certificate. CA DN is '" + caCert.getSubjectDN().getName() + "'");
        caCert.verify(caCert.getPublicKey());
        //logger.debug("Successfully verified CA certificate with its own public key.");
    }
    
    @SuppressWarnings("empty-statement")
    public boolean createCertificate(String dn, int validityDays, String exportFile, String exportPassword) throws NoSuchAlgorithmException, CertificateEncodingException, IOException, InvalidKeySpecException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, KeyStoreException, OperatorCreationException, UnrecoverableKeyException {
        // creating public and private key of client A certificate
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom sr = new SecureRandom();;
        keyGen.initialize(1024,sr);
        KeyPair keypair = keyGen.genKeyPair();
        PrivateKey privKey = keypair.getPrivate();
        PublicKey pubKey = keypair.getPublic();
        

        //
        // subjects name table.
        //
        X500NameBuilder subjectBuilder = new X500NameBuilder();

        subjectBuilder.addRDN(BCStyle.C, "SA");
        subjectBuilder.addRDN(BCStyle.O, "Crypto");
        subjectBuilder.addRDN(BCStyle.L, "CapeTown");
        subjectBuilder.addRDN(BCStyle.CN, "Client B");
        
        //
        // create the certificate - version 3
        //
        X509v3CertificateBuilder v3Bldr = new JcaX509v3CertificateBuilder(caCert, BigInteger.valueOf(3),new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),subjectBuilder.build(), pubKey);
        
        
        //
        // extensions
        //
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        v3Bldr.addExtension(Extension.subjectKeyIdentifier,false,extUtils.createSubjectKeyIdentifier(pubKey));

        v3Bldr.addExtension(Extension.authorityKeyIdentifier,false,extUtils.createAuthorityKeyIdentifier(caCert));

        //v3Bldr.addExtension(Extension.basicConstraints,true,new BasicConstraints(0));

        PrivateKey caPrivKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(caPrivateKey.getModulus(), caPrivateKey.getPublicExponent(),caPrivateKey.getExponent(), caPrivateKey.getP(), caPrivateKey.getQ(),caPrivateKey.getDP(), caPrivateKey.getDQ(), caPrivateKey.getQInv()));
        
        X509CertificateHolder certHldr = v3Bldr.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider("BC").build(caPrivKey));

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHldr);
        
        cert.checkValidity(new Date());
        cert.verify(caCert.getPublicKey());

        PKCS12BagAttributeCarrier   bagAttr = (PKCS12BagAttributeCarrier)cert;
        
        //
        // this is also optional - in the sense that if you leave this
        // out the keystore will add it automatically, note though that
        // for the browser to recognise the associated private key this
        // you should at least use the pkcs_9_localKeyId OID and set it
        // to the same as you do for the private key's localKeyId.
        //
        bagAttr.setBagAttribute(
            PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
            new DERBMPString("Client's B Key"));
        bagAttr.setBagAttribute(
            PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
            extUtils.createSubjectKeyIdentifier(pubKey));

        
        KeyStore store = KeyStore.getInstance("PKCS12");
        KeyStore kstore = KeyStore.getInstance("PKCS12");
        store.load (null, null);
        kstore.load(null,null);
        X509Certificate[] chain = new X509Certificate[2];
        // first the client, then the CA certificate
        chain [0] = cert ;
        chain [1] = caCert ;
        store.setKeyEntry ("PrivateKey", privKey, exportPassword.toCharArray(), chain);
        kstore.setCertificateEntry("Client B", cert);
        FileOutputStream fOut = new FileOutputStream(exportFile);
        FileOutputStream fOut1 = new FileOutputStream("PrivatekeyB.p12");
        kstore.store(fOut, new char[0]);
        store.store (fOut1, exportPassword.toCharArray());
;	
        return true;
        
}
    
    public static void main(String[] args) throws Exception {
        System.out.println(new X509CertificateGenerator("selfsigned.jks", "computerengineering", "tomcat").createCertificate("Client B", 365, "clientB.p12", "client"));
    }

    
}
