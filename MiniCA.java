import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.io.FileWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class MiniCA {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // =====================================================
    // 1) Ustvari RSA ključ
    // =====================================================
    public static KeyPair generateRSAKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    // =====================================================
    // 2) create_ca  (self-signed CA certifikat)
    // =====================================================
    public static X509Certificate createCA(String commonName, KeyPair keyPair) throws Exception {

        X500Name subject = new X500Name("CN=" + commonName);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 3650L * 24 * 60 * 60 * 1000); // 10 let

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());

        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(
                        subject,     // subject
                        serial,
                        notBefore,
                        notAfter,
                        subject,     // issuer = subject (self-signed)
                        keyPair.getPublic()
                );

        // Označimo da je to CA certifikat
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    // =====================================================
    // 3) create_csr
    // =====================================================
    public static PKCS10CertificationRequest createCSR(String commonName, String email, KeyPair keyPair) throws Exception {

        X500Name subject = new X500Name("CN=" + commonName);

        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

        // Če je email podan → SubjectAlternativeName
        if (email != null) {
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            GeneralNames gns = new GeneralNames(
                    new GeneralName(GeneralName.rfc822Name, email)
            );
            extGen.addExtension(Extension.subjectAlternativeName, false, gns);

            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    extGen.generate());
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());

        return builder.build(signer);
    }

    // =====================================================
    // 4) issue_certificate
    // =====================================================
    public static X509Certificate issueCertificate(
            X509Certificate caCert,
            PrivateKey caPrivateKey,
            PKCS10CertificationRequest csr
    ) throws Exception {

        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        JcaPKCS10CertificationRequest req = new JcaPKCS10CertificationRequest(csr);
        X500Name subject = req.getSubject();
        PublicKey publicKey = req.getPublicKey();

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000); // 1 leto

        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(
                        issuer,
                        serial,
                        notBefore,
                        notAfter,
                        subject,
                        publicKey
                );

        // Kopiramo vse razširitve iz CSR
        Attribute[] attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attrs.length > 0) {
            Extensions extensions = Extensions.getInstance(attrs[0].getAttrValues().getObjectAt(0));
            for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
                Extension ext = extensions.getExtension(oid);
                builder.addExtension(oid, ext.isCritical(), ext.getParsedValue());
            }
        }

        ContentSigner signer =
                new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey);

        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(signer));
    }

    // =====================================================
    // 5) save_private_key
    // =====================================================
    public static void savePrivateKey(PrivateKey key, String filename) throws Exception {
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(filename))) {
            writer.writeObject(key);
        }
    }

    // =====================================================
    // 6) save_certificate
    // =====================================================
    public static void saveCertificate(X509Certificate cert, String filename) throws Exception {
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(filename))) {
            writer.writeObject(cert);
        }
    }

    // =====================================================
    // 7) MAIN – celoten potek kot v Pythonu
    // =====================================================
    public static void main(String[] args) throws Exception {

        // 1) CA
        KeyPair caKeys = generateRSAKey();
        X509Certificate caCert = createCA("My Root CA", caKeys);

        // 2) Uporabnik
        KeyPair userKeys = generateRSAKey();
        PKCS10CertificationRequest csr = createCSR("Alice", "alice@email.com", userKeys);

        // 3) CA izda certifikat
        X509Certificate userCert = issueCertificate(caCert, caKeys.getPrivate(), csr);

        // 4) Shrani v PEM
        savePrivateKey(caKeys.getPrivate(), "ca.key");
        saveCertificate(caCert, "ca.pem");

        savePrivateKey(userKeys.getPrivate(), "alice.key");
        saveCertificate(userCert, "alice.pem");

        System.out.println("CA in certifikat ustvarjena.");
    }
}
