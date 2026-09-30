package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.stereotype.Service;

import java.io.StringWriter;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

@Service
public class CryptoService {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Generates an RSA KeyPair of size 2048, 3072, or 4096 bits.
     */
    public KeyPair generateRsaKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (keySize != 2048 && keySize != 3072 && keySize != 4096) {
            throw new IllegalArgumentException("Unsupported RSA key size: " + keySize + ". Must be 2048, 3072, or 4096.");
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    /**
     * Generates an EC KeyPair for curve secp256r1, secp384r1, or secp521r1.
     */
    public KeyPair generateEcKeyPair(String curveName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        String standardName = resolveCurveName(curveName);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(new ECGenParameterSpec(standardName));
        return keyGen.generateKeyPair();
    }

    /**
     * Generates an Ed25519 (EdDSA) KeyPair.
     */
    public KeyPair generateEd25519KeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        return keyGen.generateKeyPair();
    }

    /**
     * Generates a PKCS#10 CSR in PEM format.
     */
    public String generateCsr(KeyPair keyPair, String subjectDn) throws Exception {
        return generateCsr(keyPair, subjectDn, null);
    }

    /**
     * Generates a PKCS#10 CSR in PEM format with an optional custom security provider.
     */
    public String generateCsr(KeyPair keyPair, String subjectDn, Provider customProvider) throws Exception {
        String keyAlg = keyPair.getPrivate().getAlgorithm();
        String signatureAlgorithm;
        if ("EC".equalsIgnoreCase(keyAlg) || "ECDSA".equalsIgnoreCase(keyAlg)) {
            signatureAlgorithm = "SHA256withECDSA";
        } else if ("Ed25519".equalsIgnoreCase(keyAlg) || "EdDSA".equalsIgnoreCase(keyAlg)) {
            signatureAlgorithm = "Ed25519";
        } else {
            signatureAlgorithm = "SHA256withRSA";
        }

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                parseX500Name(subjectDn), keyPair.getPublic());

        ContentSigner signer;
        if (customProvider != null) {
            signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(customProvider)
                    .build(keyPair.getPrivate());
        } else {
            String className = keyPair.getPrivate().getClass().getName().toLowerCase();
            if (className.contains("pkcs11") || className.contains("p11")) {
                Provider sunPkcs11 = Security.getProvider("SunPKCS11");
                if (sunPkcs11 != null) {
                    signer = new JcaContentSignerBuilder(signatureAlgorithm)
                            .setProvider(sunPkcs11)
                            .build(keyPair.getPrivate());
                } else {
                    signer = new JcaContentSignerBuilder(signatureAlgorithm)
                            .build(keyPair.getPrivate());
                }
            } else {
                try {
                    signer = new JcaContentSignerBuilder(signatureAlgorithm)
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(keyPair.getPrivate());
                } catch (Exception e) {
                    signer = new JcaContentSignerBuilder(signatureAlgorithm)
                            .build(keyPair.getPrivate());
                }
            }
        }

        PKCS10CertificationRequest csr = p10Builder.build(signer);

        StringWriter sw = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(sw)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
        }
        return sw.toString();
    }

    public static X500Name parseX500Name(String dnStr) {
        if (dnStr == null || dnStr.trim().isEmpty()) {
            return new X500Name("CN=Unknown");
        }
        String cleaned = dnStr.trim();
        while (cleaned.startsWith("CN=CN=") || cleaned.startsWith("cn=cn=") || cleaned.startsWith("CN=cn=") || cleaned.startsWith("cn=CN=")) {
            cleaned = "CN=" + cleaned.substring(6).trim();
        }
        if (!cleaned.toUpperCase().contains("CN=") && !cleaned.toUpperCase().contains("O=")) {
            cleaned = "CN=" + cleaned;
        }
        cleaned = cleaned.replaceAll("[,;\\s]+$", "");
        try {
            return new X500Name(cleaned);
        } catch (Exception e) {
            String safeCn = cleaned.replaceAll("[^a-zA-Z0-9 ._\\-]", " ").trim();
            return new X500Name("CN=" + safeCn);
        }
    }

    private String resolveCurveName(String curveName) {
        if (curveName.equalsIgnoreCase("P-256")) return "secp256r1";
        if (curveName.equalsIgnoreCase("P-384")) return "secp384r1";
        if (curveName.equalsIgnoreCase("P-521")) return "secp521r1";
        return curveName;
    }
}