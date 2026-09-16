package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

/**
 * Service for generating and managing cryptographic keys inside a Hardware Security Module
 * (HSM) via the PKCS#11 provider interface. Conforms to FR-06.1 through FR-06.4.
 */
@Service
public class HSMKeyService {

    private static final Logger log = LoggerFactory.getLogger(HSMKeyService.class);

    public static final String HSM_PREFIX = "hsm://";

    private final Provider pkcs11Provider;

    @org.springframework.beans.factory.annotation.Value("${pki.hsm.pin:4321}")
    private String userPin = "4321";

    @org.springframework.beans.factory.annotation.Autowired
    public HSMKeyService(@org.springframework.beans.factory.annotation.Autowired(required = false) Provider pkcs11Provider) {
        this.pkcs11Provider = pkcs11Provider;
    }

    public boolean isHsmAvailable() {
        return pkcs11Provider != null;
    }

    public Provider getProvider() {
        return pkcs11Provider;
    }

    public boolean isHsmKey(String privateKeyPem) {
        return isHsmReference(privateKeyPem);
    }

    public String getHsmAlias(String privateKeyPem) {
        return extractAlias(privateKeyPem);
    }

    public PrivateKey getPrivateKeyFromHSM(String alias) throws Exception {
        return getPrivateKey(alias);
    }

    public PublicKey getPublicKeyFromHSM(String alias) throws Exception {
        return getPublicKey(alias);
    }

    public KeyPair generateRsaKeyPairInHSM(String alias, int keySize) throws Exception {
        if (pkcs11Provider == null) {
            throw new IllegalStateException("SoftHSM PKCS#11 provider is not initialized.");
        }
        if (keySize != 2048 && keySize != 3072 && keySize != 4096) {
            throw new IllegalArgumentException("Unsupported RSA key size: " + keySize + ". Must be 2048, 3072, or 4096.");
        }

        loadKeyStore();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", pkcs11Provider);
        keyGen.initialize(keySize, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        persistKeyPairInHSM(alias, keyPair, "SHA256withRSA");

        log.info("Generated HSM-backed RSA-{} KeyPair with alias: {}", keySize, alias);
        return keyPair;
    }

    /**
     * Generates an EC KeyPair directly inside the HSM and stores it under the
     * given alias in the PKCS#11 KeyStore.
     *
     * @param alias     Unique alias for the key entry
     * @param curveName Curve name (P-256, P-384, or P-521)
     * @return The generated KeyPair (private key is an opaque HSM handle)
     */
    public KeyPair generateEcKeyPairInHSM(String alias, String curveName) throws Exception {
        if (pkcs11Provider == null) {
            throw new IllegalStateException("SoftHSM PKCS#11 provider is not initialized.");
        }
        String standardName = resolveEcCurveName(curveName);

        loadKeyStore();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", pkcs11Provider);
        keyGen.initialize(new ECGenParameterSpec(standardName), new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        persistKeyPairInHSM(alias, keyPair, "SHA256withECDSA");

        log.info("Generated HSM-backed EC ({}) KeyPair with alias: {}", curveName, alias);
        return keyPair;
    }

    /**
     * Generates a KeyPair in the HSM based on algorithm type and size/curve.
     *
     * @param alias          Unique alias for the key entry
     * @param keyType        "RSA", "EC", or "ECDSA"
     * @param keySizeOrCurve RSA key size or EC curve identifier (256, 384, 521)
     * @return The generated KeyPair
     */
    public KeyPair generateCAKeyPairInHSM(String alias, String keyType, int keySizeOrCurve) throws Exception {
        if ("EC".equalsIgnoreCase(keyType) || "ECDSA".equalsIgnoreCase(keyType)) {
            String curve = keySizeOrCurve == 384 ? "P-384" : (keySizeOrCurve == 521 ? "P-521" : "P-256");
            return generateEcKeyPairInHSM(alias, curve);
        } else {
            return generateRsaKeyPairInHSM(alias, keySizeOrCurve > 0 ? keySizeOrCurve : 3072);
        }
    }

    // -----------------------------------------------------------------------
    // Key Retrieval
    // -----------------------------------------------------------------------

    /**
     * Retrieves a PrivateKey handle from the HSM KeyStore by alias.
     * The returned PrivateKey is an opaque reference – its getEncoded() returns null.
     */
    public PrivateKey getPrivateKey(String alias) throws Exception {
        KeyStore ks = loadKeyStore();
        Key key = ks.getKey(alias, userPin.toCharArray());
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        }
        throw new KeyStoreException("No private key found in HSM for alias: " + alias);
    }

    /**
     * Retrieves a PublicKey from the HSM KeyStore by extracting it from
     * the certificate stored alongside the private key.
     */
    public PublicKey getPublicKey(String alias) throws Exception {
        KeyStore ks = loadKeyStore();
        java.security.cert.Certificate cert = ks.getCertificate(alias);
        if (cert != null) {
            return cert.getPublicKey();
        }
        throw new KeyStoreException("No certificate/public key found in HSM for alias: " + alias);
    }

    /**
     * Checks whether an alias exists in the HSM KeyStore.
     */
    public boolean aliasExists(String alias) throws Exception {
        KeyStore ks = loadKeyStore();
        return ks.containsAlias(alias);
    }

    /**
     * Stores a signed X509Certificate chain in the HSM KeyStore, replacing
     * the temporary self-signed certificate that was created during key generation.
     */
    public void storeCertificateChain(String alias, X509Certificate[] chain) throws Exception {
        KeyStore ks = loadKeyStore();
        Key key = ks.getKey(alias, userPin.toCharArray());
        if (key instanceof PrivateKey) {
            ks.setKeyEntry(alias, key, userPin.toCharArray(),
                    chain != null ? chain : new java.security.cert.Certificate[0]);
            log.info("Updated certificate chain in HSM for alias: {}", alias);
        } else {
            throw new KeyStoreException("Cannot store certificate chain – no private key for alias: " + alias);
        }
    }

    // -----------------------------------------------------------------------
    // HSM Reference Helpers
    // -----------------------------------------------------------------------

    /**
     * Returns true if the given PEM string is actually an HSM key reference
     * (format: "hsm://&lt;alias&gt;").
     */
    public static boolean isHsmReference(String privateKeyPem) {
        return privateKeyPem != null && privateKeyPem.startsWith(HSM_PREFIX);
    }

    /**
     * Extracts the key alias from an HSM reference string.
     */
    public static String extractAlias(String hsmReference) {
        if (!isHsmReference(hsmReference)) {
            throw new IllegalArgumentException("Not an HSM reference: " + hsmReference);
        }
        return hsmReference.substring(HSM_PREFIX.length()).trim();
    }

    /**
     * Builds an HSM reference string for the given alias.
     */
    public static String buildHsmReference(String alias) {
        return HSM_PREFIX + alias;
    }

    // -----------------------------------------------------------------------
    // Internal Helpers
    // -----------------------------------------------------------------------

    private KeyStore cachedKeyStore;

    private synchronized KeyStore loadKeyStore() throws Exception {
        if (pkcs11Provider == null) {
            throw new IllegalStateException("SoftHSM PKCS#11 provider is not initialized or available.");
        }
        if (cachedKeyStore == null) {
            cachedKeyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
            cachedKeyStore.load(null, userPin != null ? userPin.toCharArray() : new char[0]);
        } else {
            try {
                cachedKeyStore.load(null, userPin != null ? userPin.toCharArray() : new char[0]);
            } catch (Exception ignored) {}
        }
        return cachedKeyStore;
    }

    /**
     * Persists a KeyPair into the PKCS#11 KeyStore under the given alias by
     * creating a temporary self-signed certificate. This is required because
     * PKCS#11 KeyStore.setKeyEntry needs a certificate chain.
     */
    private void persistKeyPairInHSM(String alias, KeyPair keyPair, String sigAlg) throws Exception {
        // Build a temporary self-signed certificate so setKeyEntry succeeds
        X500Name dn = new X500Name("CN=HSM-Key-" + alias);
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now);
        Date notAfter = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 year
        BigInteger serial = BigInteger.valueOf(now);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dn, serial, notBefore, notAfter, dn, keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(pkcs11Provider)
                .build(keyPair.getPrivate());

        X509Certificate tempCert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(signer));

        KeyStore ks = loadKeyStore();
        ks.setKeyEntry(alias, keyPair.getPrivate(), userPin.toCharArray(),
                new X509Certificate[]{tempCert});
    }

    private String resolveEcCurveName(String curveName) {
        if (curveName.equalsIgnoreCase("P-256")) return "secp256r1";
        if (curveName.equalsIgnoreCase("P-384")) return "secp384r1";
        if (curveName.equalsIgnoreCase("P-521")) return "secp521r1";
        return curveName;
    }
}