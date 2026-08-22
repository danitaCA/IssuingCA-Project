package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.CertificateProfileEntity;
import org.insa.pkiissuingca.model.KeyPairEntity;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.CertificateProfileRepository;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.repository.KeyPairRepository;
import org.insa.pkiissuingca.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

@Service
public class CertificateLifecycleService {

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private KeyPairRepository keyPairRepository;

    @Autowired
    private CertificateProfileRepository profileRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private SerializationService serializationService;

    @Autowired
    private CsrService csrService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private CertificateStatusCacheService certificateStatusCacheService;

    @Autowired
    private HSMKeyService hsmKeyService;

    @Value("${pki.ca.base-url:http://localhost:8080}")
    private String baseUrl;

    @Value("${pki.hsm.enabled:true}")
    private boolean hsmEnabled;

    /**
     * Standard-compliant SPKI AuthorityKeyIdentifier generator.
     */
    public AuthorityKeyIdentifier buildAki(PublicKey caPublicKey) throws Exception {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(caPublicKey.getEncoded());
        DigestCalculator sha1Calc = new BcDigestCalculatorProvider()
                .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        return new X509ExtensionUtils(sha1Calc).createAuthorityKeyIdentifier(spki);
    }

    /**
     * Standard-compliant SPKI SubjectKeyIdentifier generator.
     */
    public SubjectKeyIdentifier buildSki(PublicKey publicKey) throws Exception {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        DigestCalculator sha1Calc = new BcDigestCalculatorProvider()
                .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        return new X509ExtensionUtils(sha1Calc).createSubjectKeyIdentifier(spki);
    }

    /**
     * Helper to extract CN from a DN string.
     */
    public String extractCn(String dn) {
        if (dn == null) return "Unknown";
        try {
            X500Name x500Name = new X500Name(dn);
            RDN[] rdns = x500Name.getRDNs(BCStyle.CN);
            if (rdns != null && rdns.length > 0) {
                return IETFUtils.valueToString(rdns[0].getFirst().getValue());
            }
        } catch (Exception ignored) {}
        int idx = dn.indexOf("CN=");
        if (idx != -1) {
            String sub = dn.substring(idx + 3);
            int comma = sub.indexOf(",");
            return comma != -1 ? sub.substring(0, comma).trim() : sub.trim();
        }
        return dn;
    }

    /**
     * Instantiates a self-signed Root CA.
     */
    @Transactional
    public CertificateEntity initRootCa(String subjectDN, String keyType, int keySizeOrCurve, String profileName, String username) throws Exception {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        KeyPair keyPair;
        String algorithm;
        String privateKeyPem;
        String alias = "root-ca-" + System.currentTimeMillis();

        if (hsmEnabled) {
            algorithm = ("EC".equalsIgnoreCase(keyType) || "ECDSA".equalsIgnoreCase(keyType)) ? "EC" : "RSA";
            keyPair = hsmKeyService.generateCAKeyPairInHSM(alias, keyType, keySizeOrCurve);
            privateKeyPem = HSMKeyService.buildHsmReference(alias);
        } else {
            if ("EC".equalsIgnoreCase(keyType) || "ECDSA".equalsIgnoreCase(keyType)) {
                String curve = keySizeOrCurve == 384 ? "secp384r1" : (keySizeOrCurve == 521 ? "secp521r1" : "secp256r1");
                keyPair = cryptoService.generateEcKeyPair(curve);
                algorithm = "EC";
            } else if ("Ed25519".equalsIgnoreCase(keyType)) {
                keyPair = cryptoService.generateEd25519KeyPair();
                algorithm = "Ed25519";
            } else {
                keyPair = cryptoService.generateRsaKeyPair(keySizeOrCurve > 0 ? keySizeOrCurve : 2048);
                algorithm = "RSA";
            }
            privateKeyPem = serializationService.convertToPem(keyPair.getPrivate());
        }

        // Save KeyPair
        KeyPairEntity kpEntity = new KeyPairEntity();
        kpEntity.setAlgorithm(algorithm);
        kpEntity.setKeySize(keySizeOrCurve);
        kpEntity.setPrivateKeyPEM(privateKeyPem);
        kpEntity.setPublicKeyPEM(serializationService.convertToPem(keyPair.getPublic()));
        kpEntity.setCreatedAt(Instant.now());
        kpEntity.setUser(user);
        kpEntity = keyPairRepository.save(kpEntity);

        // Fetch or create profile
        CertificateProfileEntity profile = profileRepository.findByName(profileName)
                .orElseGet(() -> createDefaultProfile(profileName, true, 3650, "SHA256withRSA"));

        // Build self-signed cert
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000 * 60 * 5); // 5 mins ago
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * profile.getValidityDays());
        BigInteger serial = BigInteger.valueOf(System.nanoTime());

        X500Name subject = new X500Name(subjectDN);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic()
        );

        // Extensions
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        int keyUsageFlags = KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature;
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageFlags));
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, buildSki(keyPair.getPublic()));
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, buildAki(keyPair.getPublic()));

        String sigAlg = profile.getSignatureAlgorithm();
        if ("EC".equals(algorithm)) {
            sigAlg = "SHA256withECDSA";
        } else if ("Ed25519".equals(algorithm)) {
            sigAlg = "Ed25519";
        }

        ContentSigner signer;
        if (hsmEnabled) {
            signer = new JcaContentSignerBuilder(sigAlg).setProvider(hsmKeyService.getProvider()).build(keyPair.getPrivate());
        } else {
            signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(keyPair.getPrivate());
        }
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

        if (hsmEnabled) {
            hsmKeyService.storeCertificateChain(alias, new X509Certificate[]{cert});
        }

        CertificateEntity certEntity = new CertificateEntity();
        certEntity.setSerialNumber(serial.toString());
        certEntity.setSubjectDN(subjectDN);
        certEntity.setIssuerDN(subjectDN);
        certEntity.setNotBefore(notBefore.toInstant());
        certEntity.setNotAfter(notAfter.toInstant());
        certEntity.setPublicKeyPEM(kpEntity.getPublicKeyPEM());
        certEntity.setStatus("ISSUED");
        certEntity.setPemContent(serializationService.convertToPem(cert));
        certEntity.setCertificateType("ROOT");
        certEntity.setProfileName(profileName);

        CertificateEntity saved = certificateRepository.save(certEntity);

        auditService.log(username, "INIT_ROOT_CA", "Initialized Root CA with DN: " + subjectDN + ", Serial: " + serial + (hsmEnabled ? " [HSM-Backed]" : ""), "SUCCESS", "127.0.0.1");

        return saved;
    }

    /**
     * Provision an Intermediate CA signed by a Root CA or another parent CA.
     */
    @Transactional
    public CertificateEntity initIntermediateCa(String subjectDN, String parentSerialNumber, String keyType, int keySizeOrCurve, String profileName, String username) throws Exception {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        CertificateEntity parentCertEntity = certificateRepository.findBySerialNumber(parentSerialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Parent CA certificate not found for serial: " + parentSerialNumber));

        if (!"ISSUED".equals(parentCertEntity.getStatus())) {
            throw new IllegalStateException("Parent CA certificate is not active. Status: " + parentCertEntity.getStatus());
        }

        // Generate Intermediate CA KeyPair
        KeyPair keyPair;
        String algorithm;
        String privateKeyPem;
        String alias = "sub-ca-" + System.currentTimeMillis();

        if (hsmEnabled) {
            algorithm = ("EC".equalsIgnoreCase(keyType) || "ECDSA".equalsIgnoreCase(keyType)) ? "EC" : "RSA";
            keyPair = hsmKeyService.generateCAKeyPairInHSM(alias, keyType, keySizeOrCurve);
            privateKeyPem = HSMKeyService.buildHsmReference(alias);
        } else {
            if ("EC".equalsIgnoreCase(keyType) || "ECDSA".equalsIgnoreCase(keyType)) {
                String curve = keySizeOrCurve == 384 ? "secp384r1" : (keySizeOrCurve == 521 ? "secp521r1" : "secp256r1");
                keyPair = cryptoService.generateEcKeyPair(curve);
                algorithm = "EC";
            } else if ("Ed25519".equalsIgnoreCase(keyType)) {
                keyPair = cryptoService.generateEd25519KeyPair();
                algorithm = "Ed25519";
            } else {
                keyPair = cryptoService.generateRsaKeyPair(keySizeOrCurve > 0 ? keySizeOrCurve : 2048);
                algorithm = "RSA";
            }
            privateKeyPem = serializationService.convertToPem(keyPair.getPrivate());
        }

        // Save KeyPair
        KeyPairEntity kpEntity = new KeyPairEntity();
        kpEntity.setAlgorithm(algorithm);
        kpEntity.setKeySize(keySizeOrCurve);
        kpEntity.setPrivateKeyPEM(privateKeyPem);
        kpEntity.setPublicKeyPEM(serializationService.convertToPem(keyPair.getPublic()));
        kpEntity.setCreatedAt(Instant.now());
        kpEntity.setUser(user);
        kpEntity = keyPairRepository.save(kpEntity);

        // Fetch parent CA Private Key & Public Key
        KeyPairEntity parentKeyPair = keyPairRepository.findAll().stream()
                .filter(k -> normalizePem(k.getPublicKeyPEM()).equals(normalizePem(parentCertEntity.getPublicKeyPEM())))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Parent CA private key not found in storage."));

        PrivateKey parentPrivateKey;
        boolean parentInHsm = HSMKeyService.isHsmReference(parentKeyPair.getPrivateKeyPEM());
        if (parentInHsm) {
            String parentAlias = HSMKeyService.extractAlias(parentKeyPair.getPrivateKeyPEM());
            parentPrivateKey = hsmKeyService.getPrivateKey(parentAlias);
        } else {
            parentPrivateKey = serializationService.parsePrivateKeyFromPem(parentKeyPair.getPrivateKeyPEM());
        }
        PublicKey parentPublicKey = serializationService.parsePublicKeyFromPem(parentKeyPair.getPublicKeyPEM());

        // Fetch or create profile
        CertificateProfileEntity profile = profileRepository.findByName(profileName)
                .orElseGet(() -> createDefaultProfile(profileName, true, 1825, "SHA256withRSA"));

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000 * 60 * 5);
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * profile.getValidityDays());
        BigInteger serial = BigInteger.valueOf(System.nanoTime());

        X500Name subject = new X500Name(subjectDN);
        X500Name issuer = new X500Name(parentCertEntity.getSubjectDN());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, keyPair.getPublic()
        );

        // Extensions
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        int keyUsageFlags = KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature;
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageFlags));
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, buildSki(keyPair.getPublic()));
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, buildAki(parentPublicKey));

        String crlUrl = baseUrl + "/api/v1/crl/" + parentCertEntity.getSerialNumber() + "/latest/der";
        GeneralName crlGeneralName = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
        DistributionPointName dpName = new DistributionPointName(new GeneralNames(crlGeneralName));
        CRLDistPoint cdp = new CRLDistPoint(new DistributionPoint[]{ new DistributionPoint(dpName, null, null) });
        certBuilder.addExtension(Extension.cRLDistributionPoints, false, cdp);

        String ocspUrl = baseUrl + "/api/v1/ocsp/" + parentCertEntity.getSerialNumber();
        AccessDescription ocspAccess = new AccessDescription(
                AccessDescription.id_ad_ocsp,
                new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl));
        AuthorityInformationAccess aia = new AuthorityInformationAccess(ocspAccess);
        certBuilder.addExtension(Extension.authorityInfoAccess, false, aia);

        String sigAlg = profile.getSignatureAlgorithm();
        if (parentKeyPair.getAlgorithm().equalsIgnoreCase("EC")) {
            sigAlg = "SHA256withECDSA";
        } else if (parentKeyPair.getAlgorithm().equalsIgnoreCase("Ed25519")) {
            sigAlg = "Ed25519";
        }

        ContentSigner signer;
        if (parentInHsm) {
            signer = new JcaContentSignerBuilder(sigAlg).setProvider(hsmKeyService.getProvider()).build(parentPrivateKey);
        } else {
            signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(parentPrivateKey);
        }
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

        if (hsmEnabled) {
            hsmKeyService.storeCertificateChain(alias, new X509Certificate[]{cert});
        }

        CertificateEntity certEntity = new CertificateEntity();
        certEntity.setSerialNumber(serial.toString());
        certEntity.setSubjectDN(subjectDN);
        certEntity.setIssuerDN(parentCertEntity.getSubjectDN());
        certEntity.setNotBefore(notBefore.toInstant());
        certEntity.setNotAfter(notAfter.toInstant());
        certEntity.setPublicKeyPEM(kpEntity.getPublicKeyPEM());
        certEntity.setStatus("ISSUED");
        certEntity.setPemContent(serializationService.convertToPem(cert));
        certEntity.setCertificateType("INTERMEDIATE");
        certEntity.setProfileName(profileName);

        CertificateEntity saved = certificateRepository.save(certEntity);

        auditService.log(username, "INIT_INTERMEDIATE_CA", "Initialized Intermediate CA: " + subjectDN + " signed by: " + parentCertEntity.getSubjectDN(), "SUCCESS", "127.0.0.1");

        return saved;
    }

    /**
     * Signs an incoming CSR using a specified Sub-CA/Intermediate CA key.
     */
    @Transactional
    public CertificateEntity signCsr(String csrPem, String caSerialNumber, String profileName, String username) throws Exception {
        CertificateEntity caCertEntity = certificateRepository.findBySerialNumber(caSerialNumber)
                .orElseThrow(() -> new IllegalArgumentException("CA certificate not found for serial: " + caSerialNumber));

        if (!"ISSUED".equals(caCertEntity.getStatus())) {
            throw new IllegalStateException("CA is not active. Status: " + caCertEntity.getStatus());
        }

        CsrService.CsrDetails csrDetails = csrService.parseCsr(csrPem);

        // Fetch CA Key pair
        KeyPairEntity caKeyPair = keyPairRepository.findAll().stream()
                .filter(k -> normalizePem(k.getPublicKeyPEM()).equals(normalizePem(caCertEntity.getPublicKeyPEM())))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("CA Private Key not found."));

        PrivateKey caPrivateKey;
        boolean caInHsm = HSMKeyService.isHsmReference(caKeyPair.getPrivateKeyPEM());
        if (caInHsm) {
            String caAlias = HSMKeyService.extractAlias(caKeyPair.getPrivateKeyPEM());
            caPrivateKey = hsmKeyService.getPrivateKey(caAlias);
        } else {
            caPrivateKey = serializationService.parsePrivateKeyFromPem(caKeyPair.getPrivateKeyPEM());
        }
        PublicKey caPublicKey = serializationService.parsePublicKeyFromPem(caKeyPair.getPublicKeyPEM());

        // Fetch or create profile
        CertificateProfileEntity profile = profileRepository.findByName(profileName)
                .orElseGet(() -> createDefaultProfile(profileName, false, 365, "SHA256withRSA"));

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000 * 60 * 5);
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * profile.getValidityDays());
        BigInteger serial = BigInteger.valueOf(System.nanoTime());

        X500Name subject = new X500Name(csrDetails.getSubjectDN());
        X500Name issuer = new X500Name(caCertEntity.getSubjectDN());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, csrDetails.getPublicKey()
        );

        // Extensions
        // Basic Constraints
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(profile.isBasicConstraints()));

        // Key Usage
        int keyUsageVal = 0;
        if (profile.getKeyUsage() != null) {
            String[] kuStrings = profile.getKeyUsage().split(",");
            for (String ku : kuStrings) {
                switch (ku.trim().toLowerCase()) {
                    case "digitalsignature": keyUsageVal |= KeyUsage.digitalSignature; break;
                    case "nonrepudiation": keyUsageVal |= KeyUsage.nonRepudiation; break;
                    case "keyencipherment": keyUsageVal |= KeyUsage.keyEncipherment; break;
                    case "dataencipherment": keyUsageVal |= KeyUsage.dataEncipherment; break;
                    case "keyagreement": keyUsageVal |= KeyUsage.keyAgreement; break;
                    case "keycertsign": keyUsageVal |= KeyUsage.keyCertSign; break;
                    case "crlsign": keyUsageVal |= KeyUsage.cRLSign; break;
                }
            }
        } else {
            keyUsageVal = KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
        }
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageVal));

        // Extended Key Usage (EKU)
        if (profile.getExtendedKeyUsage() != null) {
            List<KeyPurposeId> purposeIds = new ArrayList<>();
            String[] ekuStrings = profile.getExtendedKeyUsage().split(",");
            for (String eku : ekuStrings) {
                switch (eku.trim().toLowerCase()) {
                    case "serverauth": purposeIds.add(KeyPurposeId.id_kp_serverAuth); break;
                    case "clientauth": purposeIds.add(KeyPurposeId.id_kp_clientAuth); break;
                    case "codesigning": purposeIds.add(KeyPurposeId.id_kp_codeSigning); break;
                    case "emailprotection": purposeIds.add(KeyPurposeId.id_kp_emailProtection); break;
                }
            }
            if (!purposeIds.isEmpty()) {
                certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposeIds.toArray(new KeyPurposeId[0])));
            }
        }

        // Subject Alternative Name (SAN)
        if (csrDetails.getSans() != null && !csrDetails.getSans().isEmpty()) {
            List<GeneralName> generalNamesList = new ArrayList<>();
            for (String san : csrDetails.getSans()) {
                if (san.contains(":")) {
                    String[] parts = san.split(":", 2);
                    try {
                        int tag = Integer.parseInt(parts[0]);
                        generalNamesList.add(new GeneralName(tag, parts[1]));
                    } catch (NumberFormatException e) {
                        generalNamesList.add(new GeneralName(GeneralName.dNSName, san));
                    }
                } else {
                    generalNamesList.add(new GeneralName(GeneralName.dNSName, san));
                }
            }
            GeneralNames generalNames = new GeneralNames(generalNamesList.toArray(new GeneralName[0]));
            certBuilder.addExtension(Extension.subjectAlternativeName, false, generalNames);
        }

        // Subject Key Identifier (SPKI hash)
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, buildSki(csrDetails.getPublicKey()));

        // Authority Key Identifier (SPKI hash)
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, buildAki(caPublicKey));

        // CRL Distribution Points (CDP)
        String crlUrl = baseUrl + "/api/v1/crl/" + caCertEntity.getSerialNumber() + "/latest/der";
        GeneralName crlGeneralName = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
        DistributionPointName dpName = new DistributionPointName(new GeneralNames(crlGeneralName));
        CRLDistPoint cdp = new CRLDistPoint(new DistributionPoint[]{ new DistributionPoint(dpName, null, null) });
        certBuilder.addExtension(Extension.cRLDistributionPoints, false, cdp);

        // Authority Information Access (AIA / OCSP)
        String ocspUrl = baseUrl + "/api/v1/ocsp/" + caCertEntity.getSerialNumber();
        AccessDescription ocspAccess = new AccessDescription(
                AccessDescription.id_ad_ocsp,
                new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl));
        AuthorityInformationAccess aia = new AuthorityInformationAccess(ocspAccess);
        certBuilder.addExtension(Extension.authorityInfoAccess, false, aia);

        String sigAlg = profile.getSignatureAlgorithm();
        if (caKeyPair.getAlgorithm().equalsIgnoreCase("EC")) {
            sigAlg = "SHA256withECDSA";
        } else if (caKeyPair.getAlgorithm().equalsIgnoreCase("Ed25519")) {
            sigAlg = "Ed25519";
        }

        ContentSigner signer;
        if (caInHsm) {
            signer = new JcaContentSignerBuilder(sigAlg).setProvider(hsmKeyService.getProvider()).build(caPrivateKey);
        } else {
            signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(caPrivateKey);
        }
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

        CertificateEntity certEntity = new CertificateEntity();
        certEntity.setSerialNumber(serial.toString());
        certEntity.setSubjectDN(csrDetails.getSubjectDN());
        certEntity.setIssuerDN(caCertEntity.getSubjectDN());
        certEntity.setNotBefore(notBefore.toInstant());
        certEntity.setNotAfter(notAfter.toInstant());
        certEntity.setPublicKeyPEM(serializationService.convertToPem(csrDetails.getPublicKey()));
        certEntity.setStatus("ISSUED");
        certEntity.setPemContent(serializationService.convertToPem(cert));
        certEntity.setCertificateType("END_ENTITY");
        certEntity.setProfileName(profileName);

        CertificateEntity saved = certificateRepository.save(certEntity);

        auditService.log(username, "SIGN_CSR", "Signed CSR for Subject: " + csrDetails.getSubjectDN() + ", Serial: " + serial, "SUCCESS", "127.0.0.1");

        return saved;
    }

    /**
     * Issues a dedicated OCSP Signer Certificate signed by the specified CA.
     */
    @Transactional
    public CertificateEntity issueOcspSignerCert(String caSerialNumber, String username) throws Exception {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        CertificateEntity caCertEntity = certificateRepository.findBySerialNumber(caSerialNumber)
                .orElseThrow(() -> new IllegalArgumentException("CA certificate not found for serial: " + caSerialNumber));

        if (!"ISSUED".equals(caCertEntity.getStatus())) {
            throw new IllegalStateException("CA is not active. Status: " + caCertEntity.getStatus());
        }

        // Generate fresh keypair for OCSP responder (in HSM if hsmEnabled, else software)
        KeyPair keyPair;
        String algorithm = "RSA";
        String privateKeyPem;
        String alias = "ocsp-signer-" + System.currentTimeMillis();

        if (hsmEnabled) {
            keyPair = hsmKeyService.generateCAKeyPairInHSM(alias, "RSA", 2048);
            privateKeyPem = HSMKeyService.buildHsmReference(alias);
        } else {
            keyPair = cryptoService.generateRsaKeyPair(2048);
            privateKeyPem = serializationService.convertToPem(keyPair.getPrivate());
        }

        // Save KeyPair
        KeyPairEntity kpEntity = new KeyPairEntity();
        kpEntity.setAlgorithm(algorithm);
        kpEntity.setKeySize(2048);
        kpEntity.setPrivateKeyPEM(privateKeyPem);
        kpEntity.setPublicKeyPEM(serializationService.convertToPem(keyPair.getPublic()));
        kpEntity.setCreatedAt(Instant.now());
        kpEntity.setUser(user);
        kpEntity = keyPairRepository.save(kpEntity);

        // Fetch CA KeyPair
        KeyPairEntity caKeyPair = keyPairRepository.findAll().stream()
                .filter(k -> normalizePem(k.getPublicKeyPEM()).equals(normalizePem(caCertEntity.getPublicKeyPEM())))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("CA Private Key not found in storage."));

        PrivateKey caPrivateKey;
        boolean caInHsm = HSMKeyService.isHsmReference(caKeyPair.getPrivateKeyPEM());
        if (caInHsm) {
            String caAlias = HSMKeyService.extractAlias(caKeyPair.getPrivateKeyPEM());
            caPrivateKey = hsmKeyService.getPrivateKey(caAlias);
        } else {
            caPrivateKey = serializationService.parsePrivateKeyFromPem(caKeyPair.getPrivateKeyPEM());
        }
        PublicKey caPublicKey = serializationService.parsePublicKeyFromPem(caKeyPair.getPublicKeyPEM());

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000 * 60 * 5); // 5 mins ago
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * 30); // 30 days short validity
        BigInteger serial = BigInteger.valueOf(System.nanoTime());

        String caCn = extractCn(caCertEntity.getSubjectDN());
        String subjectDN = "CN=OCSP Responder - " + caCn + ", O=INSA PKI Revocation Authority";
        X500Name subject = new X500Name(subjectDN);
        X500Name issuer = new X500Name(caCertEntity.getSubjectDN());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, keyPair.getPublic()
        );

        // Extensions
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        certBuilder.addExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.5"), false, DERNull.INSTANCE);
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, buildSki(keyPair.getPublic()));
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, buildAki(caPublicKey));

        String sigAlg = "SHA256withRSA";
        if (caKeyPair.getAlgorithm().equalsIgnoreCase("EC")) {
            sigAlg = "SHA256withECDSA";
        } else if (caKeyPair.getAlgorithm().equalsIgnoreCase("Ed25519")) {
            sigAlg = "Ed25519";
        }

        ContentSigner signer;
        if (caInHsm) {
            signer = new JcaContentSignerBuilder(sigAlg).setProvider(hsmKeyService.getProvider()).build(caPrivateKey);
        } else {
            signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(caPrivateKey);
        }
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

        if (hsmEnabled) {
            hsmKeyService.storeCertificateChain(alias, new X509Certificate[]{cert});
        }

        CertificateEntity certEntity = new CertificateEntity();
        certEntity.setSerialNumber(serial.toString());
        certEntity.setSubjectDN(subjectDN);
        certEntity.setIssuerDN(caCertEntity.getSubjectDN());
        certEntity.setNotBefore(notBefore.toInstant());
        certEntity.setNotAfter(notAfter.toInstant());
        certEntity.setPublicKeyPEM(kpEntity.getPublicKeyPEM());
        certEntity.setStatus("ISSUED");
        certEntity.setPemContent(serializationService.convertToPem(cert));
        certEntity.setCertificateType("OCSP_SIGNER");
        certEntity.setProfileName("OCSPSigner");

        CertificateEntity saved = certificateRepository.save(certEntity);

        auditService.log(username, "ISSUE_OCSP_SIGNER", "Issued OCSP Signer Cert with Serial: " + serial + " for CA: " + caSerialNumber, "SUCCESS", "127.0.0.1");

        return saved;
    }

    /**
     * Renews a certificate: generates a new certificate with extended validity using the same key.
     */
    @Transactional
    public CertificateEntity renewCertificate(String serialNumber, String username) throws Exception {
        CertificateEntity oldCert = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + serialNumber));

        if (!"ISSUED".equals(oldCert.getStatus())) {
            throw new IllegalStateException("Only ISSUED certificates can be renewed. Status: " + oldCert.getStatus());
        }

        CertificateProfileEntity profile = profileRepository.findByName(oldCert.getProfileName())
                .orElseGet(() -> createDefaultProfile(oldCert.getProfileName(), false, 365, "SHA256withRSA"));

        String rawPem = oldCert.getPemContent();
        String sanitizedPem = sanitizePem(rawPem);

        X509Certificate oldX509 = serializationService.parseCertificateFromPem(sanitizedPem);
        PublicKey pubKey = oldX509.getPublicKey();

        // Fetch Issuer CA
        CertificateEntity caCertEntity = certificateRepository.findBySubjectDN(oldCert.getIssuerDN()).stream()
                .filter(c -> "ROOT".equals(c.getCertificateType()) || "INTERMEDIATE".equals(c.getCertificateType()))
                .filter(c -> "ISSUED".equals(c.getStatus()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Issuer CA certificate not found or not active."));

        KeyPairEntity caKeyPair = keyPairRepository.findAll().stream()
                .filter(k -> normalizePem(k.getPublicKeyPEM()).equals(normalizePem(caCertEntity.getPublicKeyPEM())))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("CA Private Key not found."));

        PrivateKey caPrivateKey;
        boolean caInHsm = HSMKeyService.isHsmReference(caKeyPair.getPrivateKeyPEM());
        if (caInHsm) {
            String caAlias = HSMKeyService.extractAlias(caKeyPair.getPrivateKeyPEM());
            caPrivateKey = hsmKeyService.getPrivateKey(caAlias);
        } else {
            caPrivateKey = serializationService.parsePrivateKeyFromPem(caKeyPair.getPrivateKeyPEM());
        }

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000 * 60 * 5);
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * profile.getValidityDays());
        BigInteger serial = BigInteger.valueOf(System.nanoTime());

        X500Name subject = new X500Name(oldCert.getSubjectDN());
        X500Name issuer = new X500Name(caCertEntity.getSubjectDN());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, pubKey
        );

        // Copy extensions from old cert
        for (Extension ext : getExtensionsFromX509(oldX509)) {
            certBuilder.addExtension(ext);
        }

        String sigAlg = profile.getSignatureAlgorithm();
        if (caKeyPair.getAlgorithm().equalsIgnoreCase("EC")) {
            sigAlg = "SHA256withECDSA";
        } else if (caKeyPair.getAlgorithm().equalsIgnoreCase("Ed25519")) {
            sigAlg = "Ed25519";
        }

        ContentSigner signer;
        if (caInHsm) {
            signer = new JcaContentSignerBuilder(sigAlg).setProvider(hsmKeyService.getProvider()).build(caPrivateKey);
        } else {
            signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(caPrivateKey);
        }
        X509Certificate newX509 = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

        // Revoke the old certificate as "SUPERSEDED"
        oldCert.setStatus("REVOKED");
        oldCert.setRevocationReason("SUPERSEDED");
        oldCert.setRevocationDate(Instant.now());
        certificateRepository.save(oldCert);
        certificateStatusCacheService.evictCertificateStatus(serialNumber);

        // Save new certificate
        CertificateEntity newCert = new CertificateEntity();
        newCert.setSerialNumber(serial.toString());
        newCert.setSubjectDN(oldCert.getSubjectDN());
        newCert.setIssuerDN(oldCert.getIssuerDN());
        newCert.setNotBefore(notBefore.toInstant());
        newCert.setNotAfter(notAfter.toInstant());
        newCert.setPublicKeyPEM(oldCert.getPublicKeyPEM());
        newCert.setStatus("ISSUED");
        newCert.setPemContent(serializationService.convertToPem(newX509));
        newCert.setCertificateType(oldCert.getCertificateType());
        newCert.setProfileName(oldCert.getProfileName());

        CertificateEntity saved = certificateRepository.save(newCert);

        auditService.log(username, "RENEW_CERTIFICATE", "Renewed certificate. Old Serial: " + serialNumber + ", New Serial: " + serial, "SUCCESS", "127.0.0.1");

        return saved;
    }

    private String sanitizePem(String pem) {
        if (pem == null) return "";
        String s = pem.trim();
        int start = s.indexOf("-----BEGIN CERTIFICATE-----");
        int end = s.indexOf("-----END CERTIFICATE-----");
        if (start != -1 && end != -1 && end > start) {
            return s.substring(start, end + "-----END CERTIFICATE-----".length());
        }
        return s;
    }

    /**
     * Suspends a certificate (temporary suspension).
     */
    @Transactional
    public CertificateEntity suspendCertificate(String serialNumber, String username) {
        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + serialNumber));

        if (!"ISSUED".equals(cert.getStatus())) {
            throw new IllegalStateException("Only ISSUED certificates can be suspended. Current status: " + cert.getStatus());
        }

        cert.setStatus("SUSPENDED");
        CertificateEntity saved = certificateRepository.save(cert);
        certificateStatusCacheService.evictCertificateStatus(serialNumber);

        auditService.log(username, "SUSPEND_CERTIFICATE", "Suspended certificate with Serial: " + serialNumber, "SUCCESS", "127.0.0.1");

        return saved;
    }

    /**
     * Unsuspends/activates a suspended certificate.
     */
    @Transactional
    public CertificateEntity unsuspendCertificate(String serialNumber, String username) {
        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + serialNumber));

        if (!"SUSPENDED".equals(cert.getStatus())) {
            throw new IllegalStateException("Only SUSPENDED certificates can be unsuspended. Current status: " + cert.getStatus());
        }

        cert.setStatus("ISSUED");
        CertificateEntity saved = certificateRepository.save(cert);
        certificateStatusCacheService.evictCertificateStatus(serialNumber);

        auditService.log(username, "UNSUSPEND_CERTIFICATE", "Unsuspended certificate with Serial: " + serialNumber, "SUCCESS", "127.0.0.1");

        return saved;
    }

    /**
     * Revokes a certificate permanently with a reason.
     */
    @Transactional
    public CertificateEntity revokeCertificate(String serialNumber, String reason, String username) {
        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + serialNumber));

        if ("REVOKED".equals(cert.getStatus())) {
            throw new IllegalStateException("Certificate is already revoked.");
        }

        cert.setStatus("REVOKED");
        cert.setRevocationReason(reason != null ? reason : "UNSPECIFIED");
        cert.setRevocationDate(Instant.now());
        CertificateEntity saved = certificateRepository.save(cert);
        certificateStatusCacheService.evictCertificateStatus(serialNumber);

        auditService.log(username, "REVOKE_CERTIFICATE", "Revoked certificate with Serial: " + serialNumber + ", Reason: " + reason, "SUCCESS", "127.0.0.1");

        return saved;
    }

    private CertificateProfileEntity createDefaultProfile(String name, boolean isCa, int validityDays, String sigAlg) {
        CertificateProfileEntity profile = new CertificateProfileEntity();
        profile.setName(name);
        profile.setDescription("Default auto-created profile for " + name);
        profile.setBasicConstraints(isCa);
        profile.setValidityDays(validityDays);
        profile.setSignatureAlgorithm(sigAlg);
        if (isCa) {
            profile.setKeyUsage("digitalSignature,keyCertSign,cRLSign");
            profile.setPathLenConstraint(1);
        } else {
            profile.setKeyUsage("digitalSignature,keyEncipherment");
            profile.setExtendedKeyUsage("clientAuth,serverAuth");
        }
        return profileRepository.save(profile);
    }

    private List<Extension> getExtensionsFromX509(X509Certificate cert) throws Exception {
        List<Extension> list = new ArrayList<>();
        byte[] extOctets = cert.getExtensionValue(Extension.basicConstraints.getId());
        if (extOctets != null) {
            list.add(new Extension(Extension.basicConstraints, true, extOctets));
        }
        extOctets = cert.getExtensionValue(Extension.keyUsage.getId());
        if (extOctets != null) {
            list.add(new Extension(Extension.keyUsage, true, extOctets));
        }
        extOctets = cert.getExtensionValue(Extension.extendedKeyUsage.getId());
        if (extOctets != null) {
            list.add(new Extension(Extension.extendedKeyUsage, false, extOctets));
        }
        extOctets = cert.getExtensionValue(Extension.subjectAlternativeName.getId());
        if (extOctets != null) {
            list.add(new Extension(Extension.subjectAlternativeName, false, extOctets));
        }
        return list;
    }

    public String normalizePem(String pem) {
        if (pem == null) return "";
        return pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
    }
}
