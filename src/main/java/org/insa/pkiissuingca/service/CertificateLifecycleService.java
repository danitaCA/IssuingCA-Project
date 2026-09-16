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
import org.insa.pkiissuingca.dto.*;
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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
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

    @Autowired
    private KeystoreService keystoreService;

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
        boolean isSubCa = "SubCA".equalsIgnoreCase(profileName) || "INTERMEDIATE".equalsIgnoreCase(profileName);
        CertificateProfileEntity profile = profileRepository.findByName(profileName)
                .orElseGet(() -> createDefaultProfile(profileName, isSubCa, isSubCa ? 1825 : 365, "SHA512withRSA"));

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

        String pubKeyPem = serializationService.convertToPem(csrDetails.getPublicKey());
        CertificateEntity pendingEntity = certificateRepository.findAll().stream()
                .filter(c -> "PENDING_ACTIVATION".equals(c.getStatus()) &&
                        normalizePem(c.getPublicKeyPEM()).equals(normalizePem(pubKeyPem)))
                .findFirst()
                .orElse(null);

        CertificateEntity certEntity = pendingEntity != null ? pendingEntity : new CertificateEntity();
        boolean isCa = profile.isBasicConstraints() || isSubCa;

        certEntity.setSerialNumber(serial.toString());
        certEntity.setSubjectDN(csrDetails.getSubjectDN());
        certEntity.setIssuerDN(caCertEntity.getSubjectDN());
        certEntity.setNotBefore(notBefore.toInstant());
        certEntity.setNotAfter(notAfter.toInstant());
        certEntity.setPublicKeyPEM(pubKeyPem);
        certEntity.setStatus("ISSUED");
        certEntity.setPemContent(serializationService.convertToPem(cert));
        certEntity.setCertificateType(isCa ? "INTERMEDIATE" : "END_ENTITY");
        certEntity.setProfileName(profileName);

        CertificateEntity saved = certificateRepository.save(certEntity);

        auditService.log(username, "SIGN_CSR", "Signed CSR for Subject: " + csrDetails.getSubjectDN() + ", Serial: " + serial + ", Type: " + certEntity.getCertificateType(), "SUCCESS", "127.0.0.1");

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
        CertificateEntity caCertEntity = null;
        if (oldCert.getSubjectDN().equals(oldCert.getIssuerDN()) && ("ROOT".equals(oldCert.getCertificateType()) || "INTERMEDIATE".equals(oldCert.getCertificateType()))) {
            caCertEntity = oldCert;
        } else {
            List<CertificateEntity> candidates = certificateRepository.findBySubjectDN(oldCert.getIssuerDN());
            caCertEntity = candidates.stream()
                    .filter(c -> "ROOT".equals(c.getCertificateType()) || "INTERMEDIATE".equals(c.getCertificateType()))
                    .filter(c -> "ISSUED".equals(c.getStatus()))
                    .findFirst()
                    .orElse(null);

            if (caCertEntity == null) {
                // Fallback: match by normalized X500Name across all active CA entities
                try {
                    X500Name targetIssuerName = new X500Name(oldCert.getIssuerDN());
                    caCertEntity = certificateRepository.findAll().stream()
                            .filter(c -> "ROOT".equals(c.getCertificateType()) || "INTERMEDIATE".equals(c.getCertificateType()))
                            .filter(c -> "ISSUED".equals(c.getStatus()))
                            .filter(c -> {
                                try {
                                    return new X500Name(c.getSubjectDN()).equals(targetIssuerName);
                                } catch (Exception ignored) {
                                    return false;
                                }
                            })
                            .findFirst()
                            .orElse(null);
                } catch (Exception ignored) {}
            }
        }

        if (caCertEntity == null) {
            throw new IllegalStateException("Active Issuer CA certificate not found for issuer: " + oldCert.getIssuerDN());
        }

        final CertificateEntity finalCa = caCertEntity;
        KeyPairEntity caKeyPair = keyPairRepository.findAll().stream()
                .filter(k -> normalizePem(k.getPublicKeyPEM()).equals(normalizePem(finalCa.getPublicKeyPEM())))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("CA Private Key not found for CA: " + finalCa.getSubjectDN()));

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

        // Copy standard extensions from old cert
        for (Extension ext : getExtensionsFromX509(oldX509)) {
            certBuilder.addExtension(ext);
        }

        // Subject Key Identifier (SPKI hash)
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, buildSki(pubKey));

        // Authority Key Identifier (CA SPKI hash)
        PublicKey caPublicKey = serializationService.parsePublicKeyFromPem(caCertEntity.getPublicKeyPEM());
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
        newCert.setIssuerDN(caCertEntity.getSubjectDN());
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
     * Reactivates (unsuspends) a suspended certificate.
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
     * Revokes a certificate.
     */
    @Transactional
    public CertificateEntity revokeCertificate(String serialNumber, String reason, String username) {
        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + serialNumber));

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
        addUnwrappedExtension(list, cert, Extension.basicConstraints, true);
        addUnwrappedExtension(list, cert, Extension.keyUsage, true);
        addUnwrappedExtension(list, cert, Extension.extendedKeyUsage, false);
        addUnwrappedExtension(list, cert, Extension.subjectAlternativeName, false);
        return list;
    }

    private void addUnwrappedExtension(List<Extension> list, X509Certificate cert, org.bouncycastle.asn1.ASN1ObjectIdentifier oid, boolean critical) {
        byte[] extOctets = cert.getExtensionValue(oid.getId());
        if (extOctets != null && extOctets.length > 0) {
            try {
                org.bouncycastle.asn1.ASN1OctetString oct = org.bouncycastle.asn1.ASN1OctetString.getInstance(extOctets);
                list.add(new Extension(oid, critical, oct.getOctets()));
            } catch (Exception e) {
                list.add(new Extension(oid, critical, extOctets));
            }
        }
    }

    public String normalizePem(String pem) {
        if (pem == null) return "";
        return pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
    }

    /**
     * Generate Subordinate/Issuing CA CSR and registers it in PENDING_ACTIVATION state.
     */
    @Transactional
    public SubCaCsrResponse generateSubCaCsr(SubCaCsrRequest request, String username) throws Exception {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        int keySize = request.getKeySizeOrCurve() > 0 ? request.getKeySizeOrCurve() : 4096;
        String keyType = request.getKeyType() != null ? request.getKeyType() : "RSA";
        String sigAlg = request.getSignatureAlgorithm() != null ? request.getSignatureAlgorithm() : "SHA512withRSA";

        KeyPair keyPair;
        String algorithm;
        String privateKeyPem;
        String alias = "subca-csr-" + System.currentTimeMillis();

        if (hsmEnabled) {
            algorithm = ("EC".equalsIgnoreCase(keyType) || "ECDSA".equalsIgnoreCase(keyType)) ? "EC" : "RSA";
            keyPair = hsmKeyService.generateCAKeyPairInHSM(alias, keyType, keySize);
            privateKeyPem = HSMKeyService.buildHsmReference(alias);
        } else {
            if ("EC".equalsIgnoreCase(keyType) || "ECDSA".equalsIgnoreCase(keyType)) {
                String curve = keySize == 384 ? "secp384r1" : (keySize == 521 ? "secp521r1" : "secp256r1");
                keyPair = cryptoService.generateEcKeyPair(curve);
                algorithm = "EC";
            } else if ("Ed25519".equalsIgnoreCase(keyType)) {
                keyPair = cryptoService.generateEd25519KeyPair();
                algorithm = "Ed25519";
            } else {
                keyPair = cryptoService.generateRsaKeyPair(keySize);
                algorithm = "RSA";
            }
            privateKeyPem = serializationService.convertToPem(keyPair.getPrivate());
        }

        // Save KeyPair
        KeyPairEntity kpEntity = new KeyPairEntity();
        kpEntity.setAlgorithm(algorithm);
        kpEntity.setKeySize(keySize);
        kpEntity.setPrivateKeyPEM(privateKeyPem);
        kpEntity.setPublicKeyPEM(serializationService.convertToPem(keyPair.getPublic()));
        kpEntity.setCreatedAt(Instant.now());
        kpEntity.setUser(user);
        kpEntity = keyPairRepository.save(kpEntity);

        // Generate PKCS#10 CSR
        String csrPem;
        if (hsmEnabled && hsmKeyService.getProvider() != null) {
            csrPem = cryptoService.generateCsr(keyPair, request.getSubjectDN(), hsmKeyService.getProvider());
        } else {
            csrPem = cryptoService.generateCsr(keyPair, request.getSubjectDN());
        }

        // Create a tracking CertificateEntity in PENDING_ACTIVATION state
        BigInteger pendingSerial = BigInteger.valueOf(System.nanoTime());
        CertificateEntity pendingEntity = new CertificateEntity();
        pendingEntity.setSerialNumber(pendingSerial.toString());
        pendingEntity.setSubjectDN(request.getSubjectDN());
        pendingEntity.setIssuerDN("EXTERNAL_ROOT_PENDING");
        pendingEntity.setPublicKeyPEM(kpEntity.getPublicKeyPEM());
        pendingEntity.setStatus("PENDING_ACTIVATION");
        pendingEntity.setPemContent(csrPem);
        pendingEntity.setCertificateType("INTERMEDIATE");
        pendingEntity.setProfileName("SubCA");
        certificateRepository.save(pendingEntity);

        auditService.log(username, "GENERATE_SUB_CA_CSR", "Generated Sub CA CSR for Subject: " + request.getSubjectDN() + ", Size: " + keySize + ", SigAlg: " + sigAlg, "SUCCESS", "127.0.0.1");

        SubCaCsrResponse response = new SubCaCsrResponse();
        response.setSerialNumber(pendingSerial.toString());
        response.setSubjectDN(request.getSubjectDN());
        response.setCsrPem(csrPem);
        response.setPublicKeyPEM(kpEntity.getPublicKeyPEM());
        response.setKeyAlgorithm(algorithm);
        response.setKeySize(keySize);
        return response;
    }

    /**
     * Imports a signed Sub CA certificate and activates it for issuing end-entity certificates.
     */
    @Transactional
    public CertificateEntity importSignedCaCertificate(ImportSignedCaCertRequest request, String username) throws Exception {
        String sanitizedCertPem = sanitizePem(request.getSignedCertPem());
        X509Certificate x509 = serializationService.parseCertificateFromPem(sanitizedCertPem);
        String subjectDN = x509.getSubjectX500Principal().getName();
        String issuerDN = x509.getIssuerX500Principal().getName();
        String serialNumber = x509.getSerialNumber().toString();
        PublicKey pubKey = x509.getPublicKey();
        String pubKeyPem = serializationService.convertToPem(pubKey);

        // Look for pending Sub CA entity or match by public key
        CertificateEntity caEntity = null;
        if (request.getCaSerialNumber() != null && !request.getCaSerialNumber().isEmpty()) {
            caEntity = certificateRepository.findBySerialNumber(request.getCaSerialNumber()).orElse(null);
        }
        if (caEntity == null) {
            caEntity = certificateRepository.findAll().stream()
                    .filter(c -> normalizePem(c.getPublicKeyPEM()).equals(normalizePem(pubKeyPem)))
                    .findFirst()
                    .orElse(null);
        }
        if (caEntity == null) {
            caEntity = new CertificateEntity();
        }

        caEntity.setSerialNumber(serialNumber);
        caEntity.setSubjectDN(subjectDN);
        caEntity.setIssuerDN(issuerDN);
        caEntity.setNotBefore(x509.getNotBefore().toInstant());
        caEntity.setNotAfter(x509.getNotAfter().toInstant());
        caEntity.setPublicKeyPEM(pubKeyPem);
        caEntity.setStatus("ISSUED");
        caEntity.setPemContent(serializationService.convertToPem(x509));

        CertificateEntity saved = certificateRepository.save(caEntity);

        if (hsmEnabled) {
            // Find alias if exists
            KeyPairEntity kp = keyPairRepository.findAll().stream()
                    .filter(k -> normalizePem(k.getPublicKeyPEM()).equals(normalizePem(pubKeyPem)))
                    .findFirst().orElse(null);
            if (kp != null && HSMKeyService.isHsmReference(kp.getPrivateKeyPEM())) {
                String alias = HSMKeyService.extractAlias(kp.getPrivateKeyPEM());
                hsmKeyService.storeCertificateChain(alias, new X509Certificate[]{x509});
            }
        }

        auditService.log(username, "IMPORT_SIGNED_CA_CERTIFICATE", "Imported and activated Sub CA: " + subjectDN + ", Serial: " + serialNumber, "SUCCESS", "127.0.0.1");

        return saved;
    }

    /**
     * End-Entity Enrollment with RA metadata, Advised/Server key generation, and Admin password encryption for PKCS#12.
     */
    @Transactional
    public EndEntityEnrollResponse enrollEndEntity(EndEntityEnrollRequest req, String username) throws Exception {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        // 1. Resolve CA
        CertificateEntity caCertEntity;
        if (req.getCaSerialNumber() != null && !req.getCaSerialNumber().isEmpty()) {
            caCertEntity = certificateRepository.findBySerialNumber(req.getCaSerialNumber())
                    .orElseThrow(() -> new IllegalArgumentException("CA certificate not found for serial: " + req.getCaSerialNumber()));
        } else {
            // Default to any active Sub CA or Root CA
            caCertEntity = certificateRepository.findAll().stream()
                    .filter(c -> ("INTERMEDIATE".equals(c.getCertificateType()) || "ROOT".equals(c.getCertificateType())) && "ISSUED".equals(c.getStatus()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("No active Issuing CA found in system."));
        }

        if (!"ISSUED".equals(caCertEntity.getStatus())) {
            throw new IllegalStateException("Selected CA is not active. Status: " + caCertEntity.getStatus());
        }

        // 2. Resolve Profile
        String profileName = req.getProfileName() != null ? req.getProfileName() : "EndEntity";
        CertificateProfileEntity profile = profileRepository.findByName(profileName)
                .orElseGet(() -> createDefaultProfile(profileName, false, 365, "SHA512withRSA"));

        // 3. Build Subject DN
        StringBuilder dnBuilder = new StringBuilder();
        dnBuilder.append("CN=").append(req.getCommonName() != null ? req.getCommonName() : req.getUsername());
        if (req.getOrganization() != null && !req.getOrganization().isEmpty()) {
            dnBuilder.append(", O=").append(req.getOrganization());
        }
        if (req.getCountry() != null && !req.getCountry().isEmpty()) {
            dnBuilder.append(", C=").append(req.getCountry());
        }
        if (req.getOrgUnit() != null && !req.getOrgUnit().isEmpty()) {
            dnBuilder.append(", OU=").append(req.getOrgUnit());
        }
        if (req.getState() != null && !req.getState().isEmpty()) {
            dnBuilder.append(", ST=").append(req.getState());
        }
        if (req.getLocality() != null && !req.getLocality().isEmpty()) {
            dnBuilder.append(", L=").append(req.getLocality());
        }
        String subjectDN = dnBuilder.toString();

        PublicKey endEntityPubKey;
        PrivateKey endEntityPrivKey = null;
        KeyPairEntity eeKpEntity = null;

        boolean isAdvisedMode = !"USER_GENERATED".equalsIgnoreCase(req.getKeyGenerationMode()) || req.getCsrPem() == null || req.getCsrPem().trim().isEmpty();

        if (isAdvisedMode) {
            // Advised server-side key generation
            int keySize = (req.getKeySize() != null && req.getKeySize() > 0) ? req.getKeySize() : 4096;
            String keyType = req.getKeyType() != null ? req.getKeyType() : "RSA";
            KeyPair eeKeyPair;
            if ("EC".equalsIgnoreCase(keyType) || "ECDSA".equalsIgnoreCase(keyType)) {
                String curve = keySize == 384 ? "secp384r1" : (keySize == 521 ? "secp521r1" : "secp256r1");
                eeKeyPair = cryptoService.generateEcKeyPair(curve);
            } else {
                eeKeyPair = cryptoService.generateRsaKeyPair(keySize);
            }
            endEntityPubKey = eeKeyPair.getPublic();
            endEntityPrivKey = eeKeyPair.getPrivate();

            eeKpEntity = new KeyPairEntity();
            eeKpEntity.setAlgorithm("EC".equalsIgnoreCase(keyType) ? "EC" : "RSA");
            eeKpEntity.setKeySize(keySize);
            eeKpEntity.setPrivateKeyPEM(serializationService.convertToPem(endEntityPrivKey));
            eeKpEntity.setPublicKeyPEM(serializationService.convertToPem(endEntityPubKey));
            eeKpEntity.setCreatedAt(Instant.now());
            eeKpEntity.setUser(user);
            eeKpEntity = keyPairRepository.save(eeKpEntity);
        } else {
            CsrService.CsrDetails csrDetails = csrService.parseCsr(req.getCsrPem());
            endEntityPubKey = csrDetails.getPublicKey();
            if (csrDetails.getSubjectDN() != null && !csrDetails.getSubjectDN().isEmpty()) {
                subjectDN = csrDetails.getSubjectDN();
            }
        }

        // Fetch CA Key Pair
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
        Date notBefore = new Date(now - 1000 * 60 * 5);
        Date notAfter = new Date(now + 1000L * 60 * 60 * 24 * profile.getValidityDays());
        BigInteger serial = BigInteger.valueOf(System.nanoTime());

        X500Name subject = new X500Name(subjectDN);
        X500Name issuer = new X500Name(caCertEntity.getSubjectDN());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, endEntityPubKey
        );

        // Extensions
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        int keyUsageVal = KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageVal));

        List<KeyPurposeId> purposeIds = new ArrayList<>();
        purposeIds.add(KeyPurposeId.id_kp_clientAuth);
        purposeIds.add(KeyPurposeId.id_kp_serverAuth);
        if (req.getEmail() != null && !req.getEmail().isEmpty()) {
            purposeIds.add(KeyPurposeId.id_kp_emailProtection);
        }
        certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposeIds.toArray(new KeyPurposeId[0])));

        // Subject Alternative Name
        List<GeneralName> sanList = new ArrayList<>();
        if (req.getCommonName() != null && req.getCommonName().contains(".")) {
            sanList.add(new GeneralName(GeneralName.dNSName, req.getCommonName()));
        }
        if (req.getEmail() != null && !req.getEmail().isEmpty()) {
            sanList.add(new GeneralName(GeneralName.rfc822Name, req.getEmail()));
        }
        if (!sanList.isEmpty()) {
            certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sanList.toArray(new GeneralName[0])));
        }

        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, buildSki(endEntityPubKey));
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, buildAki(caPublicKey));

        // CDP
        String crlUrl = baseUrl + "/api/v1/crl/" + caCertEntity.getSerialNumber() + "/latest/der";
        GeneralName crlGeneralName = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
        DistributionPointName dpName = new DistributionPointName(new GeneralNames(crlGeneralName));
        CRLDistPoint cdp = new CRLDistPoint(new DistributionPoint[]{ new DistributionPoint(dpName, null, null) });
        certBuilder.addExtension(Extension.cRLDistributionPoints, false, cdp);

        // AIA / OCSP
        String ocspUrl = baseUrl + "/api/v1/ocsp/" + caCertEntity.getSerialNumber();
        AccessDescription ocspAccess = new AccessDescription(
                AccessDescription.id_ad_ocsp,
                new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl));
        AuthorityInformationAccess aia = new AuthorityInformationAccess(ocspAccess);
        certBuilder.addExtension(Extension.authorityInfoAccess, false, aia);

        String sigAlg = profile.getSignatureAlgorithm() != null ? profile.getSignatureAlgorithm() : "SHA512withRSA";
        if (caKeyPair.getAlgorithm().equalsIgnoreCase("EC")) {
            sigAlg = "SHA512withECDSA";
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
        certEntity.setSubjectDN(subjectDN);
        certEntity.setIssuerDN(caCertEntity.getSubjectDN());
        certEntity.setNotBefore(notBefore.toInstant());
        certEntity.setNotAfter(notAfter.toInstant());
        certEntity.setPublicKeyPEM(serializationService.convertToPem(endEntityPubKey));
        certEntity.setStatus("ISSUED");
        certEntity.setPemContent(serializationService.convertToPem(cert));
        certEntity.setCertificateType("END_ENTITY");
        certEntity.setProfileName(profileName);

        CertificateEntity saved = certificateRepository.save(certEntity);

        // Build Chain PEM
        String chainPem = getCertificateChainPem(serial.toString());

        // Build PKCS#12 bundle if private key is available
        String pkcs12Base64 = null;
        if (endEntityPrivKey != null) {
            String pfxPass = (req.getAdminPassword() != null && !req.getAdminPassword().isEmpty()) ? req.getAdminPassword() : "changeit";
            X509Certificate caCert = serializationService.parseCertificateFromPem(caCertEntity.getPemContent());
            Certificate[] chain = new Certificate[]{ cert, caCert };

            KeyStore ks = keystoreService.createKeyStore("PKCS12");
            keystoreService.storePrivateKey(ks, req.getUsername() != null ? req.getUsername() : "entity", endEntityPrivKey, pfxPass, chain);
            byte[] pfxBytes = keystoreService.saveKeyStore(ks, pfxPass);
            pkcs12Base64 = Base64.getEncoder().encodeToString(pfxBytes);
        }

        auditService.log(username, "ENROLL_END_ENTITY", "Enrolled End Entity: " + subjectDN + ", Serial: " + serial + ", Issuer: " + caCertEntity.getSubjectDN(), "SUCCESS", "127.0.0.1");

        EndEntityEnrollResponse response = new EndEntityEnrollResponse();
        response.setCertificate(saved);
        response.setCertificatePem(saved.getPemContent());
        response.setChainPem(chainPem);
        response.setPkcs12Base64(pkcs12Base64);
        response.setMessage("End entity certificate issued successfully.");
        return response;
    }

    /**
     * Retrieves concatenated PEM certificate chain starting from leaf to root.
     */
    public String getCertificateChainPem(String serialNumber) {
        StringBuilder chain = new StringBuilder();
        CertificateEntity current = certificateRepository.findBySerialNumber(serialNumber).orElse(null);
        int depth = 0;
        Set<String> visited = new HashSet<>();

        while (current != null && depth < 10) {
            if (visited.contains(current.getSerialNumber())) {
                break;
            }
            visited.add(current.getSerialNumber());
            chain.append(current.getPemContent().trim()).append("\n");

            if ("ROOT".equalsIgnoreCase(current.getCertificateType()) || current.getSubjectDN().equals(current.getIssuerDN())) {
                break;
            }

            final String issuerDN = current.getIssuerDN();
            current = certificateRepository.findAll().stream()
                    .filter(c -> c.getSubjectDN().equals(issuerDN) && ("ROOT".equals(c.getCertificateType()) || "INTERMEDIATE".equals(c.getCertificateType())) && "ISSUED".equals(c.getStatus()))
                    .findFirst()
                    .orElse(null);
            depth++;
        }

        return chain.toString();
    }

    /**
     * Generates a password-protected PKCS#12 bundle for an issued certificate if key exists.
     */
    public byte[] generatePkcs12ForCert(String serialNumber, String password) throws Exception {
        CertificateEntity certEntity = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found for serial: " + serialNumber));

        KeyPairEntity kp = keyPairRepository.findAll().stream()
                .filter(k -> normalizePem(k.getPublicKeyPEM()).equals(normalizePem(certEntity.getPublicKeyPEM())))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Private key not stored for certificate: " + serialNumber));

        if (HSMKeyService.isHsmReference(kp.getPrivateKeyPEM())) {
            throw new IllegalStateException("Private key is protected in HSM hardware and marked NON-EXPORTABLE.");
        }

        PrivateKey privateKey = serializationService.parsePrivateKeyFromPem(kp.getPrivateKeyPEM());
        X509Certificate cert = serializationService.parseCertificateFromPem(certEntity.getPemContent());

        List<Certificate> chainList = new ArrayList<>();
        chainList.add(cert);

        // Fetch parent CA certificate
        certificateRepository.findAll().stream()
                .filter(c -> c.getSubjectDN().equals(certEntity.getIssuerDN()) && ("ROOT".equals(c.getCertificateType()) || "INTERMEDIATE".equals(c.getCertificateType())))
                .findFirst()
                .ifPresent(ca -> {
                    try {
                        chainList.add(serializationService.parseCertificateFromPem(ca.getPemContent()));
                    } catch (Exception ignored) {}
                });

        KeyStore ks = keystoreService.createKeyStore("PKCS12");
        String pass = password != null ? password : "changeit";
        keystoreService.storePrivateKey(ks, "certificate", privateKey, pass, chainList.toArray(new Certificate[0]));
        return keystoreService.saveKeyStore(ks, pass);
    }
}

