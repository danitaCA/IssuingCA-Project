package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.CrlEntity;
import org.insa.pkiissuingca.model.KeyPairEntity;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.repository.CrlRepository;
import org.insa.pkiissuingca.repository.KeyPairRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class CrlService {

    @Autowired
    private CrlRepository crlRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private KeyPairRepository keyPairRepository;

    @Autowired
    private CertificateLifecycleService certificateLifecycleService;

    @Autowired
    private X509ExtensionHelper x509ExtensionHelper;

    @Autowired
    private SerializationService serializationService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private HSMKeyService hsmKeyService;

    @Value("${pki.crl.full-interval-hours:24}")
    private long fullIntervalHours;

    @Value("${pki.crl.delta-interval-hours:1}")
    private long deltaIntervalHours;

    private final Object crlNumberLock = new Object();

    /**
     * Monotonically increasing CRL number helper per CA (must be invoked under crlNumberLock).
     */
    private BigInteger nextCrlNumber(String caSerialNumber) {
        List<CrlEntity> crls = crlRepository.findByCaSerialNumberOrderByCrlNumberDesc(caSerialNumber);
        if (crls.isEmpty()) {
            return BigInteger.ONE;
        }
        return crls.stream()
                .map(c -> {
                    try {
                        return new BigInteger(c.getCrlNumber());
                    } catch (Exception e) {
                        return BigInteger.ZERO;
                    }
                })
                .max(BigInteger::compareTo)
                .map(max -> max.add(BigInteger.ONE))
                .orElse(BigInteger.ONE);
    }

    /**
     * Builds and signs a Full CRL for the given CA under synchronization lock.
     */
    @Transactional
    public CrlEntity generateFullCrl(String caSerialNumber, String username) throws Exception {
        synchronized (crlNumberLock) {
            CertificateEntity caCert = certificateRepository.findBySerialNumber(caSerialNumber)
                    .orElseThrow(() -> new IllegalArgumentException("CA certificate not found for serial: " + caSerialNumber));

            if (!"ISSUED".equals(caCert.getStatus())) {
                throw new IllegalStateException("CA certificate is not active. Status: " + caCert.getStatus());
            }

            // Look up CA KeyPair
            KeyPairEntity caKeyPair = keyPairRepository.findAll().stream()
                    .filter(k -> certificateLifecycleService.normalizePem(k.getPublicKeyPEM()).equals(
                            certificateLifecycleService.normalizePem(caCert.getPublicKeyPEM())))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("CA Private Key not found for CA: " + caSerialNumber));

            PrivateKey caPrivateKey;
            boolean caInHsm = HSMKeyService.isHsmReference(caKeyPair.getPrivateKeyPEM());
            if (caInHsm) {
                String caAlias = HSMKeyService.extractAlias(caKeyPair.getPrivateKeyPEM());
                caPrivateKey = hsmKeyService.getPrivateKey(caAlias);
            } else {
                caPrivateKey = serializationService.parsePrivateKeyFromPem(caKeyPair.getPrivateKeyPEM());
            }
            PublicKey caPublicKey = serializationService.parsePublicKeyFromPem(caKeyPair.getPublicKeyPEM());

            BigInteger crlNumber = nextCrlNumber(caSerialNumber);
            Instant thisUpdate = Instant.now();
            Instant nextUpdate = thisUpdate.plus(Duration.ofHours(fullIntervalHours > 0 ? fullIntervalHours : 24));

            X500Name issuer = new X500Name(caCert.getSubjectDN());
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, Date.from(thisUpdate));
            crlBuilder.setNextUpdate(Date.from(nextUpdate));

            // Pull all revoked or suspended certificates issued by this CA
            List<CertificateEntity> revokedCerts = certificateRepository.findAll().stream()
                    .filter(c -> caCert.getSubjectDN().equals(c.getIssuerDN()))
                    .filter(c -> "REVOKED".equalsIgnoreCase(c.getStatus()) || "SUSPENDED".equalsIgnoreCase(c.getStatus()))
                    .collect(Collectors.toList());

            for (CertificateEntity cert : revokedCerts) {
                BigInteger serial = new BigInteger(cert.getSerialNumber());
                Date revDate = cert.getRevocationDate() != null ? Date.from(cert.getRevocationDate()) : Date.from(thisUpdate);
                int reasonCode = mapReasonCode(cert.getStatus(), cert.getRevocationReason());
                crlBuilder.addCRLEntry(serial, revDate, reasonCode);
            }

            // Extensions
            crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(crlNumber));
            crlBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    x509ExtensionHelper != null ? x509ExtensionHelper.buildAki(caPublicKey) : certificateLifecycleService.buildAki(caPublicKey));

            // Sign CRL
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
            X509CRLHolder crlHolder = crlBuilder.build(signer);

            byte[] crlDer = crlHolder.getEncoded();
            String crlPem = serializationService.convertToPem(crlHolder);

            CrlEntity crlEntity = new CrlEntity();
            crlEntity.setCaSerialNumber(caSerialNumber);
            crlEntity.setCrlNumber(crlNumber.toString());
            crlEntity.setScope("FULL");
            crlEntity.setBaseCrlNumber(null);
            crlEntity.setThisUpdate(thisUpdate);
            crlEntity.setNextUpdate(nextUpdate);
            crlEntity.setCrlPem(crlPem);
            crlEntity.setCrlDer(crlDer);
            crlEntity.setRevokedCount(revokedCerts.size());
            crlEntity.setCreatedAt(Instant.now());

            CrlEntity saved = crlRepository.save(crlEntity);

            auditService.log(username, "GENERATE_CRL",
                    "Generated FULL CRL #" + crlNumber + " for CA: " + caSerialNumber + " with " + revokedCerts.size() + " revoked entries",
                    "SUCCESS", "127.0.0.1");

            return saved;
        }
    }

    /**
     * Builds and signs a Delta CRL for the given CA under synchronization lock.
     */
    @Transactional
    public CrlEntity generateDeltaCrl(String caSerialNumber, String username) throws Exception {
        synchronized (crlNumberLock) {
            CertificateEntity caCert = certificateRepository.findBySerialNumber(caSerialNumber)
                    .orElseThrow(() -> new IllegalArgumentException("CA certificate not found for serial: " + caSerialNumber));

            if (!"ISSUED".equals(caCert.getStatus())) {
                throw new IllegalStateException("CA certificate is not active. Status: " + caCert.getStatus());
            }

            // Must have a base full CRL
            CrlEntity baseFullCrl = getLatestCrl(caSerialNumber, "FULL");
            if (baseFullCrl == null) {
                throw new IllegalStateException("Cannot generate Delta CRL without a base Full CRL for CA: " + caSerialNumber);
            }

            KeyPairEntity caKeyPair = keyPairRepository.findAll().stream()
                    .filter(k -> certificateLifecycleService.normalizePem(k.getPublicKeyPEM()).equals(
                            certificateLifecycleService.normalizePem(caCert.getPublicKeyPEM())))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("CA Private Key not found for CA: " + caSerialNumber));

            PrivateKey caPrivateKey;
            boolean caInHsm = HSMKeyService.isHsmReference(caKeyPair.getPrivateKeyPEM());
            if (caInHsm) {
                String caAlias = HSMKeyService.extractAlias(caKeyPair.getPrivateKeyPEM());
                caPrivateKey = hsmKeyService.getPrivateKey(caAlias);
            } else {
                caPrivateKey = serializationService.parsePrivateKeyFromPem(caKeyPair.getPrivateKeyPEM());
            }
            PublicKey caPublicKey = serializationService.parsePublicKeyFromPem(caKeyPair.getPublicKeyPEM());

            BigInteger crlNumber = nextCrlNumber(caSerialNumber);
            Instant thisUpdate = Instant.now();
            Instant nextUpdate = thisUpdate.plus(Duration.ofHours(deltaIntervalHours > 0 ? deltaIntervalHours : 1));

            X500Name issuer = new X500Name(caCert.getSubjectDN());
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, Date.from(thisUpdate));
            crlBuilder.setNextUpdate(Date.from(nextUpdate));

            // Filter certificates revoked or suspended after or at the base Full CRL's thisUpdate
            List<CertificateEntity> deltaRevokedCerts = certificateRepository.findAll().stream()
                    .filter(c -> caCert.getSubjectDN().equals(c.getIssuerDN()))
                    .filter(c -> "REVOKED".equalsIgnoreCase(c.getStatus()) || "SUSPENDED".equalsIgnoreCase(c.getStatus()))
                    .filter(c -> c.getRevocationDate() != null && !c.getRevocationDate().isBefore(baseFullCrl.getThisUpdate()))
                    .collect(Collectors.toList());

            for (CertificateEntity cert : deltaRevokedCerts) {
                BigInteger serial = new BigInteger(cert.getSerialNumber());
                Date revDate = cert.getRevocationDate() != null ? Date.from(cert.getRevocationDate()) : Date.from(thisUpdate);
                int reasonCode = mapReasonCode(cert.getStatus(), cert.getRevocationReason());
                crlBuilder.addCRLEntry(serial, revDate, reasonCode);
            }

            // Extensions
            crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(crlNumber));
            crlBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    x509ExtensionHelper != null ? x509ExtensionHelper.buildAki(caPublicKey) : certificateLifecycleService.buildAki(caPublicKey));
            crlBuilder.addExtension(Extension.deltaCRLIndicator, false, new CRLNumber(new BigInteger(baseFullCrl.getCrlNumber())));

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
            X509CRLHolder crlHolder = crlBuilder.build(signer);

            byte[] crlDer = crlHolder.getEncoded();
            String crlPem = serializationService.convertToPem(crlHolder);

            CrlEntity crlEntity = new CrlEntity();
            crlEntity.setCaSerialNumber(caSerialNumber);
            crlEntity.setCrlNumber(crlNumber.toString());
            crlEntity.setScope("DELTA");
            crlEntity.setBaseCrlNumber(baseFullCrl.getCrlNumber());
            crlEntity.setThisUpdate(thisUpdate);
            crlEntity.setNextUpdate(nextUpdate);
            crlEntity.setCrlPem(crlPem);
            crlEntity.setCrlDer(crlDer);
            crlEntity.setRevokedCount(deltaRevokedCerts.size());
            crlEntity.setCreatedAt(Instant.now());

            CrlEntity saved = crlRepository.save(crlEntity);

            auditService.log(username, "GENERATE_DELTA_CRL",
                    "Generated DELTA CRL #" + crlNumber + " (Base #" + baseFullCrl.getCrlNumber() + ") for CA: " + caSerialNumber + " with " + deltaRevokedCerts.size() + " entries",
                    "SUCCESS", "127.0.0.1");

            return saved;
        }
    }

    /**
     * Returns the latest CRL for the specified CA and scope (FULL or DELTA).
     */
    public CrlEntity getLatestCrl(String caSerialNumber, String scope) {
        List<CrlEntity> list = crlRepository.findByCaSerialNumberOrderByCrlNumberDesc(caSerialNumber).stream()
                .filter(c -> scope == null || scope.equalsIgnoreCase(c.getScope()))
                .collect(Collectors.toList());

        if (list.isEmpty()) {
            return null;
        }

        // Return highest numeric CRL number
        return list.stream()
                .max((a, b) -> {
                    try {
                        return new BigInteger(a.getCrlNumber()).compareTo(new BigInteger(b.getCrlNumber()));
                    } catch (Exception e) {
                        return a.getId().compareTo(b.getId());
                    }
                })
                .orElse(null);
    }

    /**
     * Maps certificate status and textual revocation reason to RFC 5280 CRLReason codes.
     */
    public int mapReasonCode(String status, String reason) {
        if ("SUSPENDED".equalsIgnoreCase(status)) {
            return CRLReason.certificateHold;
        }
        if (reason == null) {
            return CRLReason.unspecified;
        }
        String normalized = reason.toUpperCase().replaceAll("[_\\-\\s]", "");
        switch (normalized) {
            case "KEYCOMPROMISE":
                return CRLReason.keyCompromise;
            case "CACOMPROMISE":
                return CRLReason.cACompromise;
            case "AFFILIATIONCHANGED":
                return CRLReason.affiliationChanged;
            case "SUPERSEDED":
                return CRLReason.superseded;
            case "CESSATIONOFOPERATION":
                return CRLReason.cessationOfOperation;
            case "CERTIFICATEHOLD":
                return CRLReason.certificateHold;
            case "PRIVILEGEWITHDRAWN":
                return CRLReason.privilegeWithdrawn;
            case "AACOMPROMISE":
                return CRLReason.aACompromise;
            case "REMOVEFROMCRL":
                return CRLReason.removeFromCRL;
            case "UNSPECIFIED":
            default:
                return CRLReason.unspecified;
        }
    }
}
