package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.insa.pkiissuingca.dto.CertificateStatusDto;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.KeyPairEntity;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.repository.KeyPairRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class OcspService {

    private static final Logger log = LoggerFactory.getLogger(OcspService.class);

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private KeyPairRepository keyPairRepository;

    @Autowired
    private CertificateLifecycleService certificateLifecycleService;

    @Autowired
    private CertificateStatusCacheService certificateStatusCacheService;

    @Autowired
    private SerializationService serializationService;

    @Autowired
    private CrlService crlService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private HSMKeyService hsmKeyService;

    /**
     * Processes an incoming RFC 6960 binary OCSP request for a specified issuing CA.
     *
     * @param requestBytes   Raw binary DER-encoded OCSPReq
     * @param caSerialNumber Serial number of the CA that issued the target certificate(s)
     * @return Raw binary DER-encoded OCSPResp
     */
    public byte[] processOcspRequest(byte[] requestBytes, String caSerialNumber) {
        if (requestBytes == null || requestBytes.length == 0) {
            log.warn("Malformed empty OCSP request received for CA: {}", caSerialNumber);
            return buildErrorResponse(OCSPRespBuilder.MALFORMED_REQUEST);
        }

        OCSPReq ocspReq;
        try {
            ocspReq = new OCSPReq(requestBytes);
        } catch (Exception e) {
            log.error("Failed to parse binary OCSP request: " + e.getMessage(), e);
            return buildErrorResponse(OCSPRespBuilder.MALFORMED_REQUEST);
        }

        CertificateEntity caCertEntity = certificateRepository.findBySerialNumber(caSerialNumber).orElse(null);
        if (caCertEntity == null || !"ISSUED".equalsIgnoreCase(caCertEntity.getStatus())) {
            log.warn("OCSP request rejected: issuing CA serial {} not found or inactive", caSerialNumber);
            return buildErrorResponse(OCSPRespBuilder.UNAUTHORIZED);
        }

        try {
            // Find or provision dedicated OCSP signer certificate for this CA
            CertificateEntity ocspSignerCertEntity = findOrCreateOcspSignerCert(caCertEntity);
            KeyPairEntity signerKeyPairEntity = keyPairRepository.findAll().stream()
                    .filter(k -> certificateLifecycleService.normalizePem(k.getPublicKeyPEM()).equals(
                            certificateLifecycleService.normalizePem(ocspSignerCertEntity.getPublicKeyPEM())))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("OCSP Signer private key not found in storage."));

            PrivateKey signerPrivateKey;
            boolean signerInHsm = HSMKeyService.isHsmReference(signerKeyPairEntity.getPrivateKeyPEM());
            if (signerInHsm) {
                String signerAlias = HSMKeyService.extractAlias(signerKeyPairEntity.getPrivateKeyPEM());
                signerPrivateKey = hsmKeyService.getPrivateKey(signerAlias);
            } else {
                signerPrivateKey = serializationService.parsePrivateKeyFromPem(signerKeyPairEntity.getPrivateKeyPEM());
            }
            X509Certificate signerX509 = serializationService.parseCertificateFromPem(ocspSignerCertEntity.getPemContent());
            X509CertificateHolder signerCertHolder = new JcaX509CertificateHolder(signerX509);

            // Initialize BasicOCSPRespBuilder with Signer's Subject
            BasicOCSPRespBuilder respBuilder = new BasicOCSPRespBuilder(new RespID(signerCertHolder.getSubject()));

            // Handle Nonce extension if present in client request
            Extension nonceExt = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (nonceExt != null) {
                respBuilder.setResponseExtensions(new Extensions(nonceExt));
            }

            Date now = new Date();
            Date nextUpdate = new Date(now.getTime() + 1000L * 60 * 60 * 24); // 24 hours validity

            Req[] requests = ocspReq.getRequestList();
            for (Req req : requests) {
                CertificateID certId = req.getCertID();
                BigInteger targetSerial = certId.getSerialNumber();

                CertificateStatusDto statusDto = certificateStatusCacheService.getCertificateStatus(targetSerial.toString());
                CertificateStatus ocspStatus;

                if (statusDto == null) {
                    ocspStatus = new UnknownStatus();
                } else if ("ISSUED".equalsIgnoreCase(statusDto.getStatus())) {
                    ocspStatus = CertificateStatus.GOOD;
                } else if ("REVOKED".equalsIgnoreCase(statusDto.getStatus())) {
                    Date revDate = statusDto.getRevocationDate() != null ? Date.from(statusDto.getRevocationDate()) : now;
                    int reason = crlService.mapReasonCode(statusDto.getStatus(), statusDto.getRevocationReason());
                    ocspStatus = new RevokedStatus(revDate, reason);
                } else if ("SUSPENDED".equalsIgnoreCase(statusDto.getStatus())) {
                    Date revDate = statusDto.getRevocationDate() != null ? Date.from(statusDto.getRevocationDate()) : now;
                    ocspStatus = new RevokedStatus(revDate, CRLReason.certificateHold);
                } else {
                    ocspStatus = new UnknownStatus();
                }

                respBuilder.addResponse(certId, ocspStatus, now, nextUpdate, null);
            }

            // Sign BasicOCSPResp with dedicated OCSP signer private key
            String sigAlg = "SHA256withRSA";
            if (signerKeyPairEntity.getAlgorithm().equalsIgnoreCase("EC")) {
                sigAlg = "SHA256withECDSA";
            } else if (signerKeyPairEntity.getAlgorithm().equalsIgnoreCase("Ed25519")) {
                sigAlg = "Ed25519";
            }

            ContentSigner signer;
            if (signerInHsm) {
                signer = new JcaContentSignerBuilder(sigAlg).setProvider(hsmKeyService.getProvider()).build(signerPrivateKey);
            } else {
                signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(signerPrivateKey);
            }
            BasicOCSPResp basicResp = respBuilder.build(signer, new X509CertificateHolder[]{signerCertHolder}, now);

            OCSPResp ocspResponse = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp);

            auditService.log("OCSP_CLIENT", "OCSP_TRANSACTION",
                    "Processed OCSP query for CA " + caSerialNumber + " (" + requests.length + " cert checks)",
                    "SUCCESS", "127.0.0.1");

            return ocspResponse.getEncoded();
        } catch (Exception e) {
            log.error("Internal error processing OCSP request for CA " + caSerialNumber, e);
            return buildErrorResponse(OCSPRespBuilder.INTERNAL_ERROR);
        }
    }

    private CertificateEntity findOrCreateOcspSignerCert(CertificateEntity caCert) throws Exception {
        List<CertificateEntity> signers = certificateRepository.findByCertificateType("OCSP_SIGNER").stream()
                .filter(c -> caCert.getSubjectDN().equals(c.getIssuerDN()))
                .filter(c -> "ISSUED".equalsIgnoreCase(c.getStatus()))
                .collect(Collectors.toList());

        if (!signers.isEmpty()) {
            return signers.get(signers.size() - 1);
        }

        // Auto-provision an OCSP signer certificate for this CA
        log.info("No active OCSP signer cert found for CA: {}. Auto-issuing dedicated signer...", caCert.getSubjectDN());
        return certificateLifecycleService.issueOcspSignerCert(caCert.getSerialNumber(), "SYSTEM_OCSP");
    }

    private byte[] buildErrorResponse(int status) {
        try {
            return new OCSPRespBuilder().build(status, null).getEncoded();
        } catch (Exception e) {
            log.error("Failed to build error OCSP response with status: " + status, e);
            return new byte[0];
        }
    }
}
