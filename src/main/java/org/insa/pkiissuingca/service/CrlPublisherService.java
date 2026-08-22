package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.CrlEntity;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

@Service
public class CrlPublisherService {

    private static final Logger log = LoggerFactory.getLogger(CrlPublisherService.class);

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateLifecycleService certificateLifecycleService;

    @Autowired
    private CrlDirectoryPublisher crlDirectoryPublisher;

    @Autowired
    private AuditService auditService;

    @Value("${pki.crl.output-dir:./target/crl-output}")
    private String outputDir;

    /**
     * Publishes a CRL entity to local filesystem and LDAP directory services.
     */
    public void publish(CrlEntity crl) throws Exception {
        if (crl == null || crl.getCrlDer() == null) {
            throw new IllegalArgumentException("Cannot publish empty or null CRL");
        }

        CertificateEntity caCert = certificateRepository.findBySerialNumber(crl.getCaSerialNumber())
                .orElseThrow(() -> new IllegalArgumentException("CA certificate not found for serial: " + crl.getCaSerialNumber()));

        String rawCn = certificateLifecycleService.extractCn(caCert.getSubjectDN());
        String safeCn = sanitizeFileName(rawCn);

        // 1. Filesystem Publishing
        String fileName = "DELTA".equalsIgnoreCase(crl.getScope()) ? safeCn + "-delta.crl" : safeCn + ".crl";
        Path dirPath = Paths.get(outputDir);
        if (!Files.exists(dirPath)) {
            Files.createDirectories(dirPath);
        }

        Path targetPath = dirPath.resolve(fileName);
        Files.write(targetPath, crl.getCrlDer(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        log.info("Published CRL to filesystem: {} (Size: {} bytes)", targetPath.toAbsolutePath(), crl.getCrlDer().length);

        // 2. Directory (LDAP/AD) Publishing
        try {
            crlDirectoryPublisher.publish(crl, safeCn);
        } catch (Exception e) {
            log.error("Directory publishing failed for CA: " + safeCn + ", filesystem publish succeeded.", e);
            auditService.log("SYSTEM_PUBLISHER", "PUBLISH_CRL_DIRECTORY_FAILURE",
                    "Directory publish failed for CA: " + safeCn + " (" + e.getMessage() + ")", "FAILURE", "127.0.0.1");
        }

        auditService.log("SYSTEM_PUBLISHER", "PUBLISH_CRL",
                "Published " + crl.getScope() + " CRL #" + crl.getCrlNumber() + " for CA: " + safeCn + " to " + targetPath.toString(),
                "SUCCESS", "127.0.0.1");
    }

    private String sanitizeFileName(String name) {
        if (name == null || name.trim().isEmpty()) {
            return "ca";
        }
        return name.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}
