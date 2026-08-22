package org.insa.pkiissuingca.scheduler;

import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.CrlEntity;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.service.AuditService;
import org.insa.pkiissuingca.service.CrlPublisherService;
import org.insa.pkiissuingca.service.CrlService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.List;
import java.util.concurrent.TimeUnit;

@Configuration
@EnableScheduling
public class CrlSchedulerConfig {

    private static final Logger log = LoggerFactory.getLogger(CrlSchedulerConfig.class);

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CrlService crlService;

    @Autowired
    private CrlPublisherService crlPublisherService;

    @Autowired
    private AuditService auditService;

    /**
     * Periodic generation and publishing of Full CRLs for all active CAs.
     */
    @Scheduled(fixedRateString = "${pki.crl.full-interval-hours:24}", timeUnit = TimeUnit.HOURS, initialDelayString = "1")
    public void scheduleFullCrlGeneration() {
        log.info("Starting scheduled Full CRL generation for all active CAs...");
        List<CertificateEntity> caList = certificateRepository.findByCertificateTypeIn(List.of("ROOT", "INTERMEDIATE"));

        for (CertificateEntity ca : caList) {
            if (!"ISSUED".equalsIgnoreCase(ca.getStatus())) {
                continue;
            }
            try {
                log.info("Generating Full CRL for CA: {} (Serial: {})", ca.getSubjectDN(), ca.getSerialNumber());
                CrlEntity crl = crlService.generateFullCrl(ca.getSerialNumber(), "SYSTEM_SCHEDULER");
                crlPublisherService.publish(crl);
            } catch (Exception e) {
                log.error("Failed scheduled Full CRL generation for CA serial: " + ca.getSerialNumber(), e);
                auditService.log("SYSTEM_SCHEDULER", "SCHEDULED_FULL_CRL_FAILURE",
                        "Failed scheduled Full CRL for CA: " + ca.getSerialNumber() + " (" + e.getMessage() + ")",
                        "FAILURE", "127.0.0.1");
            }
        }
    }

    /**
     * Periodic generation and publishing of Delta CRLs for all active CAs.
     */
    @Scheduled(fixedRateString = "${pki.crl.delta-interval-hours:1}", timeUnit = TimeUnit.HOURS, initialDelayString = "1")
    public void scheduleDeltaCrlGeneration() {
        log.info("Starting scheduled Delta CRL generation for all active CAs...");
        List<CertificateEntity> caList = certificateRepository.findByCertificateTypeIn(List.of("ROOT", "INTERMEDIATE"));

        for (CertificateEntity ca : caList) {
            if (!"ISSUED".equalsIgnoreCase(ca.getStatus())) {
                continue;
            }
            try {
                log.info("Generating Delta CRL for CA: {} (Serial: {})", ca.getSubjectDN(), ca.getSerialNumber());
                CrlEntity crl = crlService.generateDeltaCrl(ca.getSerialNumber(), "SYSTEM_SCHEDULER");
                crlPublisherService.publish(crl);
            } catch (Exception e) {
                log.warn("Scheduled Delta CRL generation skipped/failed for CA: {} - {}", ca.getSerialNumber(), e.getMessage());
                auditService.log("SYSTEM_SCHEDULER", "SCHEDULED_DELTA_CRL_FAILURE",
                        "Failed scheduled Delta CRL for CA: " + ca.getSerialNumber() + " (" + e.getMessage() + ")",
                        "FAILURE", "127.0.0.1");
            }
        }
    }
}
