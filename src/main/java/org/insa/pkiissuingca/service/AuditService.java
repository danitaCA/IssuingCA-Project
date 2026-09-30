package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.model.AuditLogEntity;
import org.insa.pkiissuingca.repository.AuditLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

@Service
public class AuditService {

    private static final Logger logger = LoggerFactory.getLogger(AuditService.class);
    public static final String GENESIS_SALT = "CA_GENESIS_SALT_2026_INIT";

    @Autowired
    private AuditLogRepository auditLogRepository;

    /**
     * Creates, links (by hash chain), and saves an append-only audit log entry.
     */
    @Transactional
    public AuditLogEntity log(String username, String action, String details, String status, String ipAddress) {
        AuditLogEntity entry = new AuditLogEntity();
        entry.setTimestamp(Instant.ofEpochMilli(System.currentTimeMillis()));
        entry.setUsername(username != null ? username : "SYSTEM");
        entry.setAction(action);
        entry.setDetails(details);
        entry.setStatus(status);
        entry.setIpAddress(ipAddress != null ? ipAddress : "127.0.0.1");

        // Calculate Chained Checksum to enforce immutable append-only record integrity
        try {
            Optional<AuditLogEntity> latestLog = auditLogRepository.findFirstByOrderByIdDesc();
            String prevChecksum = latestLog.map(AuditLogEntity::getChecksum).orElse(GENESIS_SALT);

            String checksum = computeChecksum(prevChecksum, entry);
            entry.setChecksum(checksum);
        } catch (Exception e) {
            logger.error("Failed to compute tamper-evident audit log checksum", e);
            entry.setChecksum("COMPUTE_ERROR");
        }

        AuditLogEntity saved = auditLogRepository.save(entry);

        // Structured output for Logstash / Fluentd / Splunk SIEM ingestion
        logger.info("[AUDIT_LOG] ID={}, Timestamp={}, User={}, Action={}, Status={}, IP={}, Checksum={}",
                saved.getId(), saved.getTimestamp(), saved.getUsername(), saved.getAction(),
                saved.getStatus(), saved.getIpAddress(), saved.getChecksum());

        return saved;
    }

    /**
     * Verifies the cryptographic integrity of the entire audit chain from genesis to head.
     * Returns true if valid, or detects tampered/altered records.
     */
    @Transactional(readOnly = true)
    public Map<String, Object> verifyAuditChainIntegrity() {
        List<AuditLogEntity> allLogs = auditLogRepository.findAll(Sort.by(Sort.Direction.ASC, "id"));

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("verifiedAt", Instant.now().toString());
        report.put("totalRecordsChecked", allLogs.size());

        if (allLogs.isEmpty()) {
            report.put("valid", true);
            report.put("message", "Audit log database is clean (no records to verify).");
            return report;
        }

        String currentExpectedPrevChecksum = GENESIS_SALT;

        for (int i = 0; i < allLogs.size(); i++) {
            AuditLogEntity log = allLogs.get(i);
            String computed = computeChecksum(currentExpectedPrevChecksum, log);

            if (!computed.equalsIgnoreCase(log.getChecksum())) {
                report.put("valid", false);
                report.put("message", "Tampering detected in audit chain!");
                report.put("tamperedRecordId", log.getId());
                report.put("recordIndex", i);
                report.put("expectedChecksum", computed);
                report.put("foundChecksum", log.getChecksum());
                report.put("tamperedTimestamp", log.getTimestamp() != null ? log.getTimestamp().toString() : "null");
                report.put("tamperedUser", log.getUsername());
                report.put("tamperedAction", log.getAction());
                return report;
            }
            currentExpectedPrevChecksum = log.getChecksum();
        }

        report.put("valid", true);
        report.put("message", "All audit log records verified cryptographically intact.");
        report.put("headChecksum", currentExpectedPrevChecksum);
        return report;
    }

    /**
     * Compute SHA-256 hash for a log entry given previous record checksum.
     */
    public String computeChecksum(String prevChecksum, AuditLogEntity entry) {
        try {
            long tsMillis = entry.getTimestamp() != null ? entry.getTimestamp().toEpochMilli() : 0L;
            String combinedString = (prevChecksum != null ? prevChecksum : GENESIS_SALT) +
                    tsMillis +
                    entry.getUsername() +
                    entry.getAction() +
                    (entry.getDetails() != null ? entry.getDetails() : "") +
                    entry.getStatus() +
                    (entry.getIpAddress() != null ? entry.getIpAddress() : "");

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(combinedString.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error computing checksum", e);
        }
    }

    /**
     * Retrieve paginated audit logs.
     */
    @Transactional(readOnly = true)
    public Page<AuditLogEntity> getAuditLogs(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "id"));
        return auditLogRepository.findAll(pageable);
    }

    /**
     * Export all audit logs formatted as SIEM JSON objects.
     */
    @Transactional(readOnly = true)
    public List<Map<String, Object>> exportSiemEvents() {
        List<AuditLogEntity> logs = auditLogRepository.findAll(Sort.by(Sort.Direction.DESC, "id"));
        List<Map<String, Object>> siemEvents = new ArrayList<>();

        for (AuditLogEntity log : logs) {
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("@version", "1");
            event.put("@timestamp", log.getTimestamp().toString());
            event.put("event_id", log.getId());
            event.put("event_source", "PKI_ISSUING_CA");
            event.put("user_name", log.getUsername());
            event.put("action", log.getAction());
            event.put("status", log.getStatus());
            event.put("client_ip", log.getIpAddress());
            event.put("details", log.getDetails());
            event.put("integrity_checksum", log.getChecksum());
            siemEvents.add(event);
        }
        return siemEvents;
    }
}
