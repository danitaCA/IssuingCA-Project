package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.model.AuditLogEntity;
import org.insa.pkiissuingca.repository.AuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
public class AuditIntegrityAndSiemTest {

    @Autowired
    private AuditService auditService;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @BeforeEach
    void setup() {
        auditLogRepository.deleteAll();
    }

    @Test
    @DisplayName("Chained hash calculation should create a tamper-evident audit ledger")
    void testAuditHashChainCalculation() {
        AuditLogEntity log1 = auditService.log("admin", "INIT_CA", "Root CA initialized", "SUCCESS", "127.0.0.1");
        AuditLogEntity log2 = auditService.log("operator", "SIGN_CSR", "Signed cert for Alice", "SUCCESS", "192.168.1.10");
        AuditLogEntity log3 = auditService.log("operator", "REVOKE_CERT", "Revoked compromised key", "SUCCESS", "192.168.1.10");

        assertNotNull(log1.getChecksum());
        assertNotNull(log2.getChecksum());
        assertNotNull(log3.getChecksum());

        assertNotEquals(log1.getChecksum(), log2.getChecksum());
        assertNotEquals(log2.getChecksum(), log3.getChecksum());

        Map<String, Object> integrityReport = auditService.verifyAuditChainIntegrity();
        assertTrue((Boolean) integrityReport.get("valid"));
        assertEquals(3, integrityReport.get("totalRecordsChecked"));
    }

    @Test
    @DisplayName("Tampering with an audit record in the database should be detected by verifyAuditChainIntegrity")
    void testTamperDetection() {
        auditService.log("admin", "INIT_CA", "Root CA initialized", "SUCCESS", "127.0.0.1");
        AuditLogEntity log2 = auditService.log("operator", "SIGN_CSR", "Signed cert for Alice", "SUCCESS", "192.168.1.10");
        auditService.log("auditor", "EXPORT_REPORT", "Auditor exported report", "SUCCESS", "10.0.0.5");

        // Verify initial chain is intact
        Map<String, Object> initialReport = auditService.verifyAuditChainIntegrity();
        assertTrue((Boolean) initialReport.get("valid"));

        // Tamper with log2 details directly in DB without recalculating chained hashes
        log2.setDetails("HACKED / MODIFIED AUDIT LOG CONTENT");
        auditLogRepository.save(log2);

        // Chain verification must fail
        Map<String, Object> tamperedReport = auditService.verifyAuditChainIntegrity();
        assertFalse((Boolean) tamperedReport.get("valid"));
        assertEquals(log2.getId(), tamperedReport.get("tamperedRecordId"));
        assertTrue(tamperedReport.get("message").toString().contains("Tampering detected"));
    }

    @Test
    @DisplayName("SIEM Export format should contain all mandatory SIEM attributes")
    void testSiemExportFormat() {
        auditService.log("admin", "LOGIN", "CA Admin logged in", "SUCCESS", "192.168.1.100");
        auditService.log("secofficer", "GENERATE_KEYPAIR", "Generated RSA 4096 key", "SUCCESS", "192.168.1.101");

        List<Map<String, Object>> events = auditService.exportSiemEvents();
        assertFalse(events.isEmpty());
        assertEquals(2, events.size());

        Map<String, Object> firstEvent = events.get(0);
        assertTrue(firstEvent.containsKey("@timestamp"));
        assertTrue(firstEvent.containsKey("event_source"));
        assertEquals("PKI_ISSUING_CA", firstEvent.get("event_source"));
        assertTrue(firstEvent.containsKey("user_name"));
        assertTrue(firstEvent.containsKey("action"));
        assertTrue(firstEvent.containsKey("status"));
        assertTrue(firstEvent.containsKey("client_ip"));
        assertTrue(firstEvent.containsKey("integrity_checksum"));
    }
}
