package org.insa.pkiissuingca.controller;

import org.insa.pkiissuingca.model.AuditLogEntity;
import org.insa.pkiissuingca.service.AuditService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/audit")
public class AuditController {

    @Autowired
    private AuditService auditService;

    /**
     * Retrieve paginated audit logs. Accessible by AUDITOR, CA_ADMIN, SECURITY_OFFICER.
     */
    @GetMapping("/logs")
    @PreAuthorize("hasAnyRole('AUDITOR', 'ROLE_AUDITOR', 'CA_ADMIN', 'ROLE_CA_ADMIN', 'SECURITY_OFFICER', 'ROLE_SECURITY_OFFICER')")
    public ResponseEntity<Page<AuditLogEntity>> getAuditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(auditService.getAuditLogs(page, size));
    }

    /**
     * Cryptographically verify the tamper-evident hash chain of all audit log records.
     */
    @GetMapping("/verify-integrity")
    @PreAuthorize("hasAnyRole('AUDITOR', 'ROLE_AUDITOR', 'CA_ADMIN', 'ROLE_CA_ADMIN', 'SECURITY_OFFICER', 'ROLE_SECURITY_OFFICER')")
    public ResponseEntity<Map<String, Object>> verifyAuditChainIntegrity() {
        Map<String, Object> integrityReport = auditService.verifyAuditChainIntegrity();
        return ResponseEntity.ok(integrityReport);
    }

    /**
     * Export all audit log events in structured SIEM format for Logstash/Splunk/Elasticsearch.
     */
    @GetMapping("/export/siem")
    @PreAuthorize("hasAnyRole('AUDITOR', 'ROLE_AUDITOR', 'CA_ADMIN', 'ROLE_CA_ADMIN', 'SECURITY_OFFICER', 'ROLE_SECURITY_OFFICER')")
    public ResponseEntity<List<Map<String, Object>>> exportSiemEvents() {
        return ResponseEntity.ok(auditService.exportSiemEvents());
    }
}
