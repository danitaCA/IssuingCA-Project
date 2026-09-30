package org.insa.pkiissuingca.controller;

import org.insa.pkiissuingca.dto.*;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.service.CertificateLifecycleService;
import org.insa.pkiissuingca.service.SerializationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.security.cert.X509Certificate;
import java.util.List;

@RestController
@RequestMapping("/api/v1/certificates")
public class CertificateController {

    @Autowired
    private CertificateLifecycleService lifecycleService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private SerializationService serializationService;

    @PostMapping("/cas/root")
    @PreAuthorize("hasRole('CA_ADMIN') or hasRole('ROLE_CA_ADMIN')")
    public ResponseEntity<?> initRootCa(@RequestBody RootCaInitRequest request) {
        String username = getCurrentUsername();
        try {
            CertificateEntity rootCa = lifecycleService.initRootCa(
                    request.getSubjectDN(),
                    request.getKeyType(),
                    request.getKeySizeOrCurve(),
                    request.getProfileName() != null ? request.getProfileName() : "RootCA",
                    username
            );
            return ResponseEntity.ok(rootCa);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to initialize Root CA: " + e.getMessage());
        }
    }

    @PostMapping("/cas/intermediate")
    @PreAuthorize("hasRole('CA_ADMIN') or hasRole('ROLE_CA_ADMIN')")
    public ResponseEntity<?> initIntermediateCa(@RequestBody IntermediateCaInitRequest request) {
        String username = getCurrentUsername();
        try {
            CertificateEntity intermediateCa = lifecycleService.initIntermediateCa(
                    request.getSubjectDN(),
                    request.getParentSerialNumber(),
                    request.getKeyType(),
                    request.getKeySizeOrCurve(),
                    request.getProfileName() != null ? request.getProfileName() : "SubCA",
                    username
            );
            return ResponseEntity.ok(intermediateCa);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to initialize Intermediate CA: " + e.getMessage());
        }
    }

    @PostMapping("/cas/{caSerialNumber}/ocsp-signer")
    @PreAuthorize("hasRole('CA_ADMIN') or hasRole('ROLE_CA_ADMIN')")
    public ResponseEntity<?> issueOcspSigner(@PathVariable String caSerialNumber) {
        String username = getCurrentUsername();
        try {
            CertificateEntity ocspSigner = lifecycleService.issueOcspSignerCert(caSerialNumber, username);
            return ResponseEntity.ok(ocspSigner);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to issue OCSP Signer certificate: " + e.getMessage());
        }
    }

    @PostMapping("/sign")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN', 'RA_OPERATOR', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> signCsr(@RequestBody CsrSignRequest request) {
        String username = getCurrentUsername();
        try {
            CertificateEntity cert = lifecycleService.signCsr(
                    request.getCsrPem(),
                    request.getCaSerialNumber(),
                    request.getProfileName() != null ? request.getProfileName() : "EndEntity",
                    username
            );
            return ResponseEntity.ok(cert);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to sign CSR: " + e.getMessage());
        }
    }

    @PostMapping(value = {"/{serialNumber}/renew", "/{serialNumber}/renewed"})
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN', 'RA_OPERATOR', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> renewCertificate(@PathVariable String serialNumber) {
        String username = getCurrentUsername();
        try {
            CertificateEntity renewed = lifecycleService.renewCertificate(serialNumber, username);
            return ResponseEntity.ok(renewed);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to renew certificate: " + e.getMessage());
        }
    }

    @PostMapping(value = {"/{serialNumber}/suspend", "/{serialNumber}/suspended"})
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN', 'RA_OPERATOR', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> suspendCertificate(@PathVariable String serialNumber) {
        String username = getCurrentUsername();
        try {
            CertificateEntity suspended = lifecycleService.suspendCertificate(serialNumber, username);
            return ResponseEntity.ok(suspended);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to suspend certificate: " + e.getMessage());
        }
    }

    @PostMapping(value = {"/{serialNumber}/unsuspend", "/{serialNumber}/unsuspended"})
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN', 'RA_OPERATOR', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> unsuspendCertificate(@PathVariable String serialNumber) {
        String username = getCurrentUsername();
        try {
            CertificateEntity unsuspended = lifecycleService.unsuspendCertificate(serialNumber, username);
            return ResponseEntity.ok(unsuspended);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to unsuspend certificate: " + e.getMessage());
        }
    }

    @PostMapping(value = {"/{serialNumber}/revoke", "/{serialNumber}/revoked"})
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN', 'RA_OPERATOR', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> revokeCertificate(@PathVariable String serialNumber, @RequestBody(required = false) RevokeRequest request) {
        String username = getCurrentUsername();
        String reason = (request != null) ? request.getReason() : "UNSPECIFIED";
        try {
            CertificateEntity revoked = lifecycleService.revokeCertificate(serialNumber, reason, username);
            return ResponseEntity.ok(revoked);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to revoke certificate: " + e.getMessage());
        }
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN', 'RA_OPERATOR', 'ROLE_RA_OPERATOR', 'AUDITOR', 'ROLE_AUDITOR', 'SECURITY_OFFICER', 'ROLE_SECURITY_OFFICER')")
    public ResponseEntity<List<CertificateEntity>> listCertificates() {
        return ResponseEntity.ok(certificateRepository.findAll());
    }

    @GetMapping("/{serialNumber}")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN', 'RA_OPERATOR', 'ROLE_RA_OPERATOR', 'AUDITOR', 'ROLE_AUDITOR', 'SECURITY_OFFICER', 'ROLE_SECURITY_OFFICER', 'END_ENTITY', 'ROLE_END_ENTITY')")
    public ResponseEntity<?> getCertificate(@PathVariable String serialNumber) {
        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber).orElse(null);
        if (cert == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(cert);
    }

    @GetMapping("/{serialNumber}/pem")
    public ResponseEntity<String> getCertificatePem(@PathVariable String serialNumber) {
        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber).orElse(null);
        if (cert == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(cert.getPemContent());
    }

    @PostMapping("/cas/intermediate/csr")
    @PreAuthorize("hasRole('CA_ADMIN') or hasRole('ROLE_CA_ADMIN')")
    public ResponseEntity<?> generateSubCaCsr(@RequestBody SubCaCsrRequest request) {
        String username = getCurrentUsername();
        try {
            SubCaCsrResponse response = lifecycleService.generateSubCaCsr(request, username);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to generate Sub CA CSR: " + e.getMessage());
        }
    }

    @PostMapping("/cas/intermediate/import")
    @PreAuthorize("hasRole('CA_ADMIN') or hasRole('ROLE_CA_ADMIN')")
    public ResponseEntity<?> importSignedCaCert(@RequestBody ImportSignedCaCertRequest request) {
        String username = getCurrentUsername();
        try {
            CertificateEntity activatedCa = lifecycleService.importSignedCaCertificate(request, username);
            return ResponseEntity.ok(activatedCa);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to import and activate CA certificate: " + e.getMessage());
        }
    }

    @PostMapping("/enroll")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN', 'RA_OPERATOR', 'ROLE_RA_OPERATOR')")
    public ResponseEntity<?> enrollEndEntity(@RequestBody EndEntityEnrollRequest request) {
        String username = getCurrentUsername();
        try {
            EndEntityEnrollResponse response = lifecycleService.enrollEndEntity(request, username);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to enroll entity: " + e.getMessage());
        }
    }

    @GetMapping("/{serialNumber}/chain")
    public ResponseEntity<String> getCertificateChain(@PathVariable String serialNumber) {
        String chainPem = lifecycleService.getCertificateChainPem(serialNumber);
        if (chainPem == null || chainPem.trim().isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "application/x-pem-file")
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + serialNumber + "-chain.pem\"")
                .body(chainPem);
    }

    @GetMapping(value = "/{serialNumber}/der", produces = "application/x-x509-ca-cert")
    public ResponseEntity<byte[]> getCertificateDer(@PathVariable String serialNumber) {
        CertificateEntity cert = certificateRepository.findBySerialNumber(serialNumber).orElse(null);
        if (cert == null || cert.getPemContent() == null) {
            return ResponseEntity.notFound().build();
        }
        try {
            X509Certificate x509 = serializationService.parseCertificateFromPem(cert.getPemContent());
            byte[] der = x509.getEncoded();
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_TYPE, "application/x-x509-ca-cert")
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + serialNumber + ".der\"")
                    .body(der);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping(value = "/{serialNumber}/pkcs12", produces = "application/x-pkcs12")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN', 'RA_OPERATOR', 'ROLE_RA_OPERATOR', 'END_ENTITY', 'ROLE_END_ENTITY')")
    public ResponseEntity<byte[]> downloadPkcs12(
            @PathVariable String serialNumber,
            @RequestParam(required = false, defaultValue = "changeit") String password) {
        try {
            byte[] pfxBytes = lifecycleService.generatePkcs12ForCert(serialNumber, password);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_TYPE, "application/x-pkcs12")
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + serialNumber + ".p12\"")
                    .body(pfxBytes);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    private String getCurrentUsername() {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            return "admin";
        }
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal == null) {
            return "admin";
        }
        if (principal instanceof String) {
            return (String) principal;
        }
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails) {
            return ((org.springframework.security.core.userdetails.UserDetails) principal).getUsername();
        }
        return principal.toString();
    }
}
