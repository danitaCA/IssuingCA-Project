package org.insa.pkiissuingca.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class SecurityRbacTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Public endpoints should be accessible without authentication")
    void testPublicEndpointsPermitAll() throws Exception {
        // Actuator health returns 200 or 503 depending on live external services (e.g. Redis), but is publicly accessible (not 401/403)
        mockMvc.perform(get("/actuator/health"))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    org.junit.jupiter.api.Assertions.assertTrue(status == 200 || status == 503,
                            "Expected 200 or 503 for accessible health endpoint but was: " + status);
                });

        mockMvc.perform(get("/api/v1/crl/non-existent-ca/latest"))
                .andExpect(status().isNotFound()); // 404 means it reached the controller past security
    }

    @Test
    @DisplayName("Protected CA Admin endpoints should return 401 Unauthorized for unauthenticated requests")
    void testUnauthenticatedAccessReturns401() throws Exception {
        mockMvc.perform(post("/api/v1/certificates/cas/root")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"subjectDN\":\"CN=Test\",\"keyType\":\"RSA\",\"keySizeOrCurve\":2048}"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/v1/audit/logs"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/v1/reports/certificates/pdf"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "endentity", roles = {"END_ENTITY"})
    @DisplayName("End Entity role should receive 403 Forbidden when attempting Root CA initialization")
    void testEndEntityForbiddenOnCaAdminOperations() throws Exception {
        mockMvc.perform(post("/api/v1/certificates/cas/root")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"subjectDN\":\"CN=UnauthorizedRoot\",\"keyType\":\"RSA\",\"keySizeOrCurve\":2048}"))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/v1/crl/some-ca/regenerate"))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/api/v1/audit/logs"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("Auditor role should have access to audit logs and reports but forbidden to issue certificates")
    void testAuditorAccessMatrix() throws Exception {
        mockMvc.perform(get("/api/v1/audit/logs"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/audit/verify-integrity"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/reports/certificates/pdf"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/pdf"));

        // Auditor must NOT be allowed to initialize Root CA
        mockMvc.perform(post("/api/v1/certificates/cas/root")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"subjectDN\":\"CN=UnauthorizedRoot\",\"keyType\":\"RSA\",\"keySizeOrCurve\":2048}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"CA_ADMIN"})
    @DisplayName("CA Admin role should have access to list certificates and audit logs")
    void testCaAdminAccess() throws Exception {
        mockMvc.perform(get("/api/v1/certificates"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/audit/logs"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Responses should enforce security headers (nosniff, frame options DENY)")
    void testSecurityHeadersEnforced() throws Exception {
        mockMvc.perform(get("/actuator/info"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"));
    }
}
