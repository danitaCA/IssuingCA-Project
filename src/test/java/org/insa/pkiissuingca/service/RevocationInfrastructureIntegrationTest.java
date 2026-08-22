package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.CrlEntity;
import org.insa.pkiissuingca.model.KeyPairEntity;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class RevocationInfrastructureIntegrationTest {

    private CryptoService cryptoService;
    private SerializationService serializationService;
    private CsrService csrService;
    private CertificateLifecycleService lifecycleService;
    private CrlService crlService;
    private CrlPublisherService crlPublisherService;
    private OcspService ocspService;
    private CertificateStatusCacheService cacheService;

    private CertificateRepository certificateRepository;
    private KeyPairRepository keyPairRepository;
    private CertificateProfileRepository profileRepository;
    private UserRepository userRepository;
    private AuditLogRepository auditLogRepository;
    private AuditService auditService;
    private CrlRepository crlRepository;
    private CrlDirectoryPublisher crlDirectoryPublisher;

    private final List<CertificateEntity> certDb = new ArrayList<>();
    private final List<KeyPairEntity> keyPairDb = new ArrayList<>();
    private final List<CrlEntity> crlDb = new ArrayList<>();

    @BeforeAll
    public static void initSecurity() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    public void setUp() {
        certDb.clear();
        keyPairDb.clear();
        crlDb.clear();

        cryptoService = new CryptoService();
        serializationService = new SerializationService();
        csrService = new CsrService();
        ReflectionTestUtils.setField(csrService, "serializationService", serializationService);

        certificateRepository = Mockito.mock(CertificateRepository.class);
        keyPairRepository = Mockito.mock(KeyPairRepository.class);
        profileRepository = Mockito.mock(CertificateProfileRepository.class);
        userRepository = Mockito.mock(UserRepository.class);
        auditLogRepository = Mockito.mock(AuditLogRepository.class);
        crlRepository = Mockito.mock(CrlRepository.class);
        crlDirectoryPublisher = Mockito.mock(CrlDirectoryPublisher.class);

        auditService = new AuditService();
        ReflectionTestUtils.setField(auditService, "auditLogRepository", auditLogRepository);
        when(auditLogRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        cacheService = new CertificateStatusCacheService();
        ReflectionTestUtils.setField(cacheService, "certificateRepository", certificateRepository);

        lifecycleService = new CertificateLifecycleService();
        ReflectionTestUtils.setField(lifecycleService, "certificateRepository", certificateRepository);
        ReflectionTestUtils.setField(lifecycleService, "keyPairRepository", keyPairRepository);
        ReflectionTestUtils.setField(lifecycleService, "profileRepository", profileRepository);
        ReflectionTestUtils.setField(lifecycleService, "userRepository", userRepository);
        ReflectionTestUtils.setField(lifecycleService, "cryptoService", cryptoService);
        ReflectionTestUtils.setField(lifecycleService, "serializationService", serializationService);
        ReflectionTestUtils.setField(lifecycleService, "csrService", csrService);
        ReflectionTestUtils.setField(lifecycleService, "auditService", auditService);
        ReflectionTestUtils.setField(lifecycleService, "certificateStatusCacheService", cacheService);
        ReflectionTestUtils.setField(lifecycleService, "baseUrl", "http://localhost:8080");

        crlService = new CrlService();
        ReflectionTestUtils.setField(crlService, "crlRepository", crlRepository);
        ReflectionTestUtils.setField(crlService, "certificateRepository", certificateRepository);
        ReflectionTestUtils.setField(crlService, "keyPairRepository", keyPairRepository);
        ReflectionTestUtils.setField(crlService, "certificateLifecycleService", lifecycleService);
        ReflectionTestUtils.setField(crlService, "serializationService", serializationService);
        ReflectionTestUtils.setField(crlService, "auditService", auditService);
        ReflectionTestUtils.setField(crlService, "fullIntervalHours", 24L);
        ReflectionTestUtils.setField(crlService, "deltaIntervalHours", 1L);

        crlPublisherService = new CrlPublisherService();
        ReflectionTestUtils.setField(crlPublisherService, "certificateRepository", certificateRepository);
        ReflectionTestUtils.setField(crlPublisherService, "certificateLifecycleService", lifecycleService);
        ReflectionTestUtils.setField(crlPublisherService, "crlDirectoryPublisher", crlDirectoryPublisher);
        ReflectionTestUtils.setField(crlPublisherService, "auditService", auditService);
        ReflectionTestUtils.setField(crlPublisherService, "outputDir", "./target/test-crl-output");

        ocspService = new OcspService();
        ReflectionTestUtils.setField(ocspService, "certificateRepository", certificateRepository);
        ReflectionTestUtils.setField(ocspService, "keyPairRepository", keyPairRepository);
        ReflectionTestUtils.setField(ocspService, "certificateLifecycleService", lifecycleService);
        ReflectionTestUtils.setField(ocspService, "certificateStatusCacheService", cacheService);
        ReflectionTestUtils.setField(ocspService, "serializationService", serializationService);
        ReflectionTestUtils.setField(ocspService, "crlService", crlService);
        ReflectionTestUtils.setField(ocspService, "auditService", auditService);

        when(certificateRepository.findBySerialNumber(anyString())).thenAnswer(inv -> {
            String s = inv.getArgument(0);
            return certDb.stream().filter(c -> c.getSerialNumber().equals(s)).findFirst();
        });
        when(certificateRepository.findAll()).thenReturn(certDb);
        when(certificateRepository.findBySubjectDN(anyString())).thenAnswer(inv -> {
            String dn = inv.getArgument(0);
            return certDb.stream().filter(c -> c.getSubjectDN().equals(dn)).toList();
        });
        when(certificateRepository.findByCertificateType(anyString())).thenAnswer(inv -> {
            String type = inv.getArgument(0);
            return certDb.stream().filter(c -> type.equals(c.getCertificateType())).toList();
        });
        when(certificateRepository.findByCertificateTypeIn(any())).thenAnswer(inv -> {
            List<String> types = inv.getArgument(0);
            return certDb.stream().filter(c -> types.contains(c.getCertificateType())).toList();
        });
        when(certificateRepository.save(any(CertificateEntity.class))).thenAnswer(inv -> {
            CertificateEntity c = inv.getArgument(0);
            if (c.getId() == null) c.setId((long) (certDb.size() + 1));
            certDb.removeIf(existing -> existing.getSerialNumber().equals(c.getSerialNumber()));
            certDb.add(c);
            return c;
        });

        when(keyPairRepository.findAll()).thenReturn(keyPairDb);
        when(keyPairRepository.save(any(KeyPairEntity.class))).thenAnswer(inv -> {
            KeyPairEntity kp = inv.getArgument(0);
            if (kp.getId() == null) kp.setId((long) (keyPairDb.size() + 1));
            keyPairDb.add(kp);
            return kp;
        });

        when(crlRepository.findByCaSerialNumberOrderByCrlNumberDesc(anyString())).thenAnswer(inv -> {
            String caSerial = inv.getArgument(0);
            return crlDb.stream()
                    .filter(c -> c.getCaSerialNumber().equals(caSerial))
                    .sorted((a, b) -> new BigInteger(b.getCrlNumber()).compareTo(new BigInteger(a.getCrlNumber())))
                    .toList();
        });
        when(crlRepository.findTopByCaSerialNumberAndScopeOrderByCrlNumberDesc(anyString(), anyString())).thenAnswer(inv -> {
            String caSerial = inv.getArgument(0);
            String scope = inv.getArgument(1);
            return crlDb.stream()
                    .filter(c -> c.getCaSerialNumber().equals(caSerial) && c.getScope().equalsIgnoreCase(scope))
                    .max((a, b) -> new BigInteger(a.getCrlNumber()).compareTo(new BigInteger(b.getCrlNumber())));
        });
        when(crlRepository.save(any(CrlEntity.class))).thenAnswer(inv -> {
            CrlEntity crl = inv.getArgument(0);
            if (crl.getId() == null) crl.setId((long) (crlDb.size() + 1));
            crlDb.add(crl);
            return crl;
        });

        User adminUser = new User();
        adminUser.setId(1L);
        adminUser.setUsername("admin");
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(adminUser));
        when(userRepository.findByUsername("SYSTEM_OCSP")).thenReturn(Optional.of(adminUser));
        when(profileRepository.findByName(anyString())).thenReturn(Optional.empty());
        when(profileRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    private OCSPReq createOcspRequest(X509Certificate issuerCert, BigInteger serialNumber) throws Exception {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        CertificateID certId = new JcaCertificateID(
                digCalcProv.get(CertificateID.HASH_SHA1),
                issuerCert,
                serialNumber
        );
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(certId);
        return builder.build();
    }

    @Test
    public void testEndToEndRevocationLifecycle() throws Exception {
        // 1. Initialize Root CA
        CertificateEntity rootCa = lifecycleService.initRootCa("CN=E2E Root CA, O=INSA PKI, C=FR", "RSA", 2048, "RootCA", "admin");
        assertNotNull(rootCa);
        X509Certificate caX509 = serializationService.parseCertificateFromPem(rootCa.getPemContent());

        // 2. Issue End-Entity Certificate via CSR
        KeyPair clientKp = cryptoService.generateRsaKeyPair(2048);
        String csrPem = csrService.generateCsr(clientKp, "CN=webapp.insa.fr, O=INSA", Collections.singletonList("DNS:webapp.insa.fr"), "SHA256withRSA");
        CertificateEntity endEntity = lifecycleService.signCsr(csrPem, rootCa.getSerialNumber(), "EndEntity", "admin");
        assertNotNull(endEntity);
        assertEquals("ISSUED", endEntity.getStatus());
        BigInteger certSerial = new BigInteger(endEntity.getSerialNumber());

        // 3. Query OCSP: Expect GOOD status
        OCSPReq ocspReq1 = createOcspRequest(caX509, certSerial);
        byte[] resp1Bytes = ocspService.processOcspRequest(ocspReq1.getEncoded(), rootCa.getSerialNumber());
        OCSPResp resp1 = new OCSPResp(resp1Bytes);
        assertEquals(OCSPRespBuilder.SUCCESSFUL, resp1.getStatus());
        BasicOCSPResp basicResp1 = (BasicOCSPResp) resp1.getResponseObject();
        assertEquals(CertificateStatus.GOOD, basicResp1.getResponses()[0].getCertStatus());

        // 4. Revoke Certificate
        CertificateEntity revoked = lifecycleService.revokeCertificate(endEntity.getSerialNumber(), "KEY_COMPROMISE", "admin");
        assertEquals("REVOKED", revoked.getStatus());

        // 5. Query OCSP immediately: Expect REVOKED status (cache was invalidated)
        OCSPReq ocspReq2 = createOcspRequest(caX509, certSerial);
        byte[] resp2Bytes = ocspService.processOcspRequest(ocspReq2.getEncoded(), rootCa.getSerialNumber());
        OCSPResp resp2 = new OCSPResp(resp2Bytes);
        assertEquals(OCSPRespBuilder.SUCCESSFUL, resp2.getStatus());
        BasicOCSPResp basicResp2 = (BasicOCSPResp) resp2.getResponseObject();
        assertTrue(basicResp2.getResponses()[0].getCertStatus() instanceof RevokedStatus);

        // 6. Generate Full CRL: Confirm revoked cert is present
        CrlEntity fullCrl = crlService.generateFullCrl(rootCa.getSerialNumber(), "admin");
        assertNotNull(fullCrl);
        assertEquals(1, fullCrl.getRevokedCount());

        X509CRLHolder crlHolder = serializationService.parseCrlFromDer(fullCrl.getCrlDer());
        X509CRLEntryHolder entry = crlHolder.getRevokedCertificate(certSerial);
        assertNotNull(entry);
        Extension reasonExt = entry.getExtension(Extension.reasonCode);
        assertNotNull(reasonExt);
        CRLReason crlReason = CRLReason.getInstance(reasonExt.getParsedValue());
        assertEquals(CRLReason.keyCompromise, crlReason.getValue().intValue());

        // 7. Publish CRL to filesystem
        crlPublisherService.publish(fullCrl);
    }
}
