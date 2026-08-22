package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.KeyPairEntity;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class OcspServiceTest {

    private CryptoService cryptoService;
    private SerializationService serializationService;
    private CertificateLifecycleService lifecycleService;
    private CrlService crlService;
    private OcspService ocspService;
    private CertificateStatusCacheService cacheService;

    private CertificateRepository certificateRepository;
    private KeyPairRepository keyPairRepository;
    private CertificateProfileRepository profileRepository;
    private UserRepository userRepository;
    private AuditLogRepository auditLogRepository;
    private AuditService auditService;
    private CrlRepository crlRepository;

    private final List<CertificateEntity> certDb = new ArrayList<>();
    private final List<KeyPairEntity> keyPairDb = new ArrayList<>();

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

        cryptoService = new CryptoService();
        serializationService = new SerializationService();

        certificateRepository = Mockito.mock(CertificateRepository.class);
        keyPairRepository = Mockito.mock(KeyPairRepository.class);
        profileRepository = Mockito.mock(CertificateProfileRepository.class);
        userRepository = Mockito.mock(UserRepository.class);
        auditLogRepository = Mockito.mock(AuditLogRepository.class);
        crlRepository = Mockito.mock(CrlRepository.class);

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

        User adminUser = new User();
        adminUser.setId(1L);
        adminUser.setUsername("admin");
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(adminUser));
        when(userRepository.findByUsername("SYSTEM_OCSP")).thenReturn(Optional.of(adminUser));
        when(profileRepository.findByName(anyString())).thenReturn(Optional.empty());
        when(profileRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    private OCSPReq buildOcspRequest(X509Certificate issuerCert, BigInteger serialNumber) throws Exception {
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
    public void testOcspSignerIssuance() throws Exception {
        CertificateEntity rootCa = lifecycleService.initRootCa("CN=INSA Root CA, O=INSA, C=FR", "RSA", 2048, "RootCA", "admin");

        CertificateEntity ocspSigner = lifecycleService.issueOcspSignerCert(rootCa.getSerialNumber(), "admin");
        assertNotNull(ocspSigner);
        assertEquals("OCSP_SIGNER", ocspSigner.getCertificateType());
        assertTrue(ocspSigner.getSubjectDN().contains("OCSP Responder"));

        X509Certificate signerX509 = serializationService.parseCertificateFromPem(ocspSigner.getPemContent());
        X509CertificateHolder holder = new JcaX509CertificateHolder(signerX509);

        // Verify ExtendedKeyUsage has id-kp-OCSPSigning
        Extension ekuExt = holder.getExtension(Extension.extendedKeyUsage);
        assertNotNull(ekuExt);
        ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ekuExt.getParsedValue());
        assertTrue(eku.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning));

        // Verify OCSPNoCheck extension (OID 1.3.6.1.5.5.7.48.1.5)
        Extension noCheckExt = holder.getExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.5"));
        assertNotNull(noCheckExt);
    }

    @Test
    public void testOcspResponderQueryStatuses() throws Exception {
        CertificateEntity rootCa = lifecycleService.initRootCa("CN=INSA Root CA, O=INSA, C=FR", "RSA", 2048, "RootCA", "admin");
        X509Certificate caX509 = serializationService.parseCertificateFromPem(rootCa.getPemContent());

        // 1. Issue an OCSP Signer explicitly
        lifecycleService.issueOcspSignerCert(rootCa.getSerialNumber(), "admin");

        // 2. Set up test certificates in DB: GOOD, REVOKED, SUSPENDED
        CertificateEntity goodCert = new CertificateEntity();
        goodCert.setSerialNumber("3001");
        goodCert.setSubjectDN("CN=Good Client");
        goodCert.setIssuerDN(rootCa.getSubjectDN());
        goodCert.setStatus("ISSUED");
        goodCert.setPublicKeyPEM(rootCa.getPublicKeyPEM());
        goodCert.setPemContent(rootCa.getPemContent());
        goodCert.setCertificateType("END_ENTITY");
        goodCert.setProfileName("EndEntity");
        certDb.add(goodCert);

        CertificateEntity revokedCert = new CertificateEntity();
        revokedCert.setSerialNumber("3002");
        revokedCert.setSubjectDN("CN=Revoked Client");
        revokedCert.setIssuerDN(rootCa.getSubjectDN());
        revokedCert.setStatus("REVOKED");
        revokedCert.setRevocationReason("KEY_COMPROMISE");
        revokedCert.setRevocationDate(Instant.now().minusSeconds(100));
        revokedCert.setPublicKeyPEM(rootCa.getPublicKeyPEM());
        revokedCert.setPemContent(rootCa.getPemContent());
        revokedCert.setCertificateType("END_ENTITY");
        revokedCert.setProfileName("EndEntity");
        certDb.add(revokedCert);

        CertificateEntity suspendedCert = new CertificateEntity();
        suspendedCert.setSerialNumber("3003");
        suspendedCert.setSubjectDN("CN=Suspended Client");
        suspendedCert.setIssuerDN(rootCa.getSubjectDN());
        suspendedCert.setStatus("SUSPENDED");
        suspendedCert.setRevocationDate(Instant.now().minusSeconds(50));
        suspendedCert.setPublicKeyPEM(rootCa.getPublicKeyPEM());
        suspendedCert.setPemContent(rootCa.getPemContent());
        suspendedCert.setCertificateType("END_ENTITY");
        suspendedCert.setProfileName("EndEntity");
        certDb.add(suspendedCert);

        // 3. Test Query for GOOD certificate
        OCSPReq goodReq = buildOcspRequest(caX509, new BigInteger("3001"));
        byte[] goodRespBytes = ocspService.processOcspRequest(goodReq.getEncoded(), rootCa.getSerialNumber());
        OCSPResp goodResp = new OCSPResp(goodRespBytes);
        assertEquals(OCSPRespBuilder.SUCCESSFUL, goodResp.getStatus());
        BasicOCSPResp basicGoodResp = (BasicOCSPResp) goodResp.getResponseObject();
        SingleResp singleGood = basicGoodResp.getResponses()[0];
        assertEquals(CertificateStatus.GOOD, singleGood.getCertStatus());

        // 4. Test Query for REVOKED certificate
        OCSPReq revReq = buildOcspRequest(caX509, new BigInteger("3002"));
        byte[] revRespBytes = ocspService.processOcspRequest(revReq.getEncoded(), rootCa.getSerialNumber());
        OCSPResp revResp = new OCSPResp(revRespBytes);
        assertEquals(OCSPRespBuilder.SUCCESSFUL, revResp.getStatus());
        BasicOCSPResp basicRevResp = (BasicOCSPResp) revResp.getResponseObject();
        SingleResp singleRev = basicRevResp.getResponses()[0];
        assertTrue(singleRev.getCertStatus() instanceof RevokedStatus);

        // 5. Test Query for SUSPENDED certificate
        OCSPReq suspReq = buildOcspRequest(caX509, new BigInteger("3003"));
        byte[] suspRespBytes = ocspService.processOcspRequest(suspReq.getEncoded(), rootCa.getSerialNumber());
        OCSPResp suspResp = new OCSPResp(suspRespBytes);
        assertEquals(OCSPRespBuilder.SUCCESSFUL, suspResp.getStatus());
        BasicOCSPResp basicSuspResp = (BasicOCSPResp) suspResp.getResponseObject();
        SingleResp singleSusp = basicSuspResp.getResponses()[0];
        assertTrue(singleSusp.getCertStatus() instanceof RevokedStatus);

        // 6. Test Query for UNKNOWN certificate
        OCSPReq unkReq = buildOcspRequest(caX509, new BigInteger("999999"));
        byte[] unkRespBytes = ocspService.processOcspRequest(unkReq.getEncoded(), rootCa.getSerialNumber());
        OCSPResp unkResp = new OCSPResp(unkRespBytes);
        assertEquals(OCSPRespBuilder.SUCCESSFUL, unkResp.getStatus());
        BasicOCSPResp basicUnkResp = (BasicOCSPResp) unkResp.getResponseObject();
        SingleResp singleUnk = basicUnkResp.getResponses()[0];
        assertTrue(singleUnk.getCertStatus() instanceof UnknownStatus);
    }
}
