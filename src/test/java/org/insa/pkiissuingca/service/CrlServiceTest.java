package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.insa.pkiissuingca.model.*;
import org.insa.pkiissuingca.repository.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Security;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

public class CrlServiceTest {

    private CryptoService cryptoService;
    private SerializationService serializationService;
    private CertificateLifecycleService lifecycleService;
    private CrlService crlService;
    private CrlPublisherService crlPublisherService;

    private CertificateRepository certificateRepository;
    private KeyPairRepository keyPairRepository;
    private CertificateProfileRepository profileRepository;
    private UserRepository userRepository;
    private AuditLogRepository auditLogRepository;
    private AuditService auditService;
    private CrlRepository crlRepository;
    private CertificateStatusCacheService cacheService;
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

        // Mock repo behaviors with in-memory DB lists
        when(certificateRepository.findBySerialNumber(anyString())).thenAnswer(inv -> {
            String s = inv.getArgument(0);
            return certDb.stream().filter(c -> c.getSerialNumber().equals(s)).findFirst();
        });
        when(certificateRepository.findAll()).thenReturn(certDb);
        when(certificateRepository.findBySubjectDN(anyString())).thenAnswer(inv -> {
            String dn = inv.getArgument(0);
            return certDb.stream().filter(c -> c.getSubjectDN().equals(dn)).toList();
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
        when(profileRepository.findByName(anyString())).thenReturn(Optional.empty());
        when(profileRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    public void testFullCrlGenerationAndStructure() throws Exception {
        // 1. Initialize Root CA
        CertificateEntity rootCa = lifecycleService.initRootCa("CN=INSA Root CA, O=INSA, C=FR", "RSA", 2048, "RootCA", "admin");
        assertNotNull(rootCa);

        // 2. Add revoked and suspended certificates to DB
        CertificateEntity cert1 = new CertificateEntity();
        cert1.setSerialNumber("1001");
        cert1.setSubjectDN("CN=Server 1, O=INSA");
        cert1.setIssuerDN(rootCa.getSubjectDN());
        cert1.setStatus("REVOKED");
        cert1.setRevocationReason("KEY_COMPROMISE");
        cert1.setRevocationDate(Instant.now().minusSeconds(3600));
        cert1.setPublicKeyPEM(rootCa.getPublicKeyPEM());
        cert1.setPemContent(rootCa.getPemContent());
        cert1.setCertificateType("END_ENTITY");
        cert1.setProfileName("EndEntity");
        certDb.add(cert1);

        CertificateEntity cert2 = new CertificateEntity();
        cert2.setSerialNumber("1002");
        cert2.setSubjectDN("CN=Server 2, O=INSA");
        cert2.setIssuerDN(rootCa.getSubjectDN());
        cert2.setStatus("SUSPENDED");
        cert2.setRevocationReason(null);
        cert2.setRevocationDate(Instant.now().minusSeconds(1800));
        cert2.setPublicKeyPEM(rootCa.getPublicKeyPEM());
        cert2.setPemContent(rootCa.getPemContent());
        cert2.setCertificateType("END_ENTITY");
        cert2.setProfileName("EndEntity");
        certDb.add(cert2);

        // 3. Generate Full CRL
        CrlEntity fullCrl = crlService.generateFullCrl(rootCa.getSerialNumber(), "admin");
        assertNotNull(fullCrl);
        assertEquals("1", fullCrl.getCrlNumber());
        assertEquals("FULL", fullCrl.getScope());
        assertEquals(2, fullCrl.getRevokedCount());
        assertNotNull(fullCrl.getCrlDer());
        assertTrue(fullCrl.getCrlPem().contains("BEGIN X509 CRL"));

        // 4. Parse CRL with Bouncy Castle and verify entries
        X509CRLHolder crlHolder = serializationService.parseCrlFromDer(fullCrl.getCrlDer());
        assertEquals(new org.bouncycastle.asn1.x500.X500Name(rootCa.getSubjectDN()), crlHolder.getIssuer());

        // Check CRL Number extension
        Extension crlNumExt = crlHolder.getExtension(Extension.cRLNumber);
        assertNotNull(crlNumExt);
        CRLNumber crlNumber = CRLNumber.getInstance(crlNumExt.getParsedValue());
        assertEquals(BigInteger.ONE, crlNumber.getCRLNumber());

        // Check Authority Key Identifier extension
        Extension akiExt = crlHolder.getExtension(Extension.authorityKeyIdentifier);
        assertNotNull(akiExt);

        // Verify revoked entries
        X509CRLEntryHolder entry1 = crlHolder.getRevokedCertificate(new BigInteger("1001"));
        assertNotNull(entry1);
        Extension reasonExt1 = entry1.getExtension(Extension.reasonCode);
        assertNotNull(reasonExt1);
        CRLReason reason1 = CRLReason.getInstance(reasonExt1.getParsedValue());
        assertEquals(CRLReason.keyCompromise, reason1.getValue().intValue());

        X509CRLEntryHolder entry2 = crlHolder.getRevokedCertificate(new BigInteger("1002"));
        assertNotNull(entry2);
        Extension reasonExt2 = entry2.getExtension(Extension.reasonCode);
        assertNotNull(reasonExt2);
        CRLReason reason2 = CRLReason.getInstance(reasonExt2.getParsedValue());
        assertEquals(CRLReason.certificateHold, reason2.getValue().intValue());
    }

    @Test
    public void testDeltaCrlGeneration() throws Exception {
        CertificateEntity rootCa = lifecycleService.initRootCa("CN=INSA Root CA, O=INSA, C=FR", "RSA", 2048, "RootCA", "admin");

        // Base revocation
        CertificateEntity cert1 = new CertificateEntity();
        cert1.setSerialNumber("2001");
        cert1.setSubjectDN("CN=Old Client, O=INSA");
        cert1.setIssuerDN(rootCa.getSubjectDN());
        cert1.setStatus("REVOKED");
        cert1.setRevocationReason("SUPERSEDED");
        cert1.setRevocationDate(Instant.now().minusSeconds(7200));
        cert1.setPublicKeyPEM(rootCa.getPublicKeyPEM());
        cert1.setPemContent(rootCa.getPemContent());
        cert1.setCertificateType("END_ENTITY");
        cert1.setProfileName("EndEntity");
        certDb.add(cert1);

        // Generate Full CRL #1
        CrlEntity baseFullCrl = crlService.generateFullCrl(rootCa.getSerialNumber(), "admin");
        assertEquals("1", baseFullCrl.getCrlNumber());

        // Add a new revocation after Full CRL generation
        CertificateEntity cert2 = new CertificateEntity();
        cert2.setSerialNumber("2002");
        cert2.setSubjectDN("CN=Recent Compromise, O=INSA");
        cert2.setIssuerDN(rootCa.getSubjectDN());
        cert2.setStatus("REVOKED");
        cert2.setRevocationReason("CA_COMPROMISE");
        cert2.setRevocationDate(Instant.now().plusSeconds(10));
        cert2.setPublicKeyPEM(rootCa.getPublicKeyPEM());
        cert2.setPemContent(rootCa.getPemContent());
        cert2.setCertificateType("END_ENTITY");
        cert2.setProfileName("EndEntity");
        certDb.add(cert2);

        // Generate Delta CRL
        CrlEntity deltaCrl = crlService.generateDeltaCrl(rootCa.getSerialNumber(), "admin");
        assertNotNull(deltaCrl);
        assertEquals("2", deltaCrl.getCrlNumber());
        assertEquals("DELTA", deltaCrl.getScope());
        assertEquals("1", deltaCrl.getBaseCrlNumber());
        assertEquals(1, deltaCrl.getRevokedCount());

        // Verify deltaCRLIndicator extension
        X509CRLHolder crlHolder = serializationService.parseCrlFromDer(deltaCrl.getCrlDer());
        Extension deltaIndExt = crlHolder.getExtension(Extension.deltaCRLIndicator);
        assertNotNull(deltaIndExt);
        CRLNumber baseCrlNum = CRLNumber.getInstance(deltaIndExt.getParsedValue());
        assertEquals(BigInteger.ONE, baseCrlNum.getCRLNumber());

        // Only cert 2002 should be in the delta CRL
        assertNotNull(crlHolder.getRevokedCertificate(new BigInteger("2002")));
    }

    @Test
    public void testCrlPublisherServiceFilesystem() throws Exception {
        CertificateEntity rootCa = lifecycleService.initRootCa("CN=INSA-Root-CA, O=INSA, C=FR", "RSA", 2048, "RootCA", "admin");
        CrlEntity fullCrl = crlService.generateFullCrl(rootCa.getSerialNumber(), "admin");

        crlPublisherService.publish(fullCrl);

        Path publishedFile = Path.of("./target/test-crl-output/INSA-Root-CA.crl");
        assertTrue(Files.exists(publishedFile));
        byte[] bytes = Files.readAllBytes(publishedFile);
        assertArrayEquals(fullCrl.getCrlDer(), bytes);
    }

    @Test
    public void concurrentFullCrlGeneration_producesDistinctCrlNumbers() throws Exception {
        CertificateEntity rootCa = lifecycleService.initRootCa("CN=INSA Concurrency CA, O=INSA, C=FR", "RSA", 2048, "RootCA", "admin");
        String caSerialNumber = rootCa.getSerialNumber();

        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(2);
        java.util.concurrent.CountDownLatch ready = new java.util.concurrent.CountDownLatch(2);
        java.util.concurrent.CountDownLatch go = new java.util.concurrent.CountDownLatch(1);

        java.util.concurrent.Callable<CrlEntity> task = () -> {
            ready.countDown();
            go.await();
            return crlService.generateFullCrl(caSerialNumber, "test-user");
        };

        java.util.concurrent.Future<CrlEntity> f1 = pool.submit(task);
        java.util.concurrent.Future<CrlEntity> f2 = pool.submit(task);
        ready.await();
        go.countDown();

        CrlEntity crl1 = f1.get();
        CrlEntity crl2 = f2.get();

        assertNotNull(crl1);
        assertNotNull(crl2);
        assertNotEquals(crl1.getCrlNumber(), crl2.getCrlNumber());
        pool.shutdown();
    }
}
