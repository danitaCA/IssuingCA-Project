package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.KeyPairEntity;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.AuditLogRepository;
import org.insa.pkiissuingca.repository.CertificateProfileRepository;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.repository.KeyPairRepository;
import org.insa.pkiissuingca.repository.UserRepository;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class AkiAndExtensionTest {

    private CryptoService cryptoService;
    private SerializationService serializationService;
    private CsrService csrService;
    private CertificateLifecycleService lifecycleService;

    private CertificateRepository certificateRepository;
    private KeyPairRepository keyPairRepository;
    private CertificateProfileRepository profileRepository;
    private UserRepository userRepository;
    private AuditLogRepository auditLogRepository;
    private AuditService auditService;
    private CertificateStatusCacheService cacheService;

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
        csrService = new CsrService();
        ReflectionTestUtils.setField(csrService, "serializationService", serializationService);

        certificateRepository = Mockito.mock(CertificateRepository.class);
        keyPairRepository = Mockito.mock(KeyPairRepository.class);
        profileRepository = Mockito.mock(CertificateProfileRepository.class);
        userRepository = Mockito.mock(UserRepository.class);
        auditLogRepository = Mockito.mock(AuditLogRepository.class);

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

        when(certificateRepository.findBySerialNumber(anyString())).thenAnswer(inv -> {
            String s = inv.getArgument(0);
            return certDb.stream().filter(c -> c.getSerialNumber().equals(s)).findFirst();
        });
        when(certificateRepository.findAll()).thenReturn(certDb);
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
        when(profileRepository.findByName(anyString())).thenReturn(Optional.empty());
        when(profileRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    public void testAkiAndSkiCalculation() throws Exception {
        KeyPair kp = cryptoService.generateRsaKeyPair(2048);

        AuthorityKeyIdentifier aki = lifecycleService.buildAki(kp.getPublic());
        assertNotNull(aki);
        assertNotNull(aki.getKeyIdentifier());
        assertEquals(20, aki.getKeyIdentifier().length); // SHA-1 is 20 bytes (160 bits)

        SubjectKeyIdentifier ski = lifecycleService.buildSki(kp.getPublic());
        assertNotNull(ski);
        assertNotNull(ski.getKeyIdentifier());
        assertEquals(20, ski.getKeyIdentifier().length);

        // For the same key, AKI keyIdentifier should match SKI keyIdentifier
        assertArrayEquals(ski.getKeyIdentifier(), aki.getKeyIdentifier());
    }

    @Test
    public void testCdpAndAiaExtensionsOnIssuedCert() throws Exception {
        CertificateEntity rootCa = lifecycleService.initRootCa("CN=INSA Root CA, O=INSA, C=FR", "RSA", 2048, "RootCA", "admin");

        KeyPair clientKp = cryptoService.generateRsaKeyPair(2048);
        String csrPem = csrService.generateCsr(clientKp, "CN=client.insa.fr, O=INSA", Collections.singletonList("DNS:client.insa.fr"), "SHA256withRSA");

        CertificateEntity endEntity = lifecycleService.signCsr(csrPem, rootCa.getSerialNumber(), "EndEntity", "admin");
        assertNotNull(endEntity);

        X509Certificate cert = serializationService.parseCertificateFromPem(endEntity.getPemContent());
        X509CertificateHolder holder = new JcaX509CertificateHolder(cert);

        // Check CRL Distribution Point (CDP)
        Extension cdpExt = holder.getExtension(Extension.cRLDistributionPoints);
        assertNotNull(cdpExt);
        CRLDistPoint cdp = CRLDistPoint.getInstance(cdpExt.getParsedValue());
        DistributionPoint[] dps = cdp.getDistributionPoints();
        assertEquals(1, dps.length);
        DistributionPointName dpName = dps[0].getDistributionPoint();
        GeneralNames generalNames = (GeneralNames) dpName.getName();
        String uri = generalNames.getNames()[0].getName().toString();
        assertTrue(uri.contains("/api/v1/crl/" + rootCa.getSerialNumber() + "/latest/der"));

        // Check Authority Information Access (AIA)
        Extension aiaExt = holder.getExtension(Extension.authorityInfoAccess);
        assertNotNull(aiaExt);
        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(aiaExt.getParsedValue());
        AccessDescription[] ads = aia.getAccessDescriptions();
        assertEquals(1, ads.length);
        assertEquals(AccessDescription.id_ad_ocsp, ads[0].getAccessMethod());
        String ocspUri = ads[0].getAccessLocation().getName().toString();
        assertTrue(ocspUri.contains("/api/v1/ocsp/" + rootCa.getSerialNumber()));
    }
}
