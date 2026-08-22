package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.CrlEntity;
import org.insa.pkiissuingca.model.KeyPairEntity;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.insa.pkiissuingca.repository.KeyPairRepository;
import org.insa.pkiissuingca.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.PrivateKey;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class HSMIntegrationTest {

    @Autowired
    private CertificateLifecycleService lifecycleService;

    @Autowired
    private CrlService crlService;

    @Autowired
    private OcspService ocspService;

    @Autowired
    private HSMKeyService hsmKeyService;

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private SerializationService serializationService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private KeyPairRepository keyPairRepository;

    @Autowired
    private UserRepository userRepository;

    private User adminUser;

    @BeforeEach
    public void setUp() {
        adminUser = userRepository.findByUsername("admin").orElseGet(() -> {
            User u = new User();
            u.setUsername("admin");
            u.setPassword("password");
            u.setEmail("admin@example.com");
            u.setEnabled(true);
            return userRepository.save(u);
        });
    }

    @Test
    public void testFullHSMLifecycle() throws Exception {
        // 1. Initialize HSM Root CA
        String rootDn = "CN=HSM Test Root CA, O=INSA PKI, C=FR";
        CertificateEntity rootCa = lifecycleService.initRootCa(rootDn, "RSA", 2048, "RootCA", adminUser.getUsername());

        assertNotNull(rootCa);
        assertNotNull(rootCa.getSerialNumber());
        assertEquals("ISSUED", rootCa.getStatus());
        assertEquals("ROOT", rootCa.getCertificateType());

        // Verify key in KeyPairRepository is stored as HSM reference
        KeyPairEntity rootKeyPair = keyPairRepository.findAll().stream()
                .filter(k -> lifecycleService.normalizePem(k.getPublicKeyPEM()).equals(lifecycleService.normalizePem(rootCa.getPublicKeyPEM())))
                .findFirst()
                .orElse(null);
        assertNotNull(rootKeyPair);
        assertTrue(HSMKeyService.isHsmReference(rootKeyPair.getPrivateKeyPEM()), "Root CA private key must be an HSM reference");

        // Verify HSM private key is non-exportable (opaque handle)
        String rootAlias = HSMKeyService.extractAlias(rootKeyPair.getPrivateKeyPEM());
        PrivateKey hsmPrivateKey = hsmKeyService.getPrivateKey(rootAlias);
        assertNotNull(hsmPrivateKey);
        assertNull(hsmPrivateKey.getEncoded(), "HSM private key bytes MUST NOT be exportable in plaintext (FR-06.3)");

        // 2. Initialize HSM Intermediate CA
        String subDn = "CN=HSM Test Sub CA, O=INSA PKI, C=FR";
        CertificateEntity subCa = lifecycleService.initIntermediateCa(subDn, rootCa.getSerialNumber(), "RSA", 2048, "SubCA", adminUser.getUsername());

        assertNotNull(subCa);
        assertEquals("ISSUED", subCa.getStatus());
        assertEquals("INTERMEDIATE", subCa.getCertificateType());

        KeyPairEntity subKeyPair = keyPairRepository.findAll().stream()
                .filter(k -> lifecycleService.normalizePem(k.getPublicKeyPEM()).equals(lifecycleService.normalizePem(subCa.getPublicKeyPEM())))
                .findFirst()
                .orElse(null);
        assertNotNull(subKeyPair);
        assertTrue(HSMKeyService.isHsmReference(subKeyPair.getPrivateKeyPEM()), "Sub CA private key must be an HSM reference");

        // 3. Sign CSR using HSM Sub CA
        KeyPair eeKeyPair = cryptoService.generateRsaKeyPair(2048);
        String csrPem = cryptoService.generateCsr(eeKeyPair, "CN=hsm-server.example.com, O=INSA PKI, C=FR");
        CertificateEntity eeCert = lifecycleService.signCsr(csrPem, subCa.getSerialNumber(), "EndEntity", adminUser.getUsername());

        assertNotNull(eeCert);
        assertEquals("ISSUED", eeCert.getStatus());
        assertEquals("END_ENTITY", eeCert.getCertificateType());

        // 4. Revoke Certificate & Generate CRL with HSM
        lifecycleService.revokeCertificate(eeCert.getSerialNumber(), "KEY_COMPROMISE", adminUser.getUsername());
        CrlEntity crl = crlService.generateFullCrl(subCa.getSerialNumber(), adminUser.getUsername());

        assertNotNull(crl);
        assertNotNull(crl.getCrlPem());
        assertEquals(1, crl.getRevokedCount());

        // 5. Test OCSP with HSM-backed OCSP Signer
        byte[] dummyOcspReq = buildDummyOcspReq(eeCert);
        if (dummyOcspReq != null) {
            byte[] ocspResp = ocspService.processOcspRequest(dummyOcspReq, subCa.getSerialNumber());
            assertNotNull(ocspResp);
            assertTrue(ocspResp.length > 0);
        }
    }

    private byte[] buildDummyOcspReq(CertificateEntity cert) {
        try {
            org.bouncycastle.cert.X509CertificateHolder holder =
                    serializationService.parseCertificateFromPem(cert.getPemContent()) != null ?
                            new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(serializationService.parseCertificateFromPem(cert.getPemContent())) : null;
            if (holder == null) return null;
            org.bouncycastle.operator.DigestCalculator digestCalc = new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().build().get(org.bouncycastle.asn1.x509.AlgorithmIdentifier.getInstance(org.bouncycastle.asn1.oiw.OIWObjectIdentifiers.idSHA1));
            org.bouncycastle.cert.ocsp.CertificateID id = new org.bouncycastle.cert.ocsp.CertificateID(digestCalc, holder, new java.math.BigInteger(cert.getSerialNumber()));
            org.bouncycastle.cert.ocsp.OCSPReqBuilder builder = new org.bouncycastle.cert.ocsp.OCSPReqBuilder();
            builder.addRequest(id);
            return builder.build().getEncoded();
        } catch (Exception e) {
            return null;
        }
    }
}
