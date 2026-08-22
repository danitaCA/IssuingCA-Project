package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.springframework.stereotype.Component;

import java.security.PublicKey;

@Component
public class X509ExtensionHelper {

    /**
     * Builds a standard SPKI SHA-1 based AuthorityKeyIdentifier.
     */
    public AuthorityKeyIdentifier buildAki(PublicKey caPublicKey) throws Exception {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(caPublicKey.getEncoded());
        DigestCalculator sha1Calc = new BcDigestCalculatorProvider()
                .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        return new X509ExtensionUtils(sha1Calc).createAuthorityKeyIdentifier(spki);
    }

    /**
     * Builds a standard SPKI SHA-1 based SubjectKeyIdentifier.
     */
    public SubjectKeyIdentifier buildSki(PublicKey publicKey) throws Exception {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        DigestCalculator sha1Calc = new BcDigestCalculatorProvider()
                .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        return new X509ExtensionUtils(sha1Calc).createSubjectKeyIdentifier(spki);
    }
}
