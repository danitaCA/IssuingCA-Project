import React, { useEffect, useState } from 'react';
import type { CertificateItem, CertificateProfile, SubCaCsrResponse, EndEntityEnrollResponse } from '../api/pkiApi';
import { pkiApi } from '../api/pkiApi';
import { CertificateViewerModal } from '../components/CertificateViewerModal';
import { 
  FileCheck2, 
  GitFork, 
  Plus, 
  Download, 
  CheckCircle2, 
  Copy, 
  Check, 
  Award, 
  KeyRound, 
  Layers, 
  ArrowRight, 
  Sparkles, 
  Lock, 
  UserPlus,
  RefreshCw,
  FileText,
  Eye,
  AlertCircle
} from 'lucide-react';

export const Operations: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'issuing_ca' | 'profiles' | 'ra_add_entity' | 'root_and_csr'>('issuing_ca');

  // Loaded data
  const [certs, setCerts] = useState<CertificateItem[]>([]);
  const [profiles, setProfiles] = useState<CertificateProfile[]>([]);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // Modal / Result states
  const [selectedCertForView, setSelectedCertForView] = useState<CertificateItem | null>(null);
  const [enrollmentResult, setEnrollmentResult] = useState<EndEntityEnrollResponse | null>(null);

  // ==========================================
  // STEP 1-5: ISSUING CA LIFECYCLE WORKFLOW STATE
  // ==========================================
  const [caStep, setCaStep] = useState<1 | 2 | 3 | 4 | 5>(1);

  // Step 1: Token & Key
  const [caKeyType, setCaKeyType] = useState('RSA');
  const [caKeySize, setCaKeySize] = useState(4096); // Default 4096 as required!

  // Step 2: Subject DN & Signature Algorithm
  const [caSigAlg, setCaSigAlg] = useState('SHA512withRSA'); // Default SHA-512 as required!
  const [caCommonName, setCaCommonName] = useState('INSA Enterprise Issuing CA v1');
  const [caOrg, setCaOrg] = useState('INSA PKI Trust Network');
  const [caCountry, setCaCountry] = useState('FR');
  const [caOrgUnit, setCaOrgUnit] = useState('Cryptographic Authority');
  const [caState, setCaState] = useState('IdF');
  const [caLocality, setCaLocality] = useState('Paris');

  // Step 3: Generated CSR Result
  const [generatedSubCaCsr, setGeneratedSubCaCsr] = useState<SubCaCsrResponse | null>(null);

  // Step 4: Root CA Signing
  const [selectedRootSerial, setSelectedRootSerial] = useState<string>('');
  const [rootSigningLoading, setRootSigningLoading] = useState(false);

  // Step 5: Import & Activation
  const [importCertPem, setImportCertPem] = useState<string>('');
  const [activatedCaCert, setActivatedCaCert] = useState<CertificateItem | null>(null);

  // ==========================================
  // PROFILE STATE
  // ==========================================
  const [profName, setProfName] = useState('EnterpriseEndEntity');
  const [profDesc, setProfDesc] = useState('Standard profile for corporate users & web servers with mandatory CRL/AIA');
  const [profValidityDays, setProfValidityDays] = useState(365);
  const [profSigAlg, setProfSigAlg] = useState('SHA512withRSA');
  const [profSelectedCaSerial, setProfSelectedCaSerial] = useState('');
  const [profTokenType, setProfTokenType] = useState<'ADVISED_GENERATED' | 'USER_GENERATED'>('ADVISED_GENERATED');
  const [profCdp, setProfCdp] = useState('http://localhost:8080/api/v1/crl/{CA_SERIAL}/latest/der');
  const [profOcsp, setProfOcsp] = useState('http://localhost:8080/api/v1/ocsp/{CA_SERIAL}');
  const [profKeyUsage, setProfKeyUsage] = useState('digitalSignature,keyEncipherment');
  const [profEku, setProfEku] = useState('serverAuth,clientAuth,emailProtection');

  // ==========================================
  // RA WEB: ADD END ENTITY STATE (Mandatory Algorithm Step)
  // ==========================================
  const [eeUsername, setEeUsername] = useState('john.doe');
  const [eeEmail, setEeEmail] = useState('john.doe@insa.fr');
  const [eeCommonName, setEeCommonName] = useState('john.doe.insa.fr');
  const [eeOrg, setEeOrg] = useState('INSA PKI Trust');
  const [eeCountry, setEeCountry] = useState('FR');
  const [eeOrgUnit, setEeOrgUnit] = useState('Engineering');
  const [eeState, setEeState] = useState('IdF');
  const [eeLocality, setEeLocality] = useState('Paris');
  const [eeProfileName, setEeProfileName] = useState('');
  const [eeCaSerial, setEeCaSerial] = useState('');
  const [eeKeyMode, setEeKeyMode] = useState<'ADVISED_GENERATED' | 'USER_GENERATED'>('ADVISED_GENERATED');
  const [eeKeyType, setEeKeyType] = useState<'RSA' | 'EC'>('RSA');
  const [eeKeySize, setEeKeySize] = useState(4096);
  const [eeAdminPassword, setEeAdminPassword] = useState('AdminKeyPass2026!'); // Set by admin in RA web
  const [eeCsrPem, setEeCsrPem] = useState('');
  const [eeSubmitting, setEeSubmitting] = useState(false);

  // ==========================================
  // ROOT CA INIT & FAST SIGN STATE
  // ==========================================
  const [rootCn, setRootCn] = useState('INSA Global Root CA');
  const [rootOrg, setRootOrg] = useState('INSA PKI Trust Network');
  const [rootCountry, setRootCountry] = useState('FR');
  const [rootKeySize, setRootKeySize] = useState(4096);
  const [fastCsrText, setFastCsrText] = useState('');
  const [fastCaSerial, setFastCaSerial] = useState('');

  const loadData = async () => {
    setLoading(true);
    try {
      const [certList, profList] = await Promise.all([
        pkiApi.listCertificates().catch(() => []),
        pkiApi.listProfiles().catch(() => []),
      ]);
      setCerts(certList);
      setProfiles(profList);

      // Select default active root CA for signing
      const root = certList.find(c => c.certificateType === 'ROOT' && c.status === 'ISSUED');
      if (root) setSelectedRootSerial(root.serialNumber);

      // Select default active issuing CA for profiles & RA
      const subCa = certList.find(c => c.certificateType === 'INTERMEDIATE' && c.status === 'ISSUED') || root;
      if (subCa) {
        setProfSelectedCaSerial(subCa.serialNumber);
        setEeCaSerial(subCa.serialNumber);
        setFastCaSerial(subCa.serialNumber);
      }

      if (profList.length > 0) {
        setEeProfileName(profList[0].name);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // ==========================================
  // 1. GENERATE SUB CA CSR (Algorithm Step 1, 2, 3)
  // ==========================================
  const handleGenerateSubCaCsr = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const rawCn = caCommonName.trim();
      let subjectDN = '';
      if (rawCn.includes('=') && rawCn.toUpperCase().includes('CN=')) {
        // User provided a full DN string like "CN=INSA Issuing Sub-CA, O=INSA, C=ET"
        subjectDN = rawCn;
      } else {
        // User provided standard form components
        const cleanCn = rawCn.replace(/^CN=/i, '').trim();
        subjectDN = `CN=${cleanCn}, O=${caOrg.trim()}, C=${caCountry.trim()}${caOrgUnit.trim() ? `, OU=${caOrgUnit.trim()}` : ''}${caState.trim() ? `, ST=${caState.trim()}` : ''}${caLocality.trim() ? `, L=${caLocality.trim()}` : ''}`;
      }

      const res = await pkiApi.generateSubCaCsr({
        subjectDN,
        keyType: caKeyType,
        keySizeOrCurve: caKeySize,
        signatureAlgorithm: caSigAlg,
      });
      setGeneratedSubCaCsr(res);
      setCaStep(3); // Move to Step 3: CSR Generated & Download PEM
    } catch (err: unknown) {
      alert((err as { response?: { data?: string } })?.response?.data || 'Failed to generate Sub CA CSR.');
    } finally {
      setLoading(false);
    }
  };

  // ==========================================
  // 2. ROOT CA SIGNS SUB CA CSR (Algorithm Step 4)
  // ==========================================
  const handleSignSubCaWithRoot = async () => {
    if (!generatedSubCaCsr) return;
    if (!selectedRootSerial) {
      alert('Please select a Root CA to sign the Sub CA CSR.');
      return;
    }
    setRootSigningLoading(true);
    try {
      const signedCert = await pkiApi.signCsr({
        csrPem: generatedSubCaCsr.csrPem,
        caSerialNumber: selectedRootSerial,
        profileName: 'SubCA',
      });
      setImportCertPem(signedCert.pemContent);
      setCaStep(5); // Move to Step 5: Import & Activate
      loadData();
    } catch (err: unknown) {
      alert((err as { response?: { data?: string } })?.response?.data || 'Failed to sign CSR with Root CA.');
    } finally {
      setRootSigningLoading(false);
    }
  };

  // ==========================================
  // 3. IMPORT SIGNED CA CERT & ACTIVATE (Algorithm Step 5)
  // ==========================================
  const handleImportAndActivateCa = async () => {
    if (!importCertPem || !importCertPem.includes('BEGIN CERTIFICATE')) {
      alert('Please provide a valid PEM certificate block.');
      return;
    }
    setLoading(true);
    try {
      const activated = await pkiApi.importSignedCaCert({
        caSerialNumber: generatedSubCaCsr?.serialNumber,
        signedCertPem: importCertPem,
      });
      setActivatedCaCert(activated);
      await loadData();
      alert(`Issuing CA "${caCommonName}" successfully activated! It is now ready to issue End Entity certificates.`);
    } catch (err: unknown) {
      alert((err as { response?: { data?: string } })?.response?.data || 'Failed to import signed CA certificate.');
    } finally {
      setLoading(false);
    }
  };

  // ==========================================
  // 4. CREATE / SAVE CERTIFICATE PROFILE
  // ==========================================
  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const cdpUrl = profCdp.replace('{CA_SERIAL}', profSelectedCaSerial || '1001');
      const ocspUrl = profOcsp.replace('{CA_SERIAL}', profSelectedCaSerial || '1001');

      await pkiApi.saveProfile({
        name: profName,
        description: profDesc,
        validityDays: profValidityDays,
        signatureAlgorithm: profSigAlg,
        caSerialNumber: profSelectedCaSerial,
        tokenType: profTokenType,
        crlDistributionPoint: cdpUrl,
        ocspUrl: ocspUrl,
        basicConstraints: false,
        keyUsage: profKeyUsage,
        extendedKeyUsage: profEku,
      });
      await loadData();
      alert(`Profile "${profName}" created and bound to Issuing CA!`);
      setActiveTab('ra_add_entity');
    } catch (err: unknown) {
      alert((err as { response?: { data?: string } })?.response?.data || 'Failed to save certificate profile.');
    } finally {
      setLoading(false);
    }
  };

  // ==========================================
  // 5. RA WEB: ADD ENTITY & MINT CERTIFICATE
  // ==========================================
  const handleEnrollEndEntity = async (e: React.FormEvent) => {
    e.preventDefault();
    setEeSubmitting(true);
    try {
      const res = await pkiApi.enrollEndEntity({
        username: eeUsername,
        email: eeEmail,
        commonName: eeCommonName,
        organization: eeOrg,
        country: eeCountry,
        orgUnit: eeOrgUnit,
        state: eeState,
        locality: eeLocality,
        profileName: eeProfileName || 'EnterpriseEndEntity',
        caSerialNumber: eeCaSerial,
        keyGenerationMode: eeKeyMode,
        keyType: eeKeyType,
        keySize: eeKeySize,
        adminPassword: eeAdminPassword,
        csrPem: eeKeyMode === 'USER_GENERATED' ? eeCsrPem : undefined,
      });
      setEnrollmentResult(res);
      await loadData();
    } catch (err: unknown) {
      alert((err as { response?: { data?: string } })?.response?.data || 'Failed to enroll entity.');
    } finally {
      setEeSubmitting(false);
    }
  };

  // ==========================================
  // 6. INITIALIZE ROOT CA
  // ==========================================
  const handleInitRootCa = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const rawRootCn = rootCn.trim();
      let subjectDN = '';
      if (rawRootCn.includes('=') && rawRootCn.toUpperCase().includes('CN=')) {
        subjectDN = rawRootCn;
      } else {
        const cleanCn = rawRootCn.replace(/^CN=/i, '').trim();
        subjectDN = `CN=${cleanCn}, O=${rootOrg.trim()}, C=${rootCountry.trim()}`;
      }

      const rootCert = await pkiApi.initRootCa({
        subjectDN,
        keyType: 'RSA',
        keySizeOrCurve: rootKeySize,
        profileName: 'RootCA',
      });
      await loadData();
      alert(`Root CA "${rootCn}" initialized with Serial: ${rootCert.serialNumber}`);
    } catch (err: unknown) {
      alert((err as { response?: { data?: string } })?.response?.data || 'Failed to initialize Root CA.');
    } finally {
      setLoading(false);
    }
  };

  const activeCAs = certs.filter(c => (c.certificateType === 'ROOT' || c.certificateType === 'INTERMEDIATE') && c.status === 'ISSUED');
  const activeRootCAs = certs.filter(c => c.certificateType === 'ROOT' && c.status === 'ISSUED');

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.025em', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <FileCheck2 className="w-6 h-6 text-emerald-400" style={{ color: '#34d399' }} />
            <span>Issuing CA Lifecycle & RA Operations Hub</span>
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            Complete Subordinate CA activation pipeline, policy profile creation, and RA end-entity enrollment.
          </p>
        </div>

        <button onClick={loadData} className="btn btn-secondary btn-sm" disabled={loading}>
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Main Tab Navigation */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px', overflowX: 'auto' }}>
        {[
          { id: 'issuing_ca', label: '1. Issuing CA Activation Wizard', icon: <GitFork className="w-4 h-4" /> },
          { id: 'profiles', label: '2. Certificate Profiles (CRL/AIA)', icon: <Layers className="w-4 h-4" /> },
          { id: 'ra_add_entity', label: '3. RA Web: Add Entity & Mint Key', icon: <UserPlus className="w-4 h-4" /> },
          { id: 'root_and_csr', label: '4. Root CA & Fast CSR Sign', icon: <Award className="w-4 h-4" /> },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as typeof activeTab)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '10px 18px',
              borderRadius: 'var(--radius-md)',
              fontSize: '0.875rem',
              fontWeight: activeTab === tab.id ? 700 : 500,
              color: activeTab === tab.id ? 'white' : 'var(--text-muted)',
              background: activeTab === tab.id ? 'var(--accent-gradient)' : 'rgba(255, 255, 255, 0.04)',
              border: activeTab === tab.id ? '1px solid rgba(255, 255, 255, 0.2)' : '1px solid var(--border-color)',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
              transition: 'all 0.15s ease',
            }}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* ========================================== */}
      {/* TAB 1: ISSUING CA ACTIVATION WIZARD (Exact User Algorithm) */}
      {/* ========================================== */}
      {activeTab === 'issuing_ca' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Algorithm Visual Steps Progress Bar */}
          <div className="glass-panel" style={{ padding: '16px 20px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '10px', alignItems: 'center' }}>
              {[
                { step: 1, title: 'Token & Key', desc: 'RSA 4096 default' },
                { step: 2, title: 'CA Details', desc: 'SHA-512 + Subject DN' },
                { step: 3, title: 'Generate CSR', desc: 'Download PEM' },
                { step: 4, title: 'Root CA Sign', desc: 'Sign with Root' },
                { step: 5, title: 'Activate CA', desc: 'Import & Activate' },
              ].map(s => {
                const isActive = caStep === s.step;
                const isDone = caStep > s.step;
                return (
                  <button
                    key={s.step}
                    onClick={() => setCaStep(s.step as typeof caStep)}
                    style={{
                      background: isDone ? 'rgba(16, 185, 129, 0.15)' : isActive ? 'rgba(99, 102, 241, 0.25)' : 'rgba(255, 255, 255, 0.03)',
                      border: isDone ? '1px solid #34d399' : isActive ? '1px solid var(--accent-primary)' : '1px solid var(--border-color)',
                      borderRadius: 'var(--radius-md)',
                      padding: '10px',
                      textAlign: 'left',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                    }}
                  >
                    <div style={{
                      width: '24px',
                      height: '24px',
                      borderRadius: '50%',
                      background: isDone ? '#34d399' : isActive ? 'var(--accent-primary)' : 'rgba(255,255,255,0.1)',
                      color: isDone ? '#0b0f19' : 'white',
                      fontSize: '0.75rem',
                      fontWeight: 800,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}>
                      {isDone ? <Check className="w-3.5 h-3.5" /> : s.step}
                    </div>
                    <div>
                      <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: isActive ? 'white' : 'var(--text-secondary)' }}>{s.title}</div>
                      <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>{s.desc}</div>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Form Step Body */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            {caStep <= 2 && (
              <form onSubmit={handleGenerateSubCaCsr} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
                  <div style={{ padding: '8px', background: 'rgba(99, 102, 241, 0.2)', borderRadius: 'var(--radius-md)' }}>
                    <KeyRound className="w-5 h-5 text-indigo-400" />
                  </div>
                  <div>
                    <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>Step 1 & 2: Subordinate Issuing CA Setup</h3>
                    <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                      Generate token/key (4096-bit default), select SHA-512 hashing, and configure Subject DN.
                    </p>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
                  {/* Token Key Type */}
                  <div className="form-group">
                    <label className="form-label">Asymmetric Key Type</label>
                    <select
                      value={caKeyType}
                      onChange={(e) => {
                        setCaKeyType(e.target.value);
                        if (e.target.value === 'RSA') setCaKeySize(4096);
                        else setCaKeySize(384);
                      }}
                      className="form-control"
                    >
                      <option value="RSA">RSA (Asymmetric Modulus)</option>
                      <option value="EC">ECDSA (Elliptic Curve)</option>
                      <option value="Ed25519">Ed25519 (Edwards Curve)</option>
                    </select>
                  </div>

                  {/* Token Key Size */}
                  <div className="form-group">
                    <label className="form-label">
                      Key Size — <strong style={{ color: '#38bdf8' }}>Default: 4096-bit</strong>
                    </label>
                    {caKeyType === 'RSA' ? (
                      <select
                        value={caKeySize}
                        onChange={(e) => setCaKeySize(Number(e.target.value))}
                        className="form-control"
                      >
                        <option value={4096}>RSA 4096-bit (Advised CA Standard / High Security)</option>
                        <option value={3072}>RSA 3072-bit (Enterprise Standard)</option>
                        <option value={2048}>RSA 2048-bit (Standard Minimum)</option>
                      </select>
                    ) : (
                      <select
                        value={caKeySize}
                        onChange={(e) => setCaKeySize(Number(e.target.value))}
                        className="form-control"
                      >
                        <option value={384}>NIST P-384 / secp384r1</option>
                        <option value={256}>NIST P-256 / secp256r1</option>
                        <option value={521}>NIST P-521 / secp521r1</option>
                      </select>
                    )}
                  </div>

                  {/* Signature / Hashing Algorithm */}
                  <div className="form-group">
                    <label className="form-label">
                      Signature Algorithm — <strong style={{ color: '#34d399' }}>Select SHA-512</strong>
                    </label>
                    <select
                      value={caSigAlg}
                      onChange={(e) => setCaSigAlg(e.target.value)}
                      className="form-control"
                    >
                      <option value="SHA512withRSA">SHA-512 with RSA (SHA512withRSA - Standard)</option>
                      <option value="SHA384withRSA">SHA-384 with RSA (SHA384withRSA)</option>
                      <option value="SHA256withRSA">SHA-256 with RSA (SHA256withRSA)</option>
                      <option value="SHA512withECDSA">SHA-512 with ECDSA</option>
                      <option value="SHA256withECDSA">SHA-256 with ECDSA</option>
                    </select>
                  </div>
                </div>

                {/* Subject DN Inputs */}
                <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
                  <h4 style={{ fontSize: '0.9375rem', fontWeight: 700, marginBottom: '12px', color: 'var(--text-primary)' }}>
                    Subject Distinguished Name (DN) Fields
                  </h4>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' }}>
                    <div className="form-group">
                      <label className="form-label">Common Name (CN) *</label>
                      <input
                        type="text"
                        required
                        value={caCommonName}
                        onChange={(e) => setCaCommonName(e.target.value)}
                        placeholder="e.g. INSA Enterprise Issuing CA v1"
                        className="form-control"
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Organization (O) *</label>
                      <input
                        type="text"
                        required
                        value={caOrg}
                        onChange={(e) => setCaOrg(e.target.value)}
                        placeholder="e.g. INSA PKI Trust"
                        className="form-control"
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Country (C - 2 Letters) *</label>
                      <input
                        type="text"
                        maxLength={2}
                        required
                        value={caCountry}
                        onChange={(e) => setCaCountry(e.target.value.toUpperCase())}
                        placeholder="e.g. FR"
                        className="form-control"
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Organizational Unit (OU)</label>
                      <input
                        type="text"
                        value={caOrgUnit}
                        onChange={(e) => setCaOrgUnit(e.target.value)}
                        placeholder="e.g. Security Operations"
                        className="form-control"
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">State / Province (ST)</label>
                      <input
                        type="text"
                        value={caState}
                        onChange={(e) => setCaState(e.target.value)}
                        placeholder="e.g. IdF"
                        className="form-control"
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Locality / City (L)</label>
                      <input
                        type="text"
                        value={caLocality}
                        onChange={(e) => setCaLocality(e.target.value)}
                        placeholder="e.g. Paris"
                        className="form-control"
                      />
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '12px' }}>
                  <button type="submit" disabled={loading} className="btn btn-primary">
                    <Sparkles className="w-4 h-4" />
                    <span>{loading ? 'Generating...' : 'Next: Generate Sub CA CSR'}</span>
                  </button>
                </div>
              </form>
            )}

            {caStep === 3 && generatedSubCaCsr && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
                  <div style={{ padding: '8px', background: 'rgba(56, 189, 248, 0.2)', borderRadius: 'var(--radius-md)' }}>
                    <Download className="w-5 h-5 text-sky-400" />
                  </div>
                  <div>
                    <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>Step 3: Download Sub CA CSR PEM</h3>
                    <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                      Sub CA CSR has been generated with RSA 4096 and SHA-512. Download or send to Root CA.
                    </p>
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '16px' }}>
                  <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Subject DN:</div>
                  <div className="font-mono" style={{ color: '#38bdf8', fontWeight: 600 }}>{generatedSubCaCsr.subjectDN}</div>
                </div>

                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>PKCS#10 Certificate Signing Request (PEM)</span>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button onClick={() => handleCopy(generatedSubCaCsr.csrPem)} className="btn btn-secondary btn-sm">
                        {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copied ? 'Copied' : 'Copy PEM'}</span>
                      </button>
                      <button
                        onClick={() => {
                          const blob = new Blob([generatedSubCaCsr.csrPem], { type: 'application/x-pem-file' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = `subca_${caCommonName.replace(/[^a-zA-Z0-9]/g, '_')}.csr`;
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                        className="btn btn-secondary btn-sm"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Download CSR (.pem)</span>
                      </button>
                    </div>
                  </div>
                  <pre className="font-mono" style={{
                    background: 'rgba(11, 15, 25, 0.9)',
                    border: '1px solid var(--border-color)',
                    borderRadius: 'var(--radius-md)',
                    padding: '14px',
                    fontSize: '0.75rem',
                    color: '#34d399',
                    maxHeight: '220px',
                    overflowY: 'auto',
                    whiteSpace: 'pre-wrap',
                  }}>
                    {generatedSubCaCsr.csrPem}
                  </pre>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '12px' }}>
                  <button onClick={() => setCaStep(2)} className="btn btn-secondary">Back to Edit</button>
                  <button onClick={() => setCaStep(4)} className="btn btn-primary">
                    <span>Next: Sign by Root CA</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}

            {caStep === 4 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
                  <div style={{ padding: '8px', background: 'rgba(168, 85, 247, 0.2)', borderRadius: 'var(--radius-md)' }}>
                    <Award className="w-5 h-5 text-purple-400" />
                  </div>
                  <div>
                    <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>Step 4: Sign Sub CA by Root CA</h3>
                    <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                      Select an existing Root CA to sign this Sub CA request, or sign with an external Root CA.
                    </p>
                  </div>
                </div>

                {activeRootCAs.length > 0 ? (
                  <div className="glass-card" style={{ padding: '18px' }}>
                    <h4 style={{ fontSize: '0.9375rem', fontWeight: 700, marginBottom: '12px', color: '#c084fc' }}>
                      Option A: 1-Click Sign with Internal Root CA
                    </h4>
                    <div className="form-group">
                      <label className="form-label">Select Active Root CA</label>
                      <select
                        value={selectedRootSerial}
                        onChange={(e) => setSelectedRootSerial(e.target.value)}
                        className="form-control"
                      >
                        {activeRootCAs.map(root => (
                          <option key={root.serialNumber} value={root.serialNumber}>
                            {root.subjectDN} (Serial: {root.serialNumber})
                          </option>
                        ))}
                      </select>
                    </div>

                    <button
                      onClick={handleSignSubCaWithRoot}
                      disabled={rootSigningLoading}
                      className="btn btn-primary"
                      style={{ marginTop: '8px' }}
                    >
                      <Award className="w-4 h-4" />
                      <span>{rootSigningLoading ? 'Signing with Root CA...' : 'Sign Sub CA CSR Now'}</span>
                    </button>
                  </div>
                ) : (
                  <div style={{ background: 'rgba(245, 158, 11, 0.15)', border: '1px solid rgba(245, 158, 11, 0.3)', padding: '14px', borderRadius: 'var(--radius-md)', color: '#fbbf24', fontSize: '0.875rem' }}>
                    <AlertCircle className="w-5 h-5 inline mr-2" />
                    No active Root CA found. Go to Tab 4 to initialize a Root CA, or proceed to Step 5 to import an externally signed certificate.
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '12px' }}>
                  <button onClick={() => setCaStep(3)} className="btn btn-secondary">Back to Download</button>
                  <button onClick={() => setCaStep(5)} className="btn btn-secondary">
                    <span>Proceed to Import Step 5</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}

            {caStep === 5 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
                  <div style={{ padding: '8px', background: 'rgba(16, 185, 129, 0.2)', borderRadius: 'var(--radius-md)' }}>
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  </div>
                  <div>
                    <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>Step 5: Edit CA / Import Signed CA Certificate & Activate</h3>
                    <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                      Import the Root-signed X.509 certificate to permanently activate the Sub CA for issuing End Entity certificates.
                    </p>
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Signed Sub CA Certificate (X.509 PEM)</label>
                  <textarea
                    rows={8}
                    value={importCertPem}
                    onChange={(e) => setImportCertPem(e.target.value)}
                    placeholder="-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----"
                    className="form-control font-mono"
                  />
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <button onClick={() => setCaStep(4)} className="btn btn-secondary">Back</button>
                  <button
                    onClick={handleImportAndActivateCa}
                    disabled={loading || !importCertPem.trim()}
                    className="btn btn-primary"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    <span>{loading ? 'Activating...' : 'Import & Activate Issuing CA'}</span>
                  </button>
                </div>

                {activatedCaCert && (
                  <div className="glass-card" style={{ padding: '18px', borderLeft: '4px solid #34d399', marginTop: '12px' }}>
                    <div style={{ fontSize: '0.875rem', fontWeight: 700, color: '#34d399', marginBottom: '6px' }}>
                      CA Activated Successfully!
                    </div>
                    <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                      Subject: <strong>{activatedCaCert.subjectDN}</strong> (Serial: {activatedCaCert.serialNumber})
                    </div>
                    <div style={{ marginTop: '12px', display: 'flex', gap: '8px' }}>
                      <button onClick={() => setActiveTab('profiles')} className="btn btn-primary btn-sm">
                        <span>Next: Create Profile & Bind</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================== */}
      {/* TAB 2: CERTIFICATE PROFILES (CRL & AIA Mandatory) */}
      {/* ========================================== */}
      {activeTab === 'profiles' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '20px' }}>
          {/* Create Profile Form */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px', marginBottom: '16px' }}>
              <div style={{ padding: '8px', background: 'rgba(99, 102, 241, 0.2)', borderRadius: 'var(--radius-md)' }}>
                <Layers className="w-5 h-5 text-indigo-400" />
              </div>
              <div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>Create Certificate Profile</h3>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                  Bind profile to active Issuing CA with mandatory CRL & AIA endpoints.
                </p>
              </div>
            </div>

            <form onSubmit={handleSaveProfile} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="form-group">
                <label className="form-label">Profile Name *</label>
                <input
                  type="text"
                  required
                  value={profName}
                  onChange={(e) => setProfName(e.target.value)}
                  placeholder="e.g. EnterpriseEndEntity"
                  className="form-control"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Description</label>
                <input
                  type="text"
                  value={profDesc}
                  onChange={(e) => setProfDesc(e.target.value)}
                  placeholder="e.g. High security profile with mandatory CRL"
                  className="form-control"
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Validity (Days)</label>
                  <input
                    type="number"
                    min={1}
                    value={profValidityDays}
                    onChange={(e) => setProfValidityDays(Number(e.target.value))}
                    className="form-control"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Signature Algorithm</label>
                  <select
                    value={profSigAlg}
                    onChange={(e) => setProfSigAlg(e.target.value)}
                    className="form-control"
                  >
                    <option value="SHA512withRSA">SHA512withRSA (SHA-512)</option>
                    <option value="SHA384withRSA">SHA384withRSA</option>
                    <option value="SHA256withRSA">SHA256withRSA</option>
                    <option value="SHA512withECDSA">SHA512withECDSA</option>
                  </select>
                </div>
              </div>

              {/* Choose Available CA (Mandatory) */}
              <div className="form-group">
                <label className="form-label">
                  Choose Available CA (Issuing CA) *
                </label>
                <select
                  value={profSelectedCaSerial}
                  onChange={(e) => setProfSelectedCaSerial(e.target.value)}
                  className="form-control"
                >
                  {activeCAs.map(ca => (
                    <option key={ca.serialNumber} value={ca.serialNumber}>
                      [{ca.certificateType}] {ca.subjectDN} (Serial: {ca.serialNumber})
                    </option>
                  ))}
                </select>
              </div>

              {/* Choose Available Token Mode */}
              <div className="form-group">
                <label className="form-label">
                  Available Token / Key Mode — <strong style={{ color: '#38bdf8' }}>Advised Generated</strong>
                </label>
                <select
                  value={profTokenType}
                  onChange={(e) => setProfTokenType(e.target.value as typeof profTokenType)}
                  className="form-control"
                >
                  <option value="ADVISED_GENERATED">Advised Generated (Server Generates Key Pair & Keystore)</option>
                  <option value="USER_GENERATED">User Generated (External PKCS#10 CSR Upload)</option>
                </select>
              </div>

              {/* Mandatory CRL Distribution Point */}
              <div className="form-group">
                <label className="form-label">
                  CRL Distribution Point (CDP) * <span style={{ color: '#f87171' }}>(Mandatory)</span>
                </label>
                <input
                  type="text"
                  required
                  value={profCdp}
                  onChange={(e) => setProfCdp(e.target.value)}
                  placeholder="http://localhost:8080/api/v1/crl/{CA_SERIAL}/latest/der"
                  className="form-control font-mono"
                  style={{ fontSize: '0.8125rem' }}
                />
              </div>

              {/* Authority Information Access (AIA / OCSP) */}
              <div className="form-group">
                <label className="form-label">
                  Authority Information Access (AIA / OCSP) * <span style={{ color: '#f87171' }}>(Mandatory)</span>
                </label>
                <input
                  type="text"
                  required
                  value={profOcsp}
                  onChange={(e) => setProfOcsp(e.target.value)}
                  placeholder="http://localhost:8080/api/v1/ocsp/{CA_SERIAL}"
                  className="form-control font-mono"
                  style={{ fontSize: '0.8125rem' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Key Usages</label>
                  <input
                    type="text"
                    value={profKeyUsage}
                    onChange={(e) => setProfKeyUsage(e.target.value)}
                    className="form-control font-mono"
                    style={{ fontSize: '0.75rem' }}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Extended Key Usages (EKU)</label>
                  <input
                    type="text"
                    value={profEku}
                    onChange={(e) => setProfEku(e.target.value)}
                    className="form-control font-mono"
                    style={{ fontSize: '0.75rem' }}
                  />
                </div>
              </div>

              <button type="submit" disabled={loading} className="btn btn-primary" style={{ marginTop: '8px' }}>
                <Plus className="w-4 h-4" />
                <span>Save Profile Policy</span>
              </button>
            </form>
          </div>

          {/* Existing Profiles Catalog */}
          <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>Registered Certificate Profiles</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', overflowY: 'auto', maxHeight: '560px' }}>
              {profiles.map(p => (
                <div key={p.id || p.name} className="glass-card" style={{ padding: '16px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                      <div style={{ fontWeight: 700, fontSize: '0.9375rem', color: '#f8fafc' }}>{p.name}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px' }}>{p.description || 'No description'}</div>
                    </div>
                    <span className="badge badge-intermediate">{p.validityDays} Days</span>
                  </div>
                  <div style={{ marginTop: '10px', fontSize: '0.75rem', display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-secondary)' }}>
                    <div>SigAlg: <strong>{p.signatureAlgorithm}</strong></div>
                    <div>Key Mode: <strong>{p.tokenType || 'ADVISED_GENERATED'}</strong></div>
                    {p.crlDistributionPoint && <div className="font-mono" style={{ color: 'var(--accent-secondary)', fontSize: '0.6875rem' }}>CDP: {p.crlDistributionPoint}</div>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ========================================== */}
      {/* TAB 3: RA WEB: ADD END ENTITY (The Mandatory Step) */}
      {/* ========================================== */}
      {activeTab === 'ra_add_entity' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: '20px' }}>
          {/* Add Entity Form */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px', marginBottom: '16px' }}>
              <div style={{ padding: '8px', background: 'rgba(20, 184, 166, 0.2)', borderRadius: 'var(--radius-md)' }}>
                <UserPlus className="w-5 h-5 text-teal-400" />
              </div>
              <div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>RA Web: Add Entity & Mint Certificate</h3>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                  Set admin password to securely bind with the private key and generate instant PKCS#12 bundle.
                </p>
              </div>
            </div>

            <form onSubmit={handleEnrollEndEntity} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {/* Identity Details */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Username / Entity ID *</label>
                  <input
                    type="text"
                    required
                    value={eeUsername}
                    onChange={(e) => setEeUsername(e.target.value)}
                    placeholder="e.g. john.doe"
                    className="form-control"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Email Address</label>
                  <input
                    type="email"
                    value={eeEmail}
                    onChange={(e) => setEeEmail(e.target.value)}
                    placeholder="e.g. john.doe@insa.fr"
                    className="form-control"
                  />
                </div>
              </div>

              {/* Subject DN fields */}
              <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Common Name (CN) *</label>
                  <input
                    type="text"
                    required
                    value={eeCommonName}
                    onChange={(e) => setEeCommonName(e.target.value)}
                    placeholder="e.g. john.doe.insa.fr or api.domain.com"
                    className="form-control"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Organization (O) *</label>
                  <input
                    type="text"
                    required
                    value={eeOrg}
                    onChange={(e) => setEeOrg(e.target.value)}
                    placeholder="e.g. INSA PKI Trust"
                    className="form-control"
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Country (C) *</label>
                  <input
                    type="text"
                    maxLength={2}
                    required
                    value={eeCountry}
                    onChange={(e) => setEeCountry(e.target.value.toUpperCase())}
                    className="form-control"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Department (OU)</label>
                  <input
                    type="text"
                    value={eeOrgUnit}
                    onChange={(e) => setEeOrgUnit(e.target.value)}
                    placeholder="e.g. IT"
                    className="form-control"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">State (ST)</label>
                  <input
                    type="text"
                    value={eeState}
                    onChange={(e) => setEeState(e.target.value)}
                    placeholder="e.g. IdF"
                    className="form-control"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Locality (L)</label>
                  <input
                    type="text"
                    value={eeLocality}
                    onChange={(e) => setEeLocality(e.target.value)}
                    placeholder="e.g. Paris"
                    className="form-control"
                  />
                </div>
              </div>

              {/* Certificate Profile Selection */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Certificate Profile *</label>
                  <select
                    value={eeProfileName}
                    onChange={(e) => setEeProfileName(e.target.value)}
                    className="form-control"
                  >
                    {profiles.map(p => (
                      <option key={p.id || p.name} value={p.name}>{p.name} ({p.validityDays} Days)</option>
                    ))}
                    {profiles.length === 0 && <option value="EnterpriseEndEntity">EnterpriseEndEntity</option>}
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Issuing CA Authority *</label>
                  <select
                    value={eeCaSerial}
                    onChange={(e) => setEeCaSerial(e.target.value)}
                    className="form-control"
                  >
                    {activeCAs.map(ca => (
                      <option key={ca.serialNumber} value={ca.serialNumber}>
                        [{ca.certificateType}] {ca.subjectDN}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Key Generation Mode */}
              <div className="form-group">
                <label className="form-label">
                  Key Generation Mode — <strong style={{ color: '#38bdf8' }}>Advised Generated</strong>
                </label>
                <select
                  value={eeKeyMode}
                  onChange={(e) => setEeKeyMode(e.target.value as typeof eeKeyMode)}
                  className="form-control"
                >
                  <option value="ADVISED_GENERATED">Advised Generated (Server Generates Key & PKCS#12 Keystore)</option>
                  <option value="USER_GENERATED">User Generated (External PKCS#10 CSR Input)</option>
                </select>
              </div>

              {eeKeyMode === 'ADVISED_GENERATED' ? (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
                  <div className="form-group">
                    <label className="form-label">Key Type</label>
                    <select
                      value={eeKeyType}
                      onChange={(e) => setEeKeyType(e.target.value as typeof eeKeyType)}
                      className="form-control"
                    >
                      <option value="RSA">RSA</option>
                      <option value="EC">ECDSA</option>
                    </select>
                  </div>

                  <div className="form-group">
                    <label className="form-label">Key Size</label>
                    <select
                      value={eeKeySize}
                      onChange={(e) => setEeKeySize(Number(e.target.value))}
                      className="form-control"
                    >
                      <option value={4096}>4096-bit (Maximum Security)</option>
                      <option value={2048}>2048-bit (Standard)</option>
                    </select>
                  </div>

                  {/* ADMIN PASSWORD (Required by User Instructions) */}
                  <div className="form-group">
                    <label className="form-label">
                      Admin Password to Bind with Key * <span style={{ color: '#fbbf24' }}>(Protects .p12 Keystore)</span>
                    </label>
                    <input
                      type="password"
                      required
                      value={eeAdminPassword}
                      onChange={(e) => setEeAdminPassword(e.target.value)}
                      placeholder="Password to encrypt PKCS#12 bundle"
                      className="form-control"
                    />
                  </div>
                </div>
              ) : (
                <div className="form-group">
                  <label className="form-label">Paste PKCS#10 CSR *</label>
                  <textarea
                    rows={4}
                    required
                    value={eeCsrPem}
                    onChange={(e) => setEeCsrPem(e.target.value)}
                    placeholder="-----BEGIN CERTIFICATE REQUEST-----..."
                    className="form-control font-mono"
                  />
                </div>
              )}

              <button type="submit" disabled={eeSubmitting} className="btn btn-primary" style={{ marginTop: '8px' }}>
                <CheckCircle2 className="w-4 h-4" />
                <span>{eeSubmitting ? 'Minting & Enrolling...' : 'Save Entity & Issue Certificate'}</span>
              </button>
            </form>
          </div>

          {/* Instant Download & View Certificate Panel */}
          <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Download className="w-5 h-5 text-emerald-400" />
              <span>Download & View Certificate</span>
            </h3>

            {enrollmentResult ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div className="glass-card" style={{ padding: '16px', borderLeft: '4px solid #34d399' }}>
                  <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#34d399' }}>
                    Certificate Minted Successfully!
                  </div>
                  <div className="font-mono" style={{ fontSize: '0.75rem', marginTop: '4px', color: 'var(--text-secondary)' }}>
                    Serial: #{enrollmentResult.certificate.serialNumber}
                  </div>
                  <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#f8fafc', marginTop: '2px' }}>
                    {enrollmentResult.certificate.subjectDN}
                  </div>
                </div>

                {/* Instant Download Actions */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <button
                    onClick={() => {
                      const blob = new Blob([enrollmentResult.certificatePem], { type: 'application/x-pem-file' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `${eeCommonName}_cert.pem`;
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="btn btn-secondary"
                    style={{ justifyContent: 'flex-start' }}
                  >
                    <Download className="w-4 h-4 text-sky-400" />
                    <span>Download Certificate (.pem / .crt)</span>
                  </button>

                  <button
                    onClick={() => {
                      const a = document.createElement('a');
                      a.href = `/api/v1/certificates/${enrollmentResult.certificate.serialNumber}/der`;
                      a.download = `${eeCommonName}.der`;
                      a.click();
                    }}
                    className="btn btn-secondary"
                    style={{ justifyContent: 'flex-start' }}
                  >
                    <Download className="w-4 h-4 text-teal-400" />
                    <span>Download Binary Certificate (.der)</span>
                  </button>

                  {enrollmentResult.pkcs12Base64 && (
                    <button
                      onClick={() => {
                        const byteChars = atob(enrollmentResult.pkcs12Base64!);
                        const byteNumbers = new Array(byteChars.length);
                        for (let i = 0; i < byteChars.length; i++) {
                          byteNumbers[i] = byteChars.charCodeAt(i);
                        }
                        const byteArray = new Uint8Array(byteNumbers);
                        const blob = new Blob([byteArray], { type: 'application/x-pkcs12' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `${eeCommonName}.p12`;
                        a.click();
                        URL.revokeObjectURL(url);
                      }}
                      className="btn btn-primary"
                      style={{ justifyContent: 'flex-start' }}
                    >
                      <Lock className="w-4 h-4" />
                      <span>Download PKCS#12 Keystore (.p12 / .pfx)</span>
                    </button>
                  )}

                  <button
                    onClick={() => {
                      const blob = new Blob([enrollmentResult.chainPem], { type: 'application/x-pem-file' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `${eeCommonName}_chain.pem`;
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="btn btn-secondary"
                    style={{ justifyContent: 'flex-start' }}
                  >
                    <GitFork className="w-4 h-4 text-purple-400" />
                    <span>Download Full Trust Chain (.pem)</span>
                  </button>

                  <button
                    onClick={() => setSelectedCertForView(enrollmentResult.certificate)}
                    className="btn btn-secondary"
                    style={{ justifyContent: 'flex-start', marginTop: '8px' }}
                  >
                    <Eye className="w-4 h-4 text-indigo-400" />
                    <span>Open in Full Interactive Certificate Viewer</span>
                  </button>
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
                <FileText className="w-12 h-12" style={{ margin: '0 auto 12px', opacity: 0.3 }} />
                <p style={{ fontSize: '0.875rem' }}>
                  Fill out the RA Add Entity form and click &quot;Save Entity &amp; Issue Certificate&quot; to generate download links and keystore bundle.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================== */}
      {/* TAB 4: ROOT CA PROVISIONING & FAST SIGN */}
      {/* ========================================== */}
      {activeTab === 'root_and_csr' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
          {/* Initialize Self-Signed Root CA */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px', marginBottom: '16px' }}>
              <div style={{ padding: '8px', background: 'rgba(168, 85, 247, 0.2)', borderRadius: 'var(--radius-md)' }}>
                <Award className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>Initialize Self-Signed Root CA</h3>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                  Deploy the top-level Trust Anchor with FIPS 140-3 Hardware Key.
                </p>
              </div>
            </div>

            <form onSubmit={handleInitRootCa} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="form-group">
                <label className="form-label">Root CA Common Name (CN) *</label>
                <input
                  type="text"
                  required
                  value={rootCn}
                  onChange={(e) => setRootCn(e.target.value)}
                  className="form-control"
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Organization (O)</label>
                  <input
                    type="text"
                    value={rootOrg}
                    onChange={(e) => setRootOrg(e.target.value)}
                    className="form-control"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Country (C)</label>
                  <input
                    type="text"
                    maxLength={2}
                    value={rootCountry}
                    onChange={(e) => setRootCountry(e.target.value.toUpperCase())}
                    className="form-control"
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Key Size</label>
                <select
                  value={rootKeySize}
                  onChange={(e) => setRootKeySize(Number(e.target.value))}
                  className="form-control"
                >
                  <option value={4096}>RSA 4096-bit (FIPS 140-3 Standard)</option>
                  <option value={3072}>RSA 3072-bit</option>
                  <option value={2048}>RSA 2048-bit</option>
                </select>
              </div>

              <button type="submit" disabled={loading} className="btn btn-primary" style={{ marginTop: '8px' }}>
                <Award className="w-4 h-4" />
                <span>Initialize Root CA</span>
              </button>
            </form>
          </div>

          {/* Fast CSR Signer */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px', marginBottom: '16px' }}>
              <div style={{ padding: '8px', background: 'rgba(56, 189, 248, 0.2)', borderRadius: 'var(--radius-md)' }}>
                <FileCheck2 className="w-5 h-5 text-sky-400" />
              </div>
              <div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>Direct CSR Signing Pipeline</h3>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                  Sign any incoming raw PKCS#10 byte string directly with an active CA.
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="form-group">
                <label className="form-label">Select Signing CA</label>
                <select
                  value={fastCaSerial}
                  onChange={(e) => setFastCaSerial(e.target.value)}
                  className="form-control"
                >
                  {activeCAs.map(ca => (
                    <option key={ca.serialNumber} value={ca.serialNumber}>
                      [{ca.certificateType}] {ca.subjectDN}
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Incoming PKCS#10 CSR PEM</label>
                <textarea
                  rows={6}
                  value={fastCsrText}
                  onChange={(e) => setFastCsrText(e.target.value)}
                  placeholder="-----BEGIN CERTIFICATE REQUEST-----..."
                  className="form-control font-mono"
                />
              </div>

              <button
                onClick={async () => {
                  if (!fastCsrText.trim()) return alert('Please enter CSR PEM.');
                  setLoading(true);
                  try {
                    const cert = await pkiApi.signCsr({
                      csrPem: fastCsrText,
                      caSerialNumber: fastCaSerial,
                      profileName: 'EnterpriseEndEntity',
                    });
                    setSelectedCertForView(cert);
                    await loadData();
                  } catch (err: unknown) {
                    alert((err as { response?: { data?: string } })?.response?.data || 'Failed to sign CSR.');
                  } finally {
                    setLoading(false);
                  }
                }}
                disabled={loading || !fastCsrText.trim()}
                className="btn btn-primary"
              >
                <Sparkles className="w-4 h-4" />
                <span>Sign & Issue Certificate</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Certificate Viewer Modal */}
      {selectedCertForView && (
        <CertificateViewerModal
          certificate={selectedCertForView}
          onClose={() => setSelectedCertForView(null)}
          onRefresh={loadData}
        />
      )}
    </div>
  );
};
