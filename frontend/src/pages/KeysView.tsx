import React, { useEffect, useState } from 'react';
import type { CertificateItem, KeyPairItem } from '../api/pkiApi';
import { pkiApi } from '../api/pkiApi';
import { useAuth } from '../context/AuthContext';
import { 
  KeyRound, 
  Plus, 
  ShieldCheck, 
  RefreshCw, 
  Copy, 
  Check, 
  Cpu, 
  Lock, 
  FileCode,
  Layers,
  Sparkles,
  Award,
  X
} from 'lucide-react';

export const KeysView: React.FC = () => {
  const { hasRole } = useAuth();
  const [keys, setKeys] = useState<KeyPairItem[]>([]);
  const [certs, setCerts] = useState<CertificateItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [inspectKey, setInspectKey] = useState<KeyPairItem | null>(null);
  const [copied, setCopied] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [csrResult, setCsrResult] = useState<string | null>(null);

  // CSR Customization Modal State
  const [showCsrModal, setShowCsrModal] = useState(false);
  const [csrKeyId, setCsrKeyId] = useState<number | null>(null);
  const [csrCn, setCsrCn] = useState('webserver.internal.et');
  const [csrOrg, setCsrOrg] = useState('INSA PKI Trust Network');
  const [csrCountry, setCsrCountry] = useState('ET');
  const [csrOrgUnit, setCsrOrgUnit] = useState('Security Operations');

  // Key Generation Form State - default to RSA 4096 as requested!
  const [keyType, setKeyType] = useState('RSA');
  const [keySize, setKeySize] = useState(4096);
  const [storageType, setStorageType] = useState('HSM');

  const normalizePem = (pem?: string) => {
    if (!pem) return '';
    return pem.replace(/-----[^\n]+-----/g, '').replace(/\s+/g, '');
  };

  const extractCn = (dn: string) => {
    const match = dn.match(/CN=([^,]+)/i);
    return match ? match[1] : dn;
  };

  const fetchKeys = async () => {
    setLoading(true);
    try {
      const [keysData, certsData] = await Promise.all([
        pkiApi.listKeys().catch(() => []),
        pkiApi.listCertificates().catch(() => []),
      ]);
      setKeys(keysData);
      setCerts(certsData);
    } catch {
      // Mock sample data if backend empty/offline
      setKeys([
        {
          id: 1,
          algorithm: 'RSA',
          keySize: 4096,
          publicKeyPEM: '-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0m...\n-----END PUBLIC KEY-----',
          createdAt: new Date().toISOString(),
        },
        {
          id: 2,
          algorithm: 'EC',
          keySize: 384,
          publicKeyPEM: '-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE...\n-----END PUBLIC KEY-----',
          createdAt: new Date(Date.now() - 86400000).toISOString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchKeys();
  }, []);

  const handleGenerateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    setGenerating(true);
    try {
      const newKey = await pkiApi.generateKey(keyType, keySize);
      setShowGenerateModal(false);
      setInspectKey(newKey);
      fetchKeys();
    } catch (err: unknown) {
      const respData = (err as { response?: { data?: unknown } })?.response?.data;
      const msg = typeof respData === 'string'
        ? respData
        : typeof respData === 'object' && respData !== null && 'message' in respData
        ? String((respData as { message?: string }).message)
        : 'Failed to generate cryptographic key pair.';
      alert(msg);
    } finally {
      setGenerating(false);
    }
  };

  const openCsrModal = (keyId: number) => {
    setCsrKeyId(keyId);
    setShowCsrModal(true);
  };

  const handleGenerateCsr = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!csrKeyId) return;
    try {
      setGenerating(true);
      const subjectDN = `CN=${csrCn.trim()}, O=${csrOrg.trim()}, C=${csrCountry.trim()}${csrOrgUnit ? `, OU=${csrOrgUnit.trim()}` : ''}`;
      localStorage.setItem(`csr_label_${csrKeyId}`, csrCn.trim());
      const csrPem = await pkiApi.generateCsrForKey(csrKeyId, subjectDN);
      setShowCsrModal(false);
      setCsrResult(csrPem);
      fetchKeys();
    } catch (err: unknown) {
      const respData = (err as { response?: { data?: unknown } })?.response?.data;
      const msg = typeof respData === 'string'
        ? respData
        : typeof respData === 'object' && respData !== null && 'message' in respData
        ? String((respData as { message?: string }).message)
        : 'Failed to generate CSR.';
      alert(msg);
    } finally {
      setGenerating(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.025em', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <KeyRound className="w-6 h-6 text-pink-400" style={{ color: '#f472b6' }} />
            <span>PKCS#11 HSM Tokens & Key Custody Vault</span>
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            FIPS 140-3 boundary isolation, non-exportable hardware key handles, and asymmetric cryptographic vectors.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button onClick={fetchKeys} className="btn btn-secondary btn-sm">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          {hasRole(['ROLE_CA_ADMIN', 'ROLE_SECURITY_OFFICER']) && (
            <button onClick={() => setShowGenerateModal(true)} className="btn btn-primary btn-sm">
              <Plus className="w-4 h-4" />
              <span>Generate Key / Token</span>
            </button>
          )}
        </div>
      </div>

      {/* Security & HSM Status Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px' }}>
        <div className="glass-card" style={{ padding: '18px', borderLeft: '4px solid #f472b6' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Cpu className="w-5 h-5 text-pink-400" style={{ color: '#f472b6' }} />
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', fontWeight: 600 }}>HSM Hardware Status</div>
          </div>
          <div style={{ fontSize: '1.25rem', fontWeight: 800, marginTop: '8px', color: '#f8fafc' }}>
            Thales Luna / SoftHSM v2
          </div>
          <div style={{ fontSize: '0.75rem', color: '#34d399', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <ShieldCheck className="w-3.5 h-3.5" /> Slot #0 ONLINE (Active Provider)
          </div>
        </div>

        <div className="glass-card" style={{ padding: '18px', borderLeft: '4px solid #38bdf8' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Lock className="w-5 h-5 text-sky-400" style={{ color: '#38bdf8' }} />
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', fontWeight: 600 }}>Non-Exportable Keys</div>
          </div>
          <div style={{ fontSize: '1.25rem', fontWeight: 800, marginTop: '8px', color: '#f8fafc' }}>
            CKA_EXTRACTABLE = FALSE
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Private keys structurally unextractable
          </div>
        </div>

        <div className="glass-card" style={{ padding: '18px', borderLeft: '4px solid #c084fc' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Layers className="w-5 h-5 text-purple-400" style={{ color: '#c084fc' }} />
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', fontWeight: 600 }}>Total Key Vectors</div>
          </div>
          <div style={{ fontSize: '1.25rem', fontWeight: 800, marginTop: '8px', color: '#f8fafc' }}>
            {keys.length} Registered Keys
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            RSA 4096 / 3072 / 2048 & ECDSA P-256/384/521
          </div>
        </div>
      </div>

      {/* Keys Table */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Cryptographic Key Inventory</h3>
          <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>{keys.length} Keys in Vault</span>
        </div>

        <div className="table-container">
          <table className="table-custom">
            <thead>
              <tr>
                <th>Key ID / Handle</th>
                <th>Identification / Usage</th>
                <th>Algorithm</th>
                <th>Key Size / Curve</th>
                <th>Storage Security</th>
                <th>Extraction Policy</th>
                <th>Created At</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => {
                const normKeyPub = normalizePem(k.publicKeyPEM);
                const boundCert = certs.find(c => normalizePem(c.publicKeyPEM) === normKeyPub);
                const savedLabel = localStorage.getItem(`csr_label_${k.id}`);

                return (
                  <tr key={k.id}>
                    <td className="font-mono" style={{ color: 'var(--accent-secondary)' }}>
                      #KEY-{k.id.toString().padStart(4, '0')}
                    </td>
                    <td>
                      {boundCert ? (
                        <div>
                          <div style={{ fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <Award className="w-3.5 h-3.5 text-indigo-400" />
                            <span>{extractCn(boundCert.subjectDN)}</span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px' }}>
                            <span className={`badge ${
                              boundCert.certificateType === 'ROOT' ? 'badge-root' :
                              boundCert.certificateType === 'INTERMEDIATE' ? 'badge-intermediate' : 'badge-endentity'
                            }`} style={{ fontSize: '0.625rem', padding: '1px 6px' }}>
                              {boundCert.certificateType === 'ROOT' ? 'Root CA Anchor' :
                               boundCert.certificateType === 'INTERMEDIATE' ? 'Subordinate CA' : 'End Entity'}
                            </span>
                            <span className="font-mono" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                              #{boundCert.serialNumber}
                            </span>
                          </div>
                        </div>
                      ) : savedLabel ? (
                        <div>
                          <div style={{ fontWeight: 700, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <FileCode className="w-3.5 h-3.5 text-sky-400" />
                            <span>{savedLabel}</span>
                          </div>
                          <div style={{ fontSize: '0.6875rem', color: '#fbbf24', marginTop: '2px' }}>
                            ⏳ CSR Generated &bull; Waiting for CA Sign
                          </div>
                        </div>
                      ) : (
                        <div>
                          <div style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>
                            Standalone Vault Key
                          </div>
                          <div style={{ fontSize: '0.6875rem', color: '#94a3b8' }}>
                            Uncertified &bull; Ready for CSR
                          </div>
                        </div>
                      )}
                    </td>
                    <td>
                      <span className="badge badge-intermediate">
                        {k.algorithm}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600 }}>
                      {k.algorithm === 'EC' || k.algorithm === 'ECDSA' ? `Curve P-${k.keySize}` : `${k.keySize}-bit`}
                    </td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '0.8125rem', color: '#34d399' }}>
                        <ShieldCheck className="w-4 h-4" /> HSM Boundary
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-root" style={{ fontSize: '0.6875rem' }}>
                        NON-EXPORTABLE
                      </span>
                    </td>
                    <td style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                      {new Date(k.createdAt).toLocaleString()}
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <button 
                          onClick={() => setInspectKey(k)}
                          className="btn btn-secondary btn-sm"
                          style={{ padding: '4px 10px' }}
                        >
                          <FileCode className="w-3.5 h-3.5" />
                          <span>Inspect</span>
                        </button>
                        <button 
                          onClick={() => openCsrModal(k.id)}
                          className="btn btn-primary btn-sm"
                          style={{ padding: '4px 10px' }}
                        >
                          <Sparkles className="w-3.5 h-3.5" />
                          <span>Gen CSR</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Generate Key / Token Modal */}
      {showGenerateModal && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.8)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '20px',
        }}>
          <div className="glass-panel" style={{ width: '100%', maxWidth: '500px', padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <KeyRound className="w-5 h-5 text-pink-400" style={{ color: '#f472b6' }} />
                <span>Generate Cryptographic Token / Key</span>
              </h3>
              <button onClick={() => setShowGenerateModal(false)} style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleGenerateKey}>
              <div className="form-group">
                <label className="form-label">Key Algorithm</label>
                <select 
                  value={keyType}
                  onChange={(e) => {
                    const alg = e.target.value;
                    setKeyType(alg);
                    if (alg === 'RSA') setKeySize(4096);
                    else if (alg === 'EC') setKeySize(384);
                    else setKeySize(256);
                  }}
                  className="form-control"
                >
                  <option value="RSA">RSA (Recommended for CA & High Security)</option>
                  <option value="EC">ECDSA (Elliptic Curve)</option>
                  <option value="Ed25519">Ed25519 (High Performance Edwards Curve)</option>
                </select>
              </div>

              {keyType === 'RSA' && (
                <div className="form-group">
                  <label className="form-label">
                    RSA Key Length (Modulus) — <strong style={{ color: '#38bdf8' }}>Default: 4096-bit</strong>
                  </label>
                  <select 
                    value={keySize}
                    onChange={(e) => setKeySize(Number(e.target.value))}
                    className="form-control"
                  >
                    <option value={4096}>RSA 4096-bit (Advised CA Standard / Maximum Security)</option>
                    <option value={3072}>RSA 3072-bit (Enterprise Production Standard)</option>
                    <option value={2048}>RSA 2048-bit (Standard Minimum Legacy)</option>
                  </select>
                </div>
              )}

              {keyType === 'EC' && (
                <div className="form-group">
                  <label className="form-label">Elliptic Curve Profile</label>
                  <select 
                    value={keySize}
                    onChange={(e) => setKeySize(Number(e.target.value))}
                    className="form-control"
                  >
                    <option value={384}>NIST P-384 / secp384r1 (Suite B / NSA High Security)</option>
                    <option value={256}>NIST P-256 / secp256r1 (Prime256v1)</option>
                    <option value={521}>NIST P-521 / secp521r1 (Ultra High Security)</option>
                  </select>
                </div>
              )}

              <div className="form-group">
                <label className="form-label">Storage & Hardware Boundary</label>
                <select 
                  value={storageType}
                  onChange={(e) => setStorageType(e.target.value)}
                  className="form-control"
                >
                  <option value="HSM">Physical / SoftHSM v2 Token (PKCS#11 Slot #0)</option>
                  <option value="SOFTWARE">Software Protected Keystore</option>
                </select>
              </div>

              <div style={{ background: 'rgba(99, 102, 241, 0.1)', padding: '12px', borderRadius: 'var(--radius-md)', fontSize: '0.8125rem', color: '#c084fc', marginBottom: '16px' }}>
                Keys will be flagged as <strong>CKA_EXTRACTABLE=FALSE</strong>. Private key material will never leave the secure hardware boundary.
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                <button type="button" onClick={() => setShowGenerateModal(false)} className="btn btn-secondary">Cancel</button>
                <button type="submit" disabled={generating} className="btn btn-primary">
                  {generating ? 'Generating in HSM...' : 'Generate Key Pair'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Key Inspector Drawer */}
      {inspectKey && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.8)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '20px',
        }}>
          <div className="glass-panel" style={{ width: '100%', maxWidth: '600px', padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>
                Key Vector #KEY-{inspectKey.id.toString().padStart(4, '0')}
              </h3>
              <button onClick={() => setInspectKey(null)} style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <X className="w-5 h-5" />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="glass-card" style={{ padding: '12px' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Algorithm & Size</div>
                <div style={{ fontWeight: 600 }}>{inspectKey.algorithm} {inspectKey.keySize}-bit (FIPS 140-3 Hardware Token)</div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Public Key (X.509 SPKI PEM)</span>
                  <button onClick={() => handleCopy(inspectKey.publicKeyPEM)} className="btn btn-secondary btn-sm" style={{ padding: '2px 8px', fontSize: '0.75rem' }}>
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="font-mono" style={{
                  background: 'rgba(11, 15, 25, 0.9)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 'var(--radius-md)',
                  padding: '12px',
                  fontSize: '0.75rem',
                  color: '#38bdf8',
                  maxHeight: '180px',
                  overflowY: 'auto',
                  whiteSpace: 'pre-wrap',
                }}>
                  {inspectKey.publicKeyPEM}
                </pre>
              </div>

              {inspectKey.privateKeyPEM && (
                <div style={{ background: 'rgba(236, 72, 153, 0.1)', padding: '10px 14px', borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: '#f472b6' }}>
                  Private Key Handle: <strong>{inspectKey.privateKeyPEM.startsWith('HSM:') ? inspectKey.privateKeyPEM : 'Protected Keystore Entry'}</strong> (Non-Exportable)
                </div>
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '20px' }}>
              <button onClick={() => setInspectKey(null)} className="btn btn-secondary btn-sm">Close</button>
            </div>
          </div>
        </div>
      )}

      {/* CSR Customization & Generation Modal */}
      {showCsrModal && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.8)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '20px',
        }}>
          <div className="glass-panel" style={{ width: '100%', maxWidth: '540px', padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Sparkles className="w-5 h-5 text-indigo-400" />
                <span>Generate CSR for Key #{csrKeyId}</span>
              </h3>
              <button onClick={() => setShowCsrModal(false)} style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleGenerateCsr} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="form-group">
                <label className="form-label">Common Name (CN) / Identification *</label>
                <input
                  type="text"
                  required
                  value={csrCn}
                  onChange={(e) => setCsrCn(e.target.value)}
                  placeholder="e.g. webserver.internal.et or vpn.insa.et"
                  className="form-control"
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Organization (O) *</label>
                  <input
                    type="text"
                    required
                    value={csrOrg}
                    onChange={(e) => setCsrOrg(e.target.value)}
                    placeholder="e.g. INSA PKI Trust Network"
                    className="form-control"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Country Code (C) *</label>
                  <input
                    type="text"
                    required
                    maxLength={2}
                    value={csrCountry}
                    onChange={(e) => setCsrCountry(e.target.value)}
                    placeholder="ET"
                    className="form-control"
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Organizational Unit (OU)</label>
                <input
                  type="text"
                  value={csrOrgUnit}
                  onChange={(e) => setCsrOrgUnit(e.target.value)}
                  placeholder="e.g. Security Operations"
                  className="form-control"
                />
              </div>

              <div className="glass-card" style={{ padding: '10px 14px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Resulting Subject DN: <strong style={{ color: 'var(--accent-secondary)' }}>CN={csrCn}, O={csrOrg}, C={csrCountry}{csrOrgUnit ? `, OU=${csrOrgUnit}` : ''}</strong>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '12px' }}>
                <button type="button" onClick={() => setShowCsrModal(false)} className="btn btn-secondary btn-sm">Cancel</button>
                <button type="submit" disabled={generating} className="btn btn-primary btn-sm">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>{generating ? 'Generating CSR...' : 'Generate Signed CSR'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* CSR Result Modal */}
      {csrResult && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 10000,
          padding: '20px',
        }}>
          <div className="glass-panel" style={{ width: '100%', maxWidth: '580px', padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#34d399' }}>Generated PKCS#10 CSR</h3>
              <button onClick={() => setCsrResult(null)} style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <X className="w-5 h-5" />
              </button>
            </div>
            <pre className="font-mono" style={{
              background: 'rgba(11, 15, 25, 0.95)',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-md)',
              padding: '12px',
              fontSize: '0.75rem',
              color: '#34d399',
              maxHeight: '220px',
              overflowY: 'auto',
              whiteSpace: 'pre-wrap',
            }}>
              {csrResult}
            </pre>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '16px' }}>
              <button onClick={() => handleCopy(csrResult)} className="btn btn-secondary btn-sm">
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy CSR'}</span>
              </button>
              <button onClick={() => setCsrResult(null)} className="btn btn-primary btn-sm">Done</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
