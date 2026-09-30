import React, { useEffect, useState } from 'react';
import type { CertificateItem } from '../api/pkiApi';
import { pkiApi } from '../api/pkiApi';
import { CertificateViewerModal } from '../components/CertificateViewerModal';
import { useToast } from '../context/ToastContext';
import {
  GitFork,
  RefreshCw,
  Eye,
  ArrowDown,
  ShieldPlus,
} from 'lucide-react';

export const ChainView: React.FC = () => {
  const { showToast } = useToast();
  const [certs, setCerts] = useState<CertificateItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCert, setSelectedCert] = useState<CertificateItem | null>(null);
  // Track which CA serial is being issued an OCSP signer (for per-row loading state)
  const [ocspIssuingSerial, setOcspIssuingSerial] = useState<string | null>(null);

  const fetchCerts = async () => {
    setLoading(true);
    try {
      const data = await pkiApi.listCertificates();
      setCerts(data);
    } catch {
      setCerts([
        {
          id: 1, serialNumber: '1001',
          subjectDN: 'CN=INSA Global Root CA, O=INSA PKI, C=FR',
          issuerDN: 'CN=INSA Global Root CA, O=INSA PKI, C=FR',
          certificateType: 'ROOT', status: 'ISSUED', profileName: 'RootCA',
          publicKeyPEM: '...', pemContent: '...',
        },
        {
          id: 2, serialNumber: '1002',
          subjectDN: 'CN=INSA Enterprise Issuing CA v1, O=INSA PKI, C=FR',
          issuerDN: 'CN=INSA Global Root CA, O=INSA PKI, C=FR',
          certificateType: 'INTERMEDIATE', status: 'ISSUED', profileName: 'SubCA',
          publicKeyPEM: '...', pemContent: '...',
        },
        {
          id: 3, serialNumber: '1003',
          subjectDN: 'CN=OCSP Responder - INSA Sub CA, O=INSA PKI, C=FR',
          issuerDN: 'CN=INSA Enterprise Issuing CA v1, O=INSA PKI, C=FR',
          certificateType: 'OCSP_SIGNER', status: 'ISSUED', profileName: 'OCSPSigner',
          publicKeyPEM: '...', pemContent: '...',
        },
        {
          id: 4, serialNumber: '1004',
          subjectDN: 'CN=api.insa.fr, O=INSA PKI, C=FR',
          issuerDN: 'CN=INSA Enterprise Issuing CA v1, O=INSA PKI, C=FR',
          certificateType: 'END_ENTITY', status: 'ISSUED', profileName: 'EnterpriseEndEntity',
          publicKeyPEM: '...', pemContent: '...',
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchCerts(); }, []);

  // ── Task 1: Issue OCSP Signer ──────────────────────────────────────────────
  const handleIssueOcspSigner = async (caSerial: string, caCn: string) => {
    setOcspIssuingSerial(caSerial);
    try {
      const newCert = await pkiApi.issueOcspSigner(caSerial);
      showToast(`OCSP Signer issued successfully for "${caCn}" (Serial: #${newCert.serialNumber})`, 'success');
      await fetchCerts();
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: string } })?.response?.data || 'Failed to issue OCSP Signer certificate.';
      showToast(msg, 'error');
    } finally {
      setOcspIssuingSerial(null);
    }
  };

  const extractCn = (dn: string) => {
    const match = dn.match(/CN=([^,]+)/i);
    return match ? match[1] : dn;
  };

  const matchDN = (issuerDN?: string, targetSubjectDN?: string) => {
    if (!issuerDN || !targetSubjectDN) return false;
    if (issuerDN.trim().toLowerCase() === targetSubjectDN.trim().toLowerCase()) return true;
    const cn1 = extractCn(issuerDN).trim().toLowerCase();
    const cn2 = extractCn(targetSubjectDN).trim().toLowerCase();
    return cn1 && cn2 && cn1 === cn2;
  };

  const rootCAs = certs.filter(c => c.certificateType === 'ROOT');
  const getSubCAsForRoot = (root: CertificateItem) =>
    certs.filter(c => (c.certificateType === 'INTERMEDIATE' || c.profileName?.toLowerCase().includes('subca')) && matchDN(c.issuerDN, root.subjectDN));
  const getLeavesForSubCA = (sub: CertificateItem) =>
    certs.filter(c => (c.certificateType === 'END_ENTITY' || c.certificateType === 'OCSP_SIGNER') && matchDN(c.issuerDN, sub.subjectDN));
  const getDirectLeavesForRoot = (root: CertificateItem) =>
    certs.filter(c => (c.certificateType === 'END_ENTITY' || c.certificateType === 'OCSP_SIGNER') && matchDN(c.issuerDN, root.subjectDN));

  // Check if a CA already has an active OCSP signer
  const hasOcspSigner = (caSubjectDN: string) =>
    certs.some(c => c.certificateType === 'OCSP_SIGNER' && c.status === 'ISSUED' && matchDN(c.issuerDN, caSubjectDN));

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.025em', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <GitFork className="w-6 h-6 text-sky-400" style={{ color: '#38bdf8' }} />
            <span>Hierarchical CA Trust Chain Visualizer</span>
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            Interactive cryptographic chain of trust from Root Anchors down to Issuing Sub CAs and Leaf End-Entities.
          </p>
        </div>

        <button onClick={fetchCerts} className="btn btn-secondary btn-sm" disabled={loading}>
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Trust Tree Graph Container */}
      <div className="glass-panel" style={{ padding: '32px' }}>
        {rootCAs.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
            No Root CAs deployed yet. Go to &quot;CA Operations &amp; Sign&quot; to initialize a Root CA.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '40px' }}>
            {rootCAs.map(root => {
              const subCAs = getSubCAsForRoot(root);
              const directLeaves = getDirectLeavesForRoot(root);
              const hasChildren = subCAs.length > 0 || directLeaves.length > 0;

              return (
                <div key={root.serialNumber} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '20px' }}>
                  {/* ROOT NODE */}
                  <div className="glass-card" style={{
                    width: '100%', maxWidth: '520px', padding: '20px 26px',
                    border: '2px solid rgba(168, 85, 247, 0.5)',
                    background: 'rgba(26, 34, 52, 0.95)',
                    boxShadow: '0 0 25px rgba(168, 85, 247, 0.25)',
                    borderRadius: 'var(--radius-lg)', textAlign: 'center',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span className="badge badge-root">Root Trust Anchor</span>
                      <span className={`badge ${root.status === 'ISSUED' ? 'badge-issued' : root.status === 'REVOKED' ? 'badge-revoked' : 'badge-suspended'}`}>{root.status}</span>
                    </div>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#f8fafc' }}>
                      {extractCn(root.subjectDN)}
                    </h3>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px', wordBreak: 'break-all' }}>
                      {root.subjectDN}
                    </div>
                    <div className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--accent-secondary)', marginTop: '6px' }}>
                      Serial: #{root.serialNumber}
                    </div>
                    <div style={{ marginTop: '14px', display: 'flex', justifyContent: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <button onClick={() => setSelectedCert(root)} className="btn btn-secondary btn-sm" style={{ padding: '4px 14px' }}>
                        <Eye className="w-3.5 h-3.5 text-purple-400" />
                        <span>Inspect Anchor</span>
                      </button>
                      {/* OCSP Signer button for Root CA */}
                      {root.status === 'ISSUED' && (
                        <button
                          onClick={() => handleIssueOcspSigner(root.serialNumber, extractCn(root.subjectDN))}
                          disabled={ocspIssuingSerial === root.serialNumber}
                          className="btn btn-sm"
                          style={{
                            padding: '4px 14px',
                            background: hasOcspSigner(root.subjectDN) ? 'rgba(245,158,11,0.15)' : 'rgba(56,189,248,0.15)',
                            border: `1px solid ${hasOcspSigner(root.subjectDN) ? 'rgba(245,158,11,0.3)' : 'rgba(56,189,248,0.3)'}`,
                            color: hasOcspSigner(root.subjectDN) ? '#fde68a' : '#7dd3fc',
                            borderRadius: 8, fontWeight: 600, cursor: 'pointer',
                            display: 'flex', alignItems: 'center', gap: 6,
                          }}
                          title={hasOcspSigner(root.subjectDN) ? 'Re-issue OCSP Signer (replace existing)' : 'Issue OCSP Signer Certificate'}
                        >
                          <ShieldPlus style={{ width: 13, height: 13 }} />
                          <span>{ocspIssuingSerial === root.serialNumber ? 'Issuing...' : hasOcspSigner(root.subjectDN) ? 'Re-issue OCSP' : 'Issue OCSP Signer'}</span>
                        </button>
                      )}
                    </div>
                  </div>

                  {/* CONNECTING ARROW */}
                  {hasChildren ? (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', color: '#818cf8' }}>
                      <div style={{ width: '2px', height: '24px', background: 'linear-gradient(to bottom, #c084fc, #60a5fa)' }} />
                      <ArrowDown className="w-4 h-4" />
                    </div>
                  ) : (
                    <div style={{
                      padding: '12px 20px', background: 'rgba(255,255,255,0.03)',
                      border: '1px dashed var(--border-color)', borderRadius: 'var(--radius-md)',
                      color: 'var(--text-muted)', fontSize: '0.8125rem', textAlign: 'center',
                    }}>
                      No Subordinate CAs or certificates signed under this Root CA yet.
                    </div>
                  )}

                  {/* SUB CAs ROW */}
                  {subCAs.length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: '28px', width: '100%' }}>
                      {subCAs.map(sub => {
                        const leaves = getLeavesForSubCA(sub);
                        return (
                          <div key={sub.serialNumber} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px', minWidth: '320px', maxWidth: '440px', flex: 1 }}>
                            {/* SUB CA NODE */}
                            <div className="glass-card" style={{
                              width: '100%', padding: '16px 20px',
                              border: '1px solid rgba(59, 130, 246, 0.4)',
                              background: 'rgba(26, 34, 52, 0.9)',
                              borderRadius: 'var(--radius-md)',
                            }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                                <span className="badge badge-intermediate">Subordinate Issuing CA</span>
                                <span className={`badge ${sub.status === 'ISSUED' ? 'badge-issued' : sub.status === 'REVOKED' ? 'badge-revoked' : 'badge-suspended'}`}>{sub.status}</span>
                              </div>
                              <h4 style={{ fontSize: '1rem', fontWeight: 700, color: '#60a5fa' }}>
                                {extractCn(sub.subjectDN)}
                              </h4>
                              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: '2px', wordBreak: 'break-all' }}>
                                {sub.subjectDN}
                              </div>
                              <div className="font-mono" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                                Serial: #{sub.serialNumber}
                              </div>
                              <div style={{ marginTop: '10px', display: 'flex', justifyContent: 'flex-start', gap: '6px', flexWrap: 'wrap' }}>
                                <button onClick={() => setSelectedCert(sub)} className="btn btn-secondary btn-sm" style={{ padding: '3px 10px', fontSize: '0.75rem' }}>
                                  <Eye className="w-3 h-3 text-sky-400" />
                                  <span>Inspect CA</span>
                                </button>
                                {/* OCSP Signer button for Sub CA */}
                                {sub.status === 'ISSUED' && (
                                  <button
                                    onClick={() => handleIssueOcspSigner(sub.serialNumber, extractCn(sub.subjectDN))}
                                    disabled={ocspIssuingSerial === sub.serialNumber}
                                    className="btn btn-sm"
                                    style={{
                                      padding: '3px 10px', fontSize: '0.75rem',
                                      background: hasOcspSigner(sub.subjectDN) ? 'rgba(245,158,11,0.15)' : 'rgba(56,189,248,0.15)',
                                      border: `1px solid ${hasOcspSigner(sub.subjectDN) ? 'rgba(245,158,11,0.3)' : 'rgba(56,189,248,0.3)'}`,
                                      color: hasOcspSigner(sub.subjectDN) ? '#fde68a' : '#7dd3fc',
                                      borderRadius: 8, fontWeight: 600, cursor: 'pointer',
                                      display: 'flex', alignItems: 'center', gap: 5,
                                    }}
                                    title="Issue OCSP Signer Certificate for this CA"
                                  >
                                    <ShieldPlus style={{ width: 11, height: 11 }} />
                                    <span>{ocspIssuingSerial === sub.serialNumber ? 'Issuing...' : hasOcspSigner(sub.subjectDN) ? 'Re-issue OCSP' : 'Issue OCSP Signer'}</span>
                                  </button>
                                )}
                              </div>
                            </div>

                            {/* CONNECTING ARROW TO LEAVES */}
                            {leaves.length > 0 && (
                              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', color: '#60a5fa' }}>
                                <div style={{ width: '2px', height: '18px', background: 'linear-gradient(to bottom, #60a5fa, #2dd4bf)' }} />
                                <ArrowDown className="w-3.5 h-3.5" />
                              </div>
                            )}

                            {/* LEAF NODES */}
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', width: '100%' }}>
                              {leaves.map(leaf => (
                                <div key={leaf.serialNumber} className="glass-card" style={{
                                  padding: '12px 16px',
                                  borderLeft: `3px solid ${leaf.status === 'REVOKED' ? '#ef4444' : leaf.certificateType === 'OCSP_SIGNER' ? '#f59e0b' : '#34d399'}`,
                                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                                }}>
                                  <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                      <span style={{ fontWeight: 600, fontSize: '0.8125rem', color: '#f8fafc' }}>
                                        {extractCn(leaf.subjectDN)}
                                      </span>
                                      {leaf.certificateType === 'OCSP_SIGNER' && (
                                        <span style={{ fontSize: '0.625rem', padding: '1px 6px', background: 'rgba(245,158,11,0.15)', color: '#fde68a', borderRadius: 4, fontWeight: 700 }}>
                                          OCSP SIGNER
                                        </span>
                                      )}
                                      <span className={`badge ${leaf.status === 'ISSUED' ? 'badge-issued' : leaf.status === 'SUSPENDED' ? 'badge-suspended' : 'badge-revoked'}`} style={{ fontSize: '0.625rem', padding: '1px 6px' }}>
                                        {leaf.status} {leaf.revocationReason ? `(${leaf.revocationReason})` : ''}
                                      </span>
                                    </div>
                                    <div className="font-mono" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                                      #{leaf.serialNumber}
                                    </div>
                                  </div>
                                  <button onClick={() => setSelectedCert(leaf)} className="btn btn-secondary btn-sm" style={{ padding: '4px 8px' }}>
                                    <Eye className="w-3.5 h-3.5 text-teal-400" />
                                  </button>
                                </div>
                              ))}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {/* DIRECT LEAVES UNDER ROOT */}
                  {directLeaves.length > 0 && subCAs.length === 0 && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', width: '100%', maxWidth: '440px' }}>
                      {directLeaves.map(leaf => (
                        <div key={leaf.serialNumber} className="glass-card" style={{
                          padding: '12px 16px',
                          borderLeft: `3px solid ${leaf.status === 'REVOKED' ? '#ef4444' : '#34d399'}`,
                          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                        }}>
                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <span style={{ fontWeight: 600, fontSize: '0.8125rem', color: '#f8fafc' }}>
                                {extractCn(leaf.subjectDN)}
                              </span>
                              <span className={`badge ${leaf.status === 'ISSUED' ? 'badge-issued' : 'badge-revoked'}`} style={{ fontSize: '0.625rem', padding: '1px 6px' }}>
                                {leaf.status}
                              </span>
                            </div>
                            <div className="font-mono" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                              #{leaf.serialNumber}
                            </div>
                          </div>
                          <button onClick={() => setSelectedCert(leaf)} className="btn btn-secondary btn-sm" style={{ padding: '4px 8px' }}>
                            <Eye className="w-3.5 h-3.5 text-teal-400" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {selectedCert && (
        <CertificateViewerModal
          certificate={selectedCert}
          onClose={() => setSelectedCert(null)}
          onRefresh={fetchCerts}
        />
      )}
    </div>
  );
};
