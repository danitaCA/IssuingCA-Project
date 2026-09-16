import React, { useState } from 'react';
import type { CertificateItem } from '../api/pkiApi';
import { pkiApi } from '../api/pkiApi';
import { useAuth } from '../context/AuthContext';
import { 
  X, 
  Download, 
  Copy, 
  Check, 
  Award, 
  Shield, 
  Calendar, 
  GitFork, 
  RefreshCw, 
  PauseCircle, 
  PlayCircle, 
  AlertTriangle,
  FileCode,
  Layers,
  Lock,
  Sparkles
} from 'lucide-react';

interface CertificateViewerModalProps {
  certificate: CertificateItem | null;
  onClose: () => void;
  onRefresh?: () => void;
}

export const CertificateViewerModal: React.FC<CertificateViewerModalProps> = ({
  certificate,
  onClose,
  onRefresh,
}) => {
  const { hasRole } = useAuth();
  const [currentCert, setCurrentCert] = useState<CertificateItem | null>(certificate);
  const [activeTab, setActiveTab] = useState<'details' | 'extensions' | 'chain' | 'pem'>('details');
  const [copied, setCopied] = useState(false);
  const [pfxPassword, setPfxPassword] = useState('');
  const [showPfxModal, setShowPfxModal] = useState(false);
  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [revokeReason, setRevokeReason] = useState('UNSPECIFIED');
  const [actionLoading, setActionLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  React.useEffect(() => {
    if (certificate) setCurrentCert(certificate);
  }, [certificate]);

  if (!currentCert) return null;

  const extractCn = (dn: string) => {
    const match = dn.match(/CN=([^,]+)/i);
    return match ? match[1] : dn;
  };

  const toHexSerial = (serial: string) => {
    try {
      const big = BigInt(serial);
      return '0x' + big.toString(16).toUpperCase();
    } catch {
      return serial;
    }
  };

  const handleCopyPem = () => {
    navigator.clipboard.writeText(currentCert.pemContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadPem = () => {
    const blob = new Blob([currentCert.pemContent], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${extractCn(currentCert.subjectDN).replace(/[^a-zA-Z0-9_-]/g, '_')}_${currentCert.serialNumber}.pem`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadChain = async () => {
    try {
      const chainPem = await pkiApi.getCertificateChain(currentCert.serialNumber);
      const blob = new Blob([chainPem], { type: 'application/x-pem-file' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${extractCn(currentCert.subjectDN).replace(/[^a-zA-Z0-9_-]/g, '_')}_chain.pem`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      handleDownloadPem();
    }
  };

  const handleDownloadDer = () => {
    const url = `/api/v1/certificates/${currentCert.serialNumber}/der`;
    const a = document.createElement('a');
    a.href = url;
    a.download = `${currentCert.serialNumber}.der`;
    a.click();
  };

  const handleDownloadPfx = async () => {
    try {
      setActionLoading(true);
      const blob = await pkiApi.downloadPkcs12(currentCert.serialNumber, pfxPassword || 'changeit');
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${extractCn(currentCert.subjectDN).replace(/[^a-zA-Z0-9_-]/g, '_')}.p12`;
      a.click();
      URL.revokeObjectURL(url);
      setShowPfxModal(false);
      setPfxPassword('');
    } catch (err: unknown) {
      alert((err as { response?: { data?: string } })?.response?.data || 'Failed to download PKCS#12 bundle (Private key may be protected in HSM or not available).');
    } finally {
      setActionLoading(false);
    }
  };

  const handleRenew = async () => {
    if (!confirm('Are you sure you want to renew this certificate? The current certificate will be marked SUPERSEDED.')) return;
    try {
      setActionLoading(true);
      const renewed = await pkiApi.renewCertificate(currentCert.serialNumber);
      setCurrentCert(renewed);
      setActionMessage(`Certificate renewed successfully! Now viewing active renewed certificate (Serial: #${renewed.serialNumber}). Previous certificate was marked SUPERSEDED.`);
      if (onRefresh) onRefresh();
    } catch (err: unknown) {
      alert((err as { response?: { data?: string } })?.response?.data || 'Failed to renew certificate.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleSuspendToggle = async () => {
    try {
      setActionLoading(true);
      if (currentCert.status === 'SUSPENDED') {
        const unsuspended = await pkiApi.unsuspendCertificate(currentCert.serialNumber);
        setCurrentCert(unsuspended);
        setActionMessage('Certificate unsuspended/reactivated.');
      } else {
        const suspended = await pkiApi.suspendCertificate(currentCert.serialNumber);
        setCurrentCert(suspended);
        setActionMessage('Certificate suspended.');
      }
      if (onRefresh) onRefresh();
    } catch (err: unknown) {
      alert((err as { response?: { data?: string } })?.response?.data || 'Operation failed.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleRevoke = async () => {
    try {
      setActionLoading(true);
      const revoked = await pkiApi.revokeCertificate(currentCert.serialNumber, revokeReason);
      setCurrentCert(revoked);
      setShowRevokeModal(false);
      setActionMessage('Certificate revoked successfully.');
      if (onRefresh) onRefresh();
    } catch (err: unknown) {
      alert((err as { response?: { data?: string } })?.response?.data || 'Failed to revoke certificate.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleSignAndActivatePendingCa = async () => {
    try {
      setActionLoading(true);
      const certList = await pkiApi.listCertificates();
      const activeRoot = certList.find(c => c.certificateType === 'ROOT' && c.status === 'ISSUED');
      if (!activeRoot) {
        alert('No active Root CA found. Please ensure a Root CA is initialized first.');
        return;
      }

      const signedCert = await pkiApi.signCsr({
        csrPem: currentCert.pemContent,
        caSerialNumber: activeRoot.serialNumber,
        profileName: 'SubCA',
      });

      const activated = await pkiApi.importSignedCaCert({
        caSerialNumber: currentCert.serialNumber,
        signedCertPem: signedCert.pemContent,
      });

      setCurrentCert(activated);
      setActionMessage('Subordinate Issuing CA signed by Root CA and activated successfully!');
      if (onRefresh) onRefresh();
    } catch (err: unknown) {
      alert((err as { response?: { data?: string } })?.response?.data || 'Failed to sign and activate Sub CA.');
    } finally {
      setActionLoading(false);
    }
  };

  const notBefore = currentCert.notBefore ? new Date(currentCert.notBefore) : null;
  const notAfter = currentCert.notAfter ? new Date(currentCert.notAfter) : null;
  const isExpired = notAfter ? notAfter.getTime() < Date.now() : false;
  const daysRemaining = notAfter ? Math.max(0, Math.ceil((notAfter.getTime() - Date.now()) / (1000 * 60 * 60 * 24))) : null;

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(0, 0, 0, 0.75)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999,
      padding: '20px',
    }}>
      <div className="glass-panel" style={{
        width: '100%',
        maxWidth: '860px',
        maxHeight: '90vh',
        display: 'flex',
        flexDirection: 'column',
        boxShadow: 'var(--shadow-lg)',
        border: '1px solid rgba(255, 255, 255, 0.12)',
        overflow: 'hidden',
      }}>
        {/* Header */}
        <div style={{
          padding: '20px 24px',
          borderBottom: '1px solid var(--border-color)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          background: 'rgba(17, 24, 39, 0.6)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{
              width: '44px',
              height: '44px',
              borderRadius: 'var(--radius-md)',
              background: currentCert.certificateType === 'ROOT' 
                ? 'rgba(168, 85, 247, 0.2)' 
                : currentCert.certificateType === 'INTERMEDIATE' 
                ? 'rgba(59, 130, 246, 0.2)' 
                : 'rgba(20, 184, 166, 0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <Award className="w-6 h-6" style={{
                color: currentCert.certificateType === 'ROOT' 
                  ? '#c084fc' 
                  : currentCert.certificateType === 'INTERMEDIATE' 
                  ? '#60a5fa' 
                  : '#2dd4bf'
              }} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {extractCn(currentCert.subjectDN)}
                </h3>
                <span className={`badge ${
                  currentCert.status === 'ISSUED' ? 'badge-issued' :
                  currentCert.status === 'SUSPENDED' ? 'badge-suspended' :
                  currentCert.status === 'REVOKED' ? 'badge-revoked' : 'badge-expired'
                }`}>
                  {currentCert.status}
                </span>
                <span className={`badge ${
                  currentCert.certificateType === 'ROOT' ? 'badge-root' :
                  currentCert.certificateType === 'INTERMEDIATE' ? 'badge-intermediate' : 'badge-endentity'
                }`}>
                  {currentCert.certificateType}
                </span>
              </div>
              <p className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Serial: <span style={{ color: 'var(--accent-secondary)' }}>{currentCert.serialNumber}</span> ({toHexSerial(currentCert.serialNumber)})
              </p>
            </div>
          </div>

          <button 
            onClick={onClose}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '4px' }}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div style={{
          display: 'flex',
          gap: '8px',
          padding: '10px 24px',
          background: 'rgba(11, 15, 25, 0.5)',
          borderBottom: '1px solid var(--border-color)',
        }}>
          {[
            { id: 'details', label: 'Certificate Details', icon: <Shield className="w-4 h-4" /> },
            { id: 'extensions', label: 'X.509 v3 Extensions', icon: <Layers className="w-4 h-4" /> },
            { id: 'chain', label: 'Trust Chain Hierarchy', icon: <GitFork className="w-4 h-4" /> },
            { id: 'pem', label: 'Raw PEM / Keystore', icon: <FileCode className="w-4 h-4" /> },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 14px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.8125rem',
                fontWeight: activeTab === tab.id ? 600 : 500,
                color: activeTab === tab.id ? 'white' : 'var(--text-muted)',
                background: activeTab === tab.id ? 'rgba(99, 102, 241, 0.2)' : 'transparent',
                border: activeTab === tab.id ? '1px solid rgba(99, 102, 241, 0.4)' : '1px solid transparent',
                cursor: 'pointer',
              }}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Action Feedback Banner */}
        {actionMessage && (
          <div style={{ padding: '8px 24px', background: 'rgba(16, 185, 129, 0.15)', borderBottom: '1px solid rgba(16, 185, 129, 0.3)', color: '#34d399', fontSize: '0.8125rem' }}>
            {actionMessage}
          </div>
        )}

        {/* Revocation / Superseded Notice */}
        {currentCert.status === 'REVOKED' && (
          <div style={{
            margin: '12px 24px 0',
            padding: '10px 16px',
            borderRadius: 'var(--radius-sm)',
            background: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '10px',
            color: '#fca5a5',
            fontSize: '0.8125rem'
          }}>
            <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444', marginTop: '1px' }} />
            <div>
              <div style={{ fontWeight: 700, color: '#f87171' }}>
                Status: REVOKED (Reason: {currentCert.revocationReason || 'UNSPECIFIED'})
              </div>
              {currentCert.revocationReason === 'SUPERSEDED' ? (
                <div style={{ marginTop: '2px', color: 'var(--text-secondary)' }}>
                  ℹ️ This previous certificate record was superseded when renewed. A new certificate was minted with an extended validity period and a new Serial Number. You can find the active renewed certificate in the Certificates inventory.
                </div>
              ) : (
                <div style={{ marginTop: '2px', color: 'var(--text-secondary)' }}>
                  This certificate has been revoked and published to CRL / OCSP revocation lists.
                </div>
              )}
            </div>
          </div>
        )}

        {/* Modal Content Body */}
        <div style={{ padding: '20px 24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {activeTab === 'details' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Validity Banner */}
              <div className="glass-card" style={{ padding: '14px 18px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Calendar className="w-5 h-5 text-indigo-400" style={{ color: 'var(--accent-primary)' }} />
                  <div>
                    <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Validity Period</div>
                    <div style={{ fontSize: '0.875rem', fontWeight: 600 }}>
                      {notBefore ? notBefore.toLocaleDateString() : 'N/A'} — {notAfter ? notAfter.toLocaleDateString() : 'N/A'}
                    </div>
                  </div>
                </div>
                {daysRemaining !== null && (
                  <span className={`badge ${isExpired ? 'badge-expired' : 'badge-issued'}`}>
                    {isExpired ? 'Expired' : `${daysRemaining} Days Remaining`}
                  </span>
                )}
              </div>

              {/* Subject and Issuer Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                <div className="glass-card" style={{ padding: '16px' }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '8px' }}>
                    Subject Distinguished Name (DN)
                  </div>
                  <div className="font-mono" style={{ fontSize: '0.8125rem', color: '#38bdf8', wordBreak: 'break-all' }}>
                    {currentCert.subjectDN}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '16px' }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '8px' }}>
                    Issuer Distinguished Name (DN)
                  </div>
                  <div className="font-mono" style={{ fontSize: '0.8125rem', color: '#c084fc', wordBreak: 'break-all' }}>
                    {currentCert.issuerDN}
                  </div>
                </div>
              </div>

              {/* Profile & Metadata */}
              <div className="glass-card" style={{ padding: '16px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', fontSize: '0.8125rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Profile Template:</span>
                    <div style={{ fontWeight: 600, marginTop: '2px' }}>{currentCert.profileName || 'Default'}</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Signature Algorithm:</span>
                    <div style={{ fontWeight: 600, marginTop: '2px' }}>SHA512withRSA (RFC 5280)</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Key Type:</span>
                    <div style={{ fontWeight: 600, marginTop: '2px' }}>RSA 4096-bit (Hardware Anchor)</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'extensions' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div className="glass-card" style={{ padding: '14px 16px' }}>
                <div style={{ fontWeight: 600, fontSize: '0.875rem', color: '#818cf8', marginBottom: '4px' }}>
                  2.5.29.19 — Basic Constraints (Critical)
                </div>
                <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                  Is Certificate Authority (CA): <strong>{currentCert.certificateType === 'ROOT' || currentCert.certificateType === 'INTERMEDIATE' ? 'TRUE (PathLen: 0/1)' : 'FALSE (Leaf End-Entity)'}</strong>
                </div>
              </div>

              <div className="glass-card" style={{ padding: '14px 16px' }}>
                <div style={{ fontWeight: 600, fontSize: '0.875rem', color: '#818cf8', marginBottom: '4px' }}>
                  2.5.29.15 — Key Usage (Critical)
                </div>
                <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                  {currentCert.certificateType === 'ROOT' || currentCert.certificateType === 'INTERMEDIATE'
                    ? 'Digital Signature, Certificate Signing (keyCertSign), CRL Signing (cRLSign)'
                    : 'Digital Signature, Key Encipherment, Data Encipherment'}
                </div>
              </div>

              <div className="glass-card" style={{ padding: '14px 16px' }}>
                <div style={{ fontWeight: 600, fontSize: '0.875rem', color: '#818cf8', marginBottom: '4px' }}>
                  2.5.29.37 — Extended Key Usage (EKU)
                </div>
                <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                  Server Authentication (1.3.6.1.5.5.7.3.1), Client Authentication (1.3.6.1.5.5.7.3.2), Email Protection (1.3.6.1.5.5.7.3.4)
                </div>
              </div>

              <div className="glass-card" style={{ padding: '14px 16px' }}>
                <div style={{ fontWeight: 600, fontSize: '0.875rem', color: '#818cf8', marginBottom: '4px' }}>
                  2.5.29.31 — CRL Distribution Points (CDP)
                </div>
                <div className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--accent-secondary)' }}>
                  URI: http://localhost:8080/api/v1/crl/{currentCert.serialNumber}/latest/der
                </div>
              </div>

              <div className="glass-card" style={{ padding: '14px 16px' }}>
                <div style={{ fontWeight: 600, fontSize: '0.875rem', color: '#818cf8', marginBottom: '4px' }}>
                  1.3.6.1.5.5.7.1.1 — Authority Information Access (AIA / OCSP)
                </div>
                <div className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--accent-secondary)' }}>
                  OCSP Responder: http://localhost:8080/api/v1/ocsp/{currentCert.serialNumber}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'chain' && (
            <div className="glass-card" style={{ padding: '20px' }}>
              <div style={{ fontSize: '0.875rem', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <GitFork className="w-4 h-4 text-indigo-400" />
                <span>Hierarchical Chain Path to Trust Anchor</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', position: 'relative', paddingLeft: '16px' }}>
                {/* Visual Line */}
                <div style={{ position: 'absolute', top: '16px', bottom: '16px', left: '26px', width: '2px', background: 'rgba(99, 102, 241, 0.4)' }} />

                {/* Root CA Node */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', zIndex: 1 }}>
                  <div style={{ width: '22px', height: '22px', borderRadius: '50%', background: '#c084fc', border: '3px solid #0b0f19' }} />
                  <div className="glass-card" style={{ padding: '10px 14px', flex: 1, borderLeft: '3px solid #c084fc' }}>
                    <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#c084fc' }}>Root Trust Anchor (Self-Signed)</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{currentCert.issuerDN}</div>
                  </div>
                </div>

                {/* Leaf Certificate Node */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', zIndex: 1 }}>
                  <div style={{ width: '22px', height: '22px', borderRadius: '50%', background: '#34d399', border: '3px solid #0b0f19' }} />
                  <div className="glass-card" style={{ padding: '10px 14px', flex: 1, borderLeft: '3px solid #34d399' }}>
                    <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#34d399' }}>
                      {currentCert.certificateType === 'ROOT' ? 'Root Certificate' : 'Target Certificate'}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-primary)' }}>{currentCert.subjectDN}</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'pem' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Base64 RFC 7468 PEM Payload</span>
                <button 
                  onClick={handleCopyPem}
                  className="btn btn-secondary btn-sm"
                  style={{ gap: '6px' }}
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy PEM'}</span>
                </button>
              </div>
              <pre className="font-mono" style={{
                background: 'rgba(11, 15, 25, 0.9)',
                border: '1px solid var(--border-color)',
                borderRadius: 'var(--radius-md)',
                padding: '14px',
                fontSize: '0.75rem',
                color: '#34d399',
                maxHeight: '260px',
                overflowY: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}>
                {currentCert.pemContent}
              </pre>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div style={{
          padding: '16px 24px',
          borderTop: '1px solid var(--border-color)',
          background: 'rgba(17, 24, 39, 0.6)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '10px',
        }}>
          {/* Download Group */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button 
              onClick={handleDownloadPem}
              className="btn btn-secondary btn-sm"
            >
              <Download className="w-3.5 h-3.5" />
              <span>.PEM / .CRT</span>
            </button>
            <button 
              onClick={handleDownloadDer}
              className="btn btn-secondary btn-sm"
            >
              <Download className="w-3.5 h-3.5" />
              <span>.DER</span>
            </button>
            <button 
              onClick={handleDownloadChain}
              className="btn btn-secondary btn-sm"
            >
              <GitFork className="w-3.5 h-3.5" />
              <span>Chain Bundle</span>
            </button>
            <button 
              onClick={() => setShowPfxModal(true)}
              className="btn btn-primary btn-sm"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>PKCS#12 (.p12)</span>
            </button>
          </div>

          {/* Admin Lifecycle Action Group */}
          {hasRole(['ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR']) && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {currentCert.status === 'ISSUED' && (
                <>
                  <button 
                    onClick={handleRenew}
                    disabled={actionLoading}
                    className="btn btn-secondary btn-sm"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Renew</span>
                  </button>
                  <button 
                    onClick={handleSuspendToggle}
                    disabled={actionLoading}
                    className="btn btn-warning btn-sm"
                  >
                    <PauseCircle className="w-3.5 h-3.5" />
                    <span>Suspend</span>
                  </button>
                  <button 
                    onClick={() => setShowRevokeModal(true)}
                    disabled={actionLoading}
                    className="btn btn-danger btn-sm"
                  >
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Revoke</span>
                  </button>
                </>
              )}
              {currentCert.status === 'SUSPENDED' && (
                <button 
                  onClick={handleSuspendToggle}
                  disabled={actionLoading}
                  className="btn btn-primary btn-sm"
                >
                  <PlayCircle className="w-3.5 h-3.5" />
                  <span>Unsuspend</span>
                </button>
              )}
              {currentCert.status === 'PENDING_ACTIVATION' && (
                <button 
                  onClick={handleSignAndActivatePendingCa}
                  disabled={actionLoading}
                  className="btn btn-primary btn-sm"
                  style={{ background: 'linear-gradient(135deg, #a855f7 0%, #6366f1 100%)' }}
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>{actionLoading ? 'Activating Sub-CA...' : '⚡ Sign with Root CA & Activate'}</span>
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {/* PKCS#12 Password Prompt Modal */}
      {showPfxModal && (
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
          <div className="glass-panel" style={{ width: '100%', maxWidth: '420px', padding: '24px' }}>
            <h4 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '8px' }}>Export PKCS#12 Keystore</h4>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
              Set an encryption password for the `.p12` keystore bundle:
            </p>
            <div className="form-group">
              <label className="form-label">Keystore Password</label>
              <input 
                type="password"
                value={pfxPassword}
                onChange={(e) => setPfxPassword(e.target.value)}
                placeholder="Enter password (e.g. changeit)"
                className="form-control"
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '16px' }}>
              <button onClick={() => setShowPfxModal(false)} className="btn btn-secondary btn-sm">Cancel</button>
              <button onClick={handleDownloadPfx} disabled={actionLoading} className="btn btn-primary btn-sm">
                {actionLoading ? 'Exporting...' : 'Download .p12'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Revocation Reason Selection Modal */}
      {showRevokeModal && (
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
          <div className="glass-panel" style={{ width: '100%', maxWidth: '440px', padding: '24px' }}>
            <h4 style={{ fontSize: '1rem', fontWeight: 700, color: '#f87171', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AlertTriangle className="w-5 h-5" />
              <span>Revoke Certificate</span>
            </h4>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
              Select an RFC 5280 revocation reason. This will publish the serial to the next CRL & OCSP responder:
            </p>
            <div className="form-group">
              <label className="form-label">RFC 5280 Revocation Reason</label>
              <select 
                value={revokeReason}
                onChange={(e) => setRevokeReason(e.target.value)}
                className="form-control"
              >
                <option value="UNSPECIFIED">0 — Unspecified</option>
                <option value="KEY_COMPROMISE">1 — Key Compromise (keyCompromise)</option>
                <option value="CA_COMPROMISE">2 — CA Compromise (cACompromise)</option>
                <option value="AFFILIATION_CHANGED">3 — Affiliation Changed (affiliationChanged)</option>
                <option value="SUPERSEDED">4 — Superseded (superseded)</option>
                <option value="CESSATION_OF_OPERATION">5 — Cessation of Operation</option>
                <option value="CERTIFICATE_HOLD">6 — Certificate Hold (temporary)</option>
              </select>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '16px' }}>
              <button onClick={() => setShowRevokeModal(false)} className="btn btn-secondary btn-sm">Cancel</button>
              <button onClick={handleRevoke} disabled={actionLoading} className="btn btn-danger btn-sm">
                {actionLoading ? 'Revoking...' : 'Confirm Revocation'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
