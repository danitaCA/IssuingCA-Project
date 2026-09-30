import React, { useEffect, useRef, useState } from 'react';
import type { CertificateItem } from '../api/pkiApi';
import { pkiApi } from '../api/pkiApi';
import { CertificateViewerModal } from '../components/CertificateViewerModal';
import { useToast } from '../context/ToastContext';
import {
  Award,
  Search,
  RefreshCw,
  Eye,
  MoreHorizontal,
  RotateCcw,
  PauseCircle,
  PlayCircle,
  ShieldOff,
  AlertTriangle,
  FileDown,
} from 'lucide-react';

// ─── RFC 5280 Revocation Reasons ─────────────────────────────────────────────

const REVOCATION_REASONS = [
  { value: 'UNSPECIFIED', label: 'Unspecified' },
  { value: 'KEY_COMPROMISE', label: 'Key Compromise' },
  { value: 'CA_COMPROMISE', label: 'CA Compromise' },
  { value: 'AFFILIATION_CHANGED', label: 'Affiliation Changed' },
  { value: 'SUPERSEDED', label: 'Superseded' },
  { value: 'CESSATION_OF_OPERATION', label: 'Cessation of Operation' },
  { value: 'CERTIFICATE_HOLD', label: 'Certificate Hold' },
  { value: 'PRIVILEGE_WITHDRAWN', label: 'Privilege Withdrawn' },
  { value: 'AA_COMPROMISE', label: 'AA Compromise' },
];

// ─── Confirmation Modal ───────────────────────────────────────────────────────

type DestructiveAction = 'revoke' | 'suspend';

interface ConfirmModalProps {
  action: DestructiveAction;
  cert: CertificateItem;
  onConfirm: (reason?: string) => void;
  onCancel: () => void;
}

const ConfirmModal: React.FC<ConfirmModalProps> = ({ action, cert, onConfirm, onCancel }) => {
  const [reason, setReason] = useState('UNSPECIFIED');
  const isRevoke = action === 'revoke';

  const extractCn = (dn: string) => {
    const match = dn.match(/CN=([^,]+)/i);
    return match ? match[1] : dn;
  };

  return (
    <>
      <style>{`
        @keyframes modal-backdrop-in {
          from { opacity: 0; }
          to   { opacity: 1; }
        }
        @keyframes modal-card-in {
          from { opacity: 0; transform: translateY(-20px) scale(0.96); }
          to   { opacity: 1; transform: translateY(0) scale(1); }
        }
        .confirm-backdrop {
          position: fixed; inset: 0;
          background: rgba(2, 6, 23, 0.75);
          backdrop-filter: blur(6px);
          display: flex; align-items: center; justify-content: center;
          z-index: 1000;
          animation: modal-backdrop-in 0.2s ease forwards;
          padding: 16px;
        }
        .confirm-card {
          background: rgba(15, 23, 42, 0.95);
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 16px;
          padding: 28px 32px;
          max-width: 480px;
          width: 100%;
          box-shadow: 0 25px 60px rgba(0,0,0,0.5);
          animation: modal-card-in 0.25s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
      `}</style>
      <div className="confirm-backdrop" onClick={onCancel}>
        <div className="confirm-card" onClick={(e) => e.stopPropagation()}>
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
            <div style={{
              padding: '10px',
              borderRadius: '12px',
              background: isRevoke ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
            }}>
              {isRevoke
                ? <ShieldOff style={{ width: 22, height: 22, color: '#f87171' }} />
                : <PauseCircle style={{ width: 22, height: 22, color: '#fbbf24' }} />}
            </div>
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc', margin: 0 }}>
                {isRevoke ? 'Revoke Certificate' : 'Suspend Certificate'}
              </h3>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: 0 }}>
                {isRevoke ? 'This action is permanent and irreversible.' : 'The certificate will be put on hold.'}
              </p>
            </div>
          </div>

          {/* Warning */}
          <div style={{
            padding: '12px 14px',
            borderRadius: '10px',
            background: 'rgba(245, 158, 11, 0.08)',
            border: '1px solid rgba(245, 158, 11, 0.2)',
            display: 'flex', gap: '10px', alignItems: 'flex-start',
            marginBottom: '20px',
          }}>
            <AlertTriangle style={{ width: 16, height: 16, color: '#fbbf24', marginTop: 2, flexShrink: 0 }} />
            <span style={{ fontSize: '0.8125rem', color: '#fde68a', lineHeight: 1.5 }}>
              Certificate <strong>#{cert.serialNumber}</strong> — <strong>{extractCn(cert.subjectDN)}</strong>{' '}
              will be {isRevoke ? 'permanently revoked and added to the CRL' : 'suspended (CRL Reason: certificateHold)'}.
            </span>
          </div>

          {/* Reason Selector (both actions for RFC 5280) */}
          <div style={{ marginBottom: '24px' }}>
            <label style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#cbd5e1', display: 'block', marginBottom: '8px' }}>
              RFC 5280 Revocation Reason
            </label>
            <select
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="form-control"
              style={{ fontSize: '0.875rem' }}
            >
              {REVOCATION_REASONS.map((r) => (
                <option key={r.value} value={r.value}>{r.label}</option>
              ))}
            </select>
          </div>

          {/* Buttons */}
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
            <button
              onClick={onCancel}
              className="btn btn-secondary btn-sm"
              style={{ minWidth: 90 }}
            >
              Cancel
            </button>
            <button
              onClick={() => onConfirm(reason)}
              className="btn btn-sm"
              style={{
                minWidth: 120,
                background: isRevoke ? 'linear-gradient(135deg, #dc2626, #b91c1c)' : 'linear-gradient(135deg, #d97706, #b45309)',
                border: 'none',
                color: 'white',
                fontWeight: 600,
                borderRadius: 8,
                padding: '8px 16px',
                cursor: 'pointer',
                boxShadow: isRevoke ? '0 4px 14px rgba(220,38,38,0.4)' : '0 4px 14px rgba(217,119,6,0.4)',
              }}
            >
              {isRevoke ? 'Confirm Revoke' : 'Confirm Suspend'}
            </button>
          </div>
        </div>
      </div>
    </>
  );
};

// ─── Action Menu ──────────────────────────────────────────────────────────────

interface ActionMenuProps {
  cert: CertificateItem;
  onAction: (action: string, cert: CertificateItem) => void;
  busy: boolean;
}

const ActionMenu: React.FC<ActionMenuProps> = ({ cert, onAction, busy }) => {
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const isActive = cert.status === 'ISSUED';
  const isSuspended = cert.status === 'SUSPENDED';
  const isRevoked = cert.status === 'REVOKED';

  return (
    <>
      <style>{`
        @keyframes dropdown-in {
          from { opacity: 0; transform: scale(0.92) translateY(-6px); }
          to   { opacity: 1; transform: scale(1) translateY(0); }
        }
        .action-dropdown {
          position: absolute;
          right: 0;
          top: calc(100% + 6px);
          z-index: 500;
          background: rgba(15, 23, 42, 0.98);
          border: 1px solid rgba(255,255,255,0.12);
          border-radius: 12px;
          padding: 6px;
          min-width: 170px;
          box-shadow: 0 16px 40px rgba(0,0,0,0.5);
          animation: dropdown-in 0.18s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
        .action-dropdown-btn {
          display: flex;
          align-items: center;
          gap: 10px;
          width: 100%;
          padding: 9px 12px;
          background: none;
          border: none;
          border-radius: 8px;
          font-size: 0.8125rem;
          font-weight: 500;
          cursor: pointer;
          text-align: left;
          transition: background 0.15s ease;
          white-space: nowrap;
        }
        .action-dropdown-btn:hover:not(:disabled) {
          background: rgba(255,255,255,0.07);
        }
        .action-dropdown-btn:disabled {
          opacity: 0.35;
          cursor: not-allowed;
        }
      `}</style>
      <div style={{ position: 'relative', display: 'inline-block' }} ref={menuRef}>
        <button
          className="btn btn-secondary btn-sm"
          style={{ padding: '6px 10px', gap: '6px' }}
          onClick={(e) => { e.stopPropagation(); setOpen((o) => !o); }}
          disabled={busy}
          aria-label="Actions"
          title="Certificate Actions"
        >
          <Eye className="w-3.5 h-3.5" style={{ color: '#818cf8' }} />
          <MoreHorizontal className="w-3.5 h-3.5" />
        </button>

        {open && (
          <div className="action-dropdown" onClick={(e) => e.stopPropagation()}>
            {/* Inspect — always visible */}
            <button
              className="action-dropdown-btn"
              style={{ color: '#94a3b8' }}
              onClick={() => { setOpen(false); onAction('inspect', cert); }}
            >
              <Eye style={{ width: 14, height: 14, color: '#818cf8' }} />
              Inspect
            </button>

            {/* Renew — active or suspended */}
            {(isActive || isSuspended) && (
              <button
                className="action-dropdown-btn"
                style={{ color: '#93c5fd' }}
                onClick={() => { setOpen(false); onAction('renew', cert); }}
                disabled={busy}
              >
                <RotateCcw style={{ width: 14, height: 14, color: '#60a5fa' }} />
                Renew
              </button>
            )}

            {/* Suspend — active only */}
            {isActive && (
              <button
                className="action-dropdown-btn"
                style={{ color: '#fde68a' }}
                onClick={() => { setOpen(false); onAction('suspend', cert); }}
                disabled={busy}
              >
                <PauseCircle style={{ width: 14, height: 14, color: '#fbbf24' }} />
                Suspend
              </button>
            )}

            {/* Unsuspend — suspended only */}
            {isSuspended && (
              <button
                className="action-dropdown-btn"
                style={{ color: '#a7f3d0' }}
                onClick={() => { setOpen(false); onAction('unsuspend', cert); }}
                disabled={busy}
              >
                <PlayCircle style={{ width: 14, height: 14, color: '#34d399' }} />
                Unsuspend
              </button>
            )}

            {/* Revoke — active or suspended */}
            {(isActive || isSuspended) && !isRevoked && (
              <>
                <div style={{ height: 1, background: 'rgba(255,255,255,0.07)', margin: '4px 0' }} />
                <button
                  className="action-dropdown-btn"
                  style={{ color: '#fca5a5' }}
                  onClick={() => { setOpen(false); onAction('revoke', cert); }}
                  disabled={busy}
                >
                  <ShieldOff style={{ width: 14, height: 14, color: '#f87171' }} />
                  Revoke
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </>
  );
};

// ─── Main Component ───────────────────────────────────────────────────────────

export const CertificatesList: React.FC = () => {
  const { showToast } = useToast();
  const [certs, setCerts] = useState<CertificateItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [selectedCert, setSelectedCert] = useState<CertificateItem | null>(null);

  // Lifecycle action state
  const [busyCertId, setBusyCertId] = useState<number | null>(null);
  const [confirmState, setConfirmState] = useState<{
    action: DestructiveAction;
    cert: CertificateItem;
  } | null>(null);

  const fetchCerts = async () => {
    setLoading(true);
    try {
      const data = await pkiApi.listCertificates();
      data.sort((a, b) => (b.id || 0) - (a.id || 0));
      setCerts(data);
    } catch {
      // Fallback mock data
      setCerts([
        {
          id: 1,
          serialNumber: '1001',
          subjectDN: 'CN=INSA Global Root CA, O=INSA PKI, C=FR',
          issuerDN: 'CN=INSA Global Root CA, O=INSA PKI, C=FR',
          certificateType: 'ROOT',
          status: 'ISSUED',
          profileName: 'RootCA',
          notBefore: '2026-09-08T00:00:00Z',
          notAfter: '2036-09-08T00:00:00Z',
          publicKeyPEM: '-----BEGIN PUBLIC KEY-----\n...',
          pemContent: '-----BEGIN CERTIFICATE-----\nMIIDqzCCApOgAwIBAgIU...\n-----END CERTIFICATE-----',
        },
        {
          id: 2,
          serialNumber: '1002',
          subjectDN: 'CN=INSA Enterprise Issuing CA v1, O=INSA PKI, C=FR, OU=Security',
          issuerDN: 'CN=INSA Global Root CA, O=INSA PKI, C=FR',
          certificateType: 'INTERMEDIATE',
          status: 'ISSUED',
          profileName: 'SubCA',
          notBefore: '2026-09-08T00:00:00Z',
          notAfter: '2031-09-08T00:00:00Z',
          publicKeyPEM: '-----BEGIN PUBLIC KEY-----\n...',
          pemContent: '-----BEGIN CERTIFICATE-----\nMIIDqzCCApOgAwIBAgIU...\n-----END CERTIFICATE-----',
        },
        {
          id: 3,
          serialNumber: '1003',
          subjectDN: 'CN=john.doe.insa.fr, O=INSA PKI, C=FR, OU=Engineering',
          issuerDN: 'CN=INSA Enterprise Issuing CA v1, O=INSA PKI, C=FR',
          certificateType: 'END_ENTITY',
          status: 'ISSUED',
          profileName: 'EnterpriseEndEntity',
          notBefore: '2026-09-08T00:00:00Z',
          notAfter: '2027-09-08T00:00:00Z',
          publicKeyPEM: '-----BEGIN PUBLIC KEY-----\n...',
          pemContent: '-----BEGIN CERTIFICATE-----\nMIIDqzCCApOgAwIBAgIU...\n-----END CERTIFICATE-----',
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCerts();
  }, []);

  // ─── Lifecycle Action Handler ──────────────────────────────────────────────

  const handleAction = (action: string, cert: CertificateItem) => {
    if (action === 'inspect') {
      setSelectedCert(cert);
      return;
    }
    if (action === 'revoke' || action === 'suspend') {
      setConfirmState({ action, cert });
      return;
    }
    executeAction(action, cert);
  };

  const executeAction = async (action: string, cert: CertificateItem, reason?: string) => {
    setBusyCertId(cert.id);
    try {
      let updated: CertificateItem | null = null;
      switch (action) {
        case 'renew':
          updated = await pkiApi.renewCertificate(cert.serialNumber);
          showToast(`Certificate #${cert.serialNumber} renewed successfully.`, 'success');
          break;
        case 'suspend':
          updated = await pkiApi.suspendCertificate(cert.serialNumber);
          showToast(`Certificate #${cert.serialNumber} suspended.`, 'warning');
          break;
        case 'unsuspend':
          updated = await pkiApi.unsuspendCertificate(cert.serialNumber);
          showToast(`Certificate #${cert.serialNumber} unsuspended — now active.`, 'success');
          break;
        case 'revoke':
          updated = await pkiApi.revokeCertificate(cert.serialNumber, reason || 'UNSPECIFIED');
          showToast(`Certificate #${cert.serialNumber} revoked (${reason || 'UNSPECIFIED'}).`, 'error');
          break;
      }
      // Optimistically update the row
      if (updated) {
        setCerts((prev) =>
          prev.map((c) => (c.id === updated!.id ? updated! : c)),
        );
      } else {
        // If API doesn't return updated cert, do a full refresh
        await fetchCerts();
      }
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: string } })?.response?.data || 'Action failed. Check API connection.';
      showToast(msg, 'error');
    } finally {
      setBusyCertId(null);
    }
  };

  const handleConfirm = (reason?: string) => {
    if (!confirmState) return;
    const { action, cert } = confirmState;
    setConfirmState(null);
    executeAction(action, cert, reason);
  };

  // ─── Helpers ───────────────────────────────────────────────────────────────

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

  // ─── CSV Export ────────────────────────────────────────────────────────────
  const [csvExporting, setCsvExporting] = useState(false);

  const handleExportCsv = async () => {
    setCsvExporting(true);
    try {
      const blob = await pkiApi.downloadCertificateCsv();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `pki-certificate-inventory-${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('Certificate inventory exported to CSV successfully.', 'success');
    } catch {
      showToast('CSV export failed — check API connectivity.', 'error');
    } finally {
      setCsvExporting(false);
    }
  };

  const filteredCerts = certs.filter((c) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      c.serialNumber.toLowerCase().includes(q) ||
      c.subjectDN.toLowerCase().includes(q) ||
      c.issuerDN.toLowerCase().includes(q) ||
      (c.profileName && c.profileName.toLowerCase().includes(q));

    const matchesStatus = statusFilter === 'ALL' || c.status === statusFilter;
    const matchesType = typeFilter === 'ALL' || c.certificateType === typeFilter;

    return matchesSearch && matchesStatus && matchesType;
  });

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.025em', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Award className="w-6 h-6 text-indigo-400" style={{ color: '#818cf8' }} />
            <span>Digital Certificate Inventory</span>
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            Searchable X.509 v3 repository with chain inspection, lifecycle actions, and keystore downloads.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button
            onClick={handleExportCsv}
            disabled={csvExporting}
            className="btn btn-secondary btn-sm"
          >
            <FileDown className={`w-4 h-4 ${csvExporting ? 'animate-pulse' : ''}`} style={{ color: '#34d399' }} />
            <span>{csvExporting ? 'Exporting...' : 'Export CSV'}</span>
          </button>
          <button onClick={fetchCerts} className="btn btn-secondary btn-sm" disabled={loading}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-panel" style={{ padding: '16px 20px', display: 'flex', gap: '16px', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: '280px' }}>
          <div style={{ position: 'relative', width: '100%' }}>
            <Search className="w-4 h-4" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by Common Name, Serial Number, Subject DN, or Profile..."
              className="form-control"
              style={{ paddingLeft: '38px', fontSize: '0.875rem' }}
            />
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="form-control"
            style={{ width: 'auto', fontSize: '0.8125rem' }}
          >
            <option value="ALL">All Statuses</option>
            <option value="ISSUED">Issued (Active)</option>
            <option value="SUSPENDED">Suspended</option>
            <option value="REVOKED">Revoked</option>
            <option value="PENDING_ACTIVATION">Pending Activation</option>
          </select>

          {/* Type Filter */}
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="form-control"
            style={{ width: 'auto', fontSize: '0.8125rem' }}
          >
            <option value="ALL">All Types</option>
            <option value="ROOT">Root CA</option>
            <option value="INTERMEDIATE">Sub / Issuing CA</option>
            <option value="END_ENTITY">Leaf / End Entity</option>
            <option value="OCSP_SIGNER">OCSP Signer</option>
          </select>
        </div>
      </div>

      {/* Certificates Table */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>
            Results ({filteredCerts.length} Certificates)
          </h3>
        </div>

        <div className="table-container">
          <table className="table-custom">
            <thead>
              <tr>
                <th>Serial Number (Dec / Hex)</th>
                <th>Common Name (CN)</th>
                <th>Type</th>
                <th>Profile</th>
                <th>Issuer</th>
                <th>Status</th>
                <th>Expiration Date</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredCerts.map((cert) => (
                <tr key={cert.id || cert.serialNumber}>
                  <td className="font-mono">
                    <div style={{ color: 'var(--accent-secondary)', fontWeight: 600 }}>#{cert.serialNumber}</div>
                    <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>{toHexSerial(cert.serialNumber)}</div>
                  </td>
                  <td>
                    <div style={{ fontWeight: 700, color: '#f8fafc' }}>
                      {extractCn(cert.subjectDN)}
                    </div>
                    <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {cert.subjectDN}
                    </div>
                  </td>
                  <td>
                    <span className={`badge ${cert.certificateType === 'ROOT' ? 'badge-root' :
                        cert.certificateType === 'INTERMEDIATE' ? 'badge-intermediate' : 'badge-endentity'
                      }`}>
                      {cert.certificateType}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                    {cert.profileName || 'Default'}
                  </td>
                  <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                    {extractCn(cert.issuerDN)}
                  </td>
                  <td>
                    <span className={`badge ${cert.status === 'ISSUED' ? 'badge-issued' :
                        cert.status === 'SUSPENDED' ? 'badge-suspended' :
                          cert.status === 'REVOKED' ? 'badge-revoked' : 'badge-expired'
                      }`}>
                      {cert.status}
                    </span>
                    {cert.status === 'REVOKED' && cert.revocationReason && (
                      <div style={{ fontSize: '0.6875rem', color: '#f87171', marginTop: '2px', fontWeight: 600 }}>
                        {cert.revocationReason}
                      </div>
                    )}
                  </td>
                  <td style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                    {cert.notAfter ? new Date(cert.notAfter).toLocaleDateString() : 'N/A'}
                  </td>
                  <td>
                    <ActionMenu
                      cert={cert}
                      onAction={handleAction}
                      busy={busyCertId === cert.id}
                    />
                  </td>
                </tr>
              ))}
              {filteredCerts.length === 0 && (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                    No matching certificates found in database.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Certificate Viewer Modal */}
      {selectedCert && (
        <CertificateViewerModal
          certificate={selectedCert}
          onClose={() => setSelectedCert(null)}
          onRefresh={fetchCerts}
        />
      )}

      {/* Destructive Action Confirmation Modal */}
      {confirmState && (
        <ConfirmModal
          action={confirmState.action}
          cert={confirmState.cert}
          onConfirm={handleConfirm}
          onCancel={() => setConfirmState(null)}
        />
      )}
    </div>
  );
};
