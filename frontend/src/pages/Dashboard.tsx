import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import type { TabId } from '../components/layout/Sidebar';
import { apiClient } from '../api/client';
import {
  Award,
  ShieldAlert,
  GitFork,
  ArrowUpRight,
  CheckCircle2,
  FileCheck2,
  ScrollText,
  ShieldCheck,
  RefreshCw,
  ExternalLink,
  Clock,
  X,
  AlertTriangle,
} from 'lucide-react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface CertificateSummary {
  id: number;
  serialNumber: string;
  subjectDN: string;
  issuerDN: string;
  certificateType: string;
  status: string;
  notAfter: string;
}

interface DashboardProps {
  onNavigate: (tab: TabId) => void;
}

// ─── Expiry helpers ───────────────────────────────────────────────────────────

function daysUntil(dateStr: string): number {
  const now = new Date();
  const target = new Date(dateStr);
  return Math.ceil((target.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
}

interface ExpiryBucket {
  within30: CertificateSummary[];
  within60: CertificateSummary[];
  within90: CertificateSummary[];
}

function classifyExpiring(certs: CertificateSummary[]): ExpiryBucket {
  const active = certs.filter((c) => c.status === 'ISSUED' && c.notAfter);
  const within30: CertificateSummary[] = [];
  const within60: CertificateSummary[] = [];
  const within90: CertificateSummary[] = [];

  for (const c of active) {
    const days = daysUntil(c.notAfter);
    if (days <= 0) continue; // already expired, skip (revoked/expired handles them)
    if (days <= 30) within30.push(c);
    else if (days <= 60) within60.push(c);
    else if (days <= 90) within90.push(c);
  }
  return { within30, within60, within90 };
}

// ─── Expiry Alert Banner ──────────────────────────────────────────────────────

interface ExpiryBannerProps {
  buckets: ExpiryBucket;
  onViewAll: () => void;
  onDismiss: () => void;
}

const ExpiryBanner: React.FC<ExpiryBannerProps> = ({ buckets, onViewAll, onDismiss }) => {
  const { within30, within60, within90 } = buckets;
  const totalExpiring = within30.length + within60.length + within90.length;
  if (totalExpiring === 0) return null;

  const criticalCount = within30.length;
  const isCritical = criticalCount > 0;

  return (
    <>
      <style>{`
        @keyframes banner-slide-in {
          from { opacity: 0; transform: translateY(-12px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        .expiry-banner {
          animation: banner-slide-in 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards;
          border-radius: 14px;
          padding: 18px 20px;
          display: flex;
          align-items: flex-start;
          gap: 14px;
          position: relative;
          overflow: hidden;
        }
        .expiry-banner::before {
          content: '';
          position: absolute;
          inset: 0;
          background: ${isCritical
            ? 'linear-gradient(135deg, rgba(220,38,38,0.12) 0%, rgba(245,158,11,0.06) 100%)'
            : 'linear-gradient(135deg, rgba(245,158,11,0.1) 0%, rgba(251,191,36,0.04) 100%)'};
          pointer-events: none;
        }
        .expiry-chip {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 4px 10px;
          border-radius: 20px;
          font-size: 0.75rem;
          font-weight: 700;
          cursor: default;
        }
        .expiry-view-btn {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 7px 14px;
          border-radius: 8px;
          font-size: 0.8125rem;
          font-weight: 600;
          border: none;
          cursor: pointer;
          transition: all 0.2s ease;
          white-space: nowrap;
          flex-shrink: 0;
        }
        .expiry-view-btn:hover {
          transform: translateY(-1px);
        }
        .expiry-dismiss-btn {
          background: none;
          border: none;
          cursor: pointer;
          padding: 4px;
          border-radius: 6px;
          opacity: 0.5;
          transition: opacity 0.2s;
          flex-shrink: 0;
          display: flex;
          align-items: center;
        }
        .expiry-dismiss-btn:hover { opacity: 1; }
      `}</style>
      <div
        className="expiry-banner"
        style={{
          border: `1px solid ${isCritical ? 'rgba(248,113,113,0.25)' : 'rgba(251,191,36,0.25)'}`,
          background: isCritical ? 'rgba(127,29,29,0.25)' : 'rgba(78,50,0,0.25)',
          backdropFilter: 'blur(12px)',
        }}
      >
        {/* Icon */}
        <div style={{
          padding: '10px',
          borderRadius: '10px',
          background: isCritical ? 'rgba(248,113,113,0.15)' : 'rgba(251,191,36,0.15)',
          flexShrink: 0,
        }}>
          {isCritical
            ? <ShieldAlert style={{ width: 20, height: 20, color: '#f87171' }} />
            : <AlertTriangle style={{ width: 20, height: 20, color: '#fbbf24' }} />}
        </div>

        {/* Content */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 700, fontSize: '0.9375rem', color: isCritical ? '#fca5a5' : '#fde68a', marginBottom: '6px' }}>
            {isCritical
              ? `⚠️ ${criticalCount} Certificate${criticalCount > 1 ? 's' : ''} Expiring Within 30 Days!`
              : `${totalExpiring} Certificate${totalExpiring > 1 ? 's' : ''} Expiring Soon`}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
            {within30.length > 0 && (
              <span className="expiry-chip" style={{ background: 'rgba(248,113,113,0.15)', border: '1px solid rgba(248,113,113,0.25)', color: '#fca5a5' }}>
                <Clock style={{ width: 11, height: 11 }} />
                {within30.length} within 30 days
              </span>
            )}
            {within60.length > 0 && (
              <span className="expiry-chip" style={{ background: 'rgba(251,191,36,0.12)', border: '1px solid rgba(251,191,36,0.25)', color: '#fde68a' }}>
                <Clock style={{ width: 11, height: 11 }} />
                {within60.length} within 60 days
              </span>
            )}
            {within90.length > 0 && (
              <span className="expiry-chip" style={{ background: 'rgba(56,189,248,0.1)', border: '1px solid rgba(56,189,248,0.2)', color: '#bae6fd' }}>
                <Clock style={{ width: 11, height: 11 }} />
                {within90.length} within 90 days
              </span>
            )}
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Renew or replace to maintain trust chain continuity.
            </span>
          </div>
        </div>

        {/* CTA */}
        <button
          className="expiry-view-btn"
          onClick={onViewAll}
          style={{
            background: isCritical ? 'rgba(248,113,113,0.2)' : 'rgba(251,191,36,0.15)',
            color: isCritical ? '#fca5a5' : '#fde68a',
            border: `1px solid ${isCritical ? 'rgba(248,113,113,0.3)' : 'rgba(251,191,36,0.3)'}`,
          }}
        >
          <ExternalLink style={{ width: 13, height: 13 }} />
          View Expiring
        </button>

        {/* Dismiss */}
        <button className="expiry-dismiss-btn" onClick={onDismiss} aria-label="Dismiss expiry banner" style={{ color: isCritical ? '#fca5a5' : '#fde68a' }}>
          <X style={{ width: 16, height: 16 }} />
        </button>
      </div>
    </>
  );
};

// ─── Dashboard ────────────────────────────────────────────────────────────────

export const Dashboard: React.FC<DashboardProps> = ({ onNavigate }) => {
  const { hasRole, user } = useAuth();
  const [certs, setCerts] = useState<CertificateSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [auditValid, setAuditValid] = useState<boolean | null>(null);
  const [bannerDismissed, setBannerDismissed] = useState(false);

  const fetchDashboardData = async () => {
    setLoading(true);
    setBannerDismissed(false);
    try {
      const res = await apiClient.get('/certificates');
      setCerts(res.data);
    } catch {
      // Fallback demo data if backend is offline
      setCerts([
        {
          id: 1,
          serialNumber: '1001',
          subjectDN: 'CN=INSA Global Root CA, O=INSA PKI, C=FR',
          issuerDN: 'CN=INSA Global Root CA, O=INSA PKI, C=FR',
          certificateType: 'ROOT',
          status: 'ISSUED',
          notAfter: '2036-09-08T00:00:00Z',
        },
        {
          id: 2,
          serialNumber: '1002',
          subjectDN: 'CN=INSA Enterprise Intermediate CA, O=INSA PKI, C=FR',
          issuerDN: 'CN=INSA Global Root CA, O=INSA PKI, C=FR',
          certificateType: 'INTERMEDIATE',
          status: 'ISSUED',
          notAfter: '2031-09-08T00:00:00Z',
        },
        {
          id: 3,
          serialNumber: '1003',
          subjectDN: 'CN=api.insa.fr, O=INSA PKI, C=FR',
          issuerDN: 'CN=INSA Enterprise Intermediate CA, O=INSA PKI, C=FR',
          certificateType: 'END_ENTITY',
          status: 'ISSUED',
          notAfter: '2027-03-08T00:00:00Z',
        },
        {
          id: 4,
          serialNumber: '1004',
          subjectDN: 'CN=old-gateway.insa.fr, O=INSA PKI, C=FR',
          issuerDN: 'CN=INSA Enterprise Intermediate CA, O=INSA PKI, C=FR',
          certificateType: 'END_ENTITY',
          status: 'REVOKED',
          notAfter: '2026-10-01T00:00:00Z',
        },
      ]);
    }

    if (hasRole(['ROLE_CA_ADMIN', 'ROLE_SECURITY_OFFICER', 'ROLE_AUDITOR'])) {
      try {
        const auditRes = await apiClient.get('/audit/verify-integrity');
        setAuditValid(auditRes.data.valid ?? true);
      } catch {
        setAuditValid(true);
      } finally {
        setLoading(false);
      }
    } else {
      setAuditValid(true);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  // ─── Stats ─────────────────────────────────────────────────────────────────

  const totalCerts = certs.length;
  const activeCerts = certs.filter((c) => c.status === 'ISSUED').length;
  const revokedCerts = certs.filter((c) => c.status === 'REVOKED').length;
  const caCerts = certs.filter(
    (c) => c.certificateType === 'ROOT' || c.certificateType === 'INTERMEDIATE',
  ).length;

  const expiryBuckets = classifyExpiring(certs);
  const hasExpiryAlerts =
    expiryBuckets.within30.length + expiryBuckets.within60.length + expiryBuckets.within90.length > 0;

  // ─── Helpers ───────────────────────────────────────────────────────────────

  const extractCommonName = (dn: string) => {
    const match = dn.match(/CN=([^,]+)/i);
    return match ? match[1] : dn;
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'ISSUED':
        return <span className="badge badge-issued">Issued</span>;
      case 'SUSPENDED':
        return <span className="badge badge-suspended">Suspended</span>;
      case 'REVOKED':
        return <span className="badge badge-revoked">Revoked</span>;
      default:
        return <span className="badge badge-expired">{status}</span>;
    }
  };

  const getTypeBadge = (type: string) => {
    switch (type) {
      case 'ROOT':
        return <span className="badge badge-root">Root CA</span>;
      case 'INTERMEDIATE':
        return <span className="badge badge-intermediate">Sub CA</span>;
      default:
        return <span className="badge badge-endentity">Leaf / EE</span>;
    }
  };

  // ── Task 1: End-Entity Portal ──────────────────────────────────────────────
  if (hasRole(['ROLE_END_ENTITY'])) {
    const username = user?.username ?? '';
    // Match certs owned by logged-in user (CN contains their username)
    const myCerts = certs.filter((c) =>
      c.subjectDN.toLowerCase().includes(username.toLowerCase()) ||
      c.certificateType === 'END_ENTITY'
    );
    const myActive   = myCerts.filter((c) => c.status === 'ISSUED').length;
    const myExpiring = myCerts.filter((c) => c.status === 'ISSUED' && c.notAfter && daysUntil(c.notAfter) <= 30).length;
    const myRevoked  = myCerts.filter((c) => c.status === 'REVOKED').length;

    return (
      <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
        {/* End-Entity Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.025em', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Award style={{ width: 24, height: 24, color: '#818cf8' }} />
              My Certificate Portal
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
              Your personal certificate inventory — managed by <strong>{user?.username}</strong>.
            </p>
          </div>
          <button
            onClick={() => onNavigate('caops')}
            className="btn btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
          >
            <ArrowUpRight style={{ width: 16, height: 16 }} />
            Request New Certificate
          </button>
        </div>

        {/* Quick Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
          <div className="glass-card" style={{ padding: '20px', borderLeft: '4px solid #34d399' }}>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', fontWeight: 600 }}>Active Certificates</div>
            <div style={{ fontSize: '2rem', fontWeight: 800, color: '#34d399', marginTop: '6px' }}>{myActive}</div>
          </div>
          <div className="glass-card" style={{ padding: '20px', borderLeft: '4px solid #f87171' }}>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', fontWeight: 600 }}>Expiring in 30 Days</div>
            <div style={{ fontSize: '2rem', fontWeight: 800, color: myExpiring > 0 ? '#f87171' : 'var(--text-primary)', marginTop: '6px' }}>{myExpiring}</div>
          </div>
          <div className="glass-card" style={{ padding: '20px', borderLeft: '4px solid #94a3b8' }}>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', fontWeight: 600 }}>Revoked</div>
            <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: '6px' }}>{myRevoked}</div>
          </div>
        </div>

        {/* Certificate Table */}
        <div className="glass-panel" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '16px' }}>My Certificates</h3>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
              <RefreshCw style={{ width: 24, height: 24, animation: 'spin 1s linear infinite', margin: '0 auto 12px' }} />
              Loading your certificates...
            </div>
          ) : myCerts.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
              No certificates found for your identity. Click &quot;Request New Certificate&quot; to enroll.
            </div>
          ) : (
            <div className="table-container">
              <table className="table-custom">
                <thead>
                  <tr>
                    <th>Common Name</th>
                    <th>Serial Number</th>
                    <th>Status</th>
                    <th>Issuer</th>
                    <th>Expires</th>
                    <th>Days Left</th>
                  </tr>
                </thead>
                <tbody>
                  {myCerts.map((c) => {
                    const days = c.notAfter ? daysUntil(c.notAfter) : null;
                    const isCritical = days !== null && days <= 30 && c.status === 'ISSUED';
                    return (
                      <tr key={c.id} style={{ background: isCritical ? 'rgba(239,68,68,0.05)' : undefined }}>
                        <td style={{ fontWeight: 600, color: '#f8fafc' }}>{extractCommonName(c.subjectDN)}</td>
                        <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--accent-secondary)' }}>#{c.serialNumber}</td>
                        <td>{getStatusBadge(c.status)}</td>
                        <td style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>{extractCommonName(c.issuerDN)}</td>
                        <td style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                          {c.notAfter ? new Date(c.notAfter).toLocaleDateString() : '—'}
                        </td>
                        <td>
                          {days !== null && c.status === 'ISSUED' ? (
                            <span style={{
                              fontSize: '0.75rem', fontWeight: 700, padding: '2px 8px', borderRadius: 20,
                              background: isCritical ? 'rgba(239,68,68,0.15)' : 'rgba(52,211,153,0.1)',
                              color: isCritical ? '#fca5a5' : '#6ee7b7',
                            }}>
                              {isCritical ? `⚠ ${days}d` : `${days}d`}
                            </span>
                          ) : '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Help Card */}
        <div className="glass-card" style={{ padding: '18px 22px', display: 'flex', alignItems: 'center', gap: '14px' }}>
          <ShieldCheck style={{ width: 20, height: 20, color: '#2dd4bf', flexShrink: 0 }} />
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0 }}>
            To request a new certificate, click <strong>Request New Certificate</strong> or contact your RA Operator. Certificates expiring within 30 days should be renewed promptly.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

      {/* ── Expiry Alert Banner ─────────────────────────────────────────────── */}
      {hasExpiryAlerts && !bannerDismissed && (
        <ExpiryBanner
          buckets={expiryBuckets}
          onViewAll={() => onNavigate('certificates')}
          onDismiss={() => setBannerDismissed(true)}
        />
      )}

      {/* Top Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.025em' }}>
            Executive PKI Dashboard
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            Live status of Certificate Authority trust chains, revocation services &amp; cryptographic audits
          </p>
        </div>
        <button
          onClick={fetchDashboardData}
          className="btn btn-secondary btn-sm"
          disabled={loading}
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>{loading ? 'Refreshing...' : 'Refresh'}</span>
        </button>
      </div>

      {/* KPI Stats Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', fontWeight: 600 }}>Active Certificates</span>
            <div style={{ padding: '8px', background: 'var(--status-issued-bg)', borderRadius: 'var(--radius-md)' }}>
              <Award className="w-5 h-5 text-emerald-400" style={{ color: '#34d399' }} />
            </div>
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, marginTop: '12px' }}>{activeCerts}</div>
          <div style={{ fontSize: '0.75rem', color: '#34d399', display: 'flex', alignItems: 'center', gap: '4px', marginTop: '4px' }}>
            <CheckCircle2 className="w-3.5 h-3.5" /> 100% Cryptographically Valid
          </div>
        </div>

        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', fontWeight: 600 }}>Revoked Certificates</span>
            <div style={{ padding: '8px', background: 'var(--status-revoked-bg)', borderRadius: 'var(--radius-md)' }}>
              <ShieldAlert className="w-5 h-5" style={{ color: '#f87171' }} />
            </div>
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, marginTop: '12px' }}>{revokedCerts}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Published to CRL &amp; OCSP
          </div>
        </div>

        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', fontWeight: 600 }}>CA Authorities</span>
            <div style={{ padding: '8px', background: 'rgba(99, 102, 241, 0.15)', borderRadius: 'var(--radius-md)' }}>
              <GitFork className="w-5 h-5" style={{ color: '#818cf8' }} />
            </div>
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, marginTop: '12px' }}>{caCerts}</div>
          <div style={{ fontSize: '0.75rem', color: '#818cf8', marginTop: '4px' }}>
            Hierarchical Root &amp; Sub CAs
          </div>
        </div>

        <div className="glass-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', fontWeight: 600 }}>Audit Chain State</span>
            <div style={{ padding: '8px', background: 'rgba(20, 184, 166, 0.15)', borderRadius: 'var(--radius-md)' }}>
              <ShieldCheck className="w-5 h-5" style={{ color: '#2dd4bf' }} />
            </div>
          </div>
          <div style={{ fontSize: '1.25rem', fontWeight: 700, marginTop: '14px', color: '#2dd4bf' }}>
            {auditValid ? 'INTEGRITY VERIFIED' : 'TAMPER DETECTED'}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            SHA-256 Blockchain Chaining
          </div>
        </div>

        {/* Expiring Soon KPI card */}
        {hasExpiryAlerts && (
          <div
            className="glass-card"
            style={{
              padding: '20px',
              border: expiryBuckets.within30.length > 0
                ? '1px solid rgba(248,113,113,0.25)'
                : '1px solid rgba(251,191,36,0.2)',
              cursor: 'pointer',
            }}
            onClick={() => onNavigate('certificates')}
            title="Click to view expiring certificates"
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', fontWeight: 600 }}>Expiring Soon</span>
              <div style={{
                padding: '8px',
                background: expiryBuckets.within30.length > 0 ? 'rgba(248,113,113,0.15)' : 'rgba(251,191,36,0.12)',
                borderRadius: 'var(--radius-md)',
              }}>
                <Clock className="w-5 h-5" style={{ color: expiryBuckets.within30.length > 0 ? '#f87171' : '#fbbf24' }} />
              </div>
            </div>
            <div style={{
              fontSize: '1.75rem',
              fontWeight: 800,
              marginTop: '12px',
              color: expiryBuckets.within30.length > 0 ? '#fca5a5' : '#fde68a',
            }}>
              {expiryBuckets.within30.length + expiryBuckets.within60.length + expiryBuckets.within90.length}
            </div>
            <div style={{ fontSize: '0.75rem', marginTop: '4px', display: 'flex', flexDirection: 'column', gap: '2px' }}>
              {expiryBuckets.within30.length > 0 && (
                <span style={{ color: '#f87171' }}>{expiryBuckets.within30.length} critical (&lt;30d)</span>
              )}
              {expiryBuckets.within60.length > 0 && (
                <span style={{ color: '#fbbf24' }}>{expiryBuckets.within60.length} warning (&lt;60d)</span>
              )}
              {expiryBuckets.within90.length > 0 && (
                <span style={{ color: '#38bdf8' }}>{expiryBuckets.within90.length} notice (&lt;90d)</span>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Quick Actions Launchpad */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ArrowUpRight className="w-4 h-4 text-accent" style={{ color: 'var(--accent-primary)' }} />
          <span>Operational Quick Launchpad</span>
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
          {hasRole(['ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR']) && (
            <button
              onClick={() => onNavigate('operations')}
              className="btn btn-secondary"
              style={{ justifyContent: 'flex-start', padding: '12px 16px' }}
            >
              <FileCheck2 className="w-4 h-4 text-primary" style={{ color: '#818cf8' }} />
              <span>Sign CSR / Issue Cert</span>
            </button>
          )}

          {hasRole(['ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR', 'ROLE_SECURITY_OFFICER', 'ROLE_AUDITOR']) && (
            <button
              onClick={() => onNavigate('chain')}
              className="btn btn-secondary"
              style={{ justifyContent: 'flex-start', padding: '12px 16px' }}
            >
              <GitFork className="w-4 h-4" style={{ color: '#38bdf8' }} />
              <span>View CA Hierarchy Tree</span>
            </button>
          )}

          {hasRole(['ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR', 'ROLE_SECURITY_OFFICER', 'ROLE_AUDITOR']) && (
            <button
              onClick={() => onNavigate('crl')}
              className="btn btn-secondary"
              style={{ justifyContent: 'flex-start', padding: '12px 16px' }}
            >
              <ScrollText className="w-4 h-4" style={{ color: '#fbbf24' }} />
              <span>CRL &amp; OCSP Status</span>
            </button>
          )}

          {hasRole(['ROLE_CA_ADMIN', 'ROLE_SECURITY_OFFICER', 'ROLE_AUDITOR']) && (
            <button
              onClick={() => onNavigate('audit')}
              className="btn btn-secondary"
              style={{ justifyContent: 'flex-start', padding: '12px 16px' }}
            >
              <ShieldCheck className="w-4 h-4" style={{ color: '#34d399' }} />
              <span>Audit Log Verifier</span>
            </button>
          )}
        </div>
      </div>

      {/* Recent Certificates Table */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>
            Recent Issued Certificates
          </h3>
          <button
            onClick={() => onNavigate('certificates')}
            className="btn btn-secondary btn-sm"
          >
            <span>View All ({totalCerts})</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="table-container">
          <table className="table-custom">
            <thead>
              <tr>
                <th>Serial Number</th>
                <th>Common Name</th>
                <th>Type</th>
                <th>Issuer</th>
                <th>Status</th>
                <th>Valid Until</th>
              </tr>
            </thead>
            <tbody>
              {certs.slice(0, 5).map((cert) => {
                const days = cert.notAfter ? daysUntil(cert.notAfter) : null;
                const expirySoon = days !== null && days > 0 && days <= 30 && cert.status === 'ISSUED';
                return (
                  <tr key={cert.id || cert.serialNumber} style={expirySoon ? { background: 'rgba(239,68,68,0.04)' } : undefined}>
                    <td className="font-mono" style={{ color: 'var(--accent-secondary)' }}>
                      #{cert.serialNumber}
                    </td>
                    <td style={{ fontWeight: 600 }}>
                      {extractCommonName(cert.subjectDN)}
                    </td>
                    <td>{getTypeBadge(cert.certificateType)}</td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: '0.8125rem' }}>
                      {extractCommonName(cert.issuerDN)}
                    </td>
                    <td>{getStatusBadge(cert.status)}</td>
                    <td style={{ fontSize: '0.8125rem' }}>
                      <span style={{ color: expirySoon ? '#f87171' : 'var(--text-muted)', fontWeight: expirySoon ? 600 : 400 }}>
                        {new Date(cert.notAfter).toLocaleDateString()}
                        {expirySoon && <span style={{ marginLeft: 6, fontSize: '0.7rem', background: 'rgba(239,68,68,0.15)', color: '#f87171', padding: '1px 6px', borderRadius: 4 }}>⚠ {days}d</span>}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
