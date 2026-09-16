import React, { useEffect, useState } from 'react';
import type { CertificateItem } from '../api/pkiApi';
import { pkiApi } from '../api/pkiApi';
import { CertificateViewerModal } from '../components/CertificateViewerModal';
import { 
  Award, 
  Search, 
  RefreshCw, 
  Eye
} from 'lucide-react';

export const CertificatesList: React.FC = () => {
  const [certs, setCerts] = useState<CertificateItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [selectedCert, setSelectedCert] = useState<CertificateItem | null>(null);

  const fetchCerts = async () => {
    setLoading(true);
    try {
      const data = await pkiApi.listCertificates();
      // Sort newest certificates first so renewed/issued certificates appear at top
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

  const filteredCerts = certs.filter(c => {
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

        <button onClick={fetchCerts} className="btn btn-secondary btn-sm" disabled={loading}>
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
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
                    <span className={`badge ${
                      cert.certificateType === 'ROOT' ? 'badge-root' :
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
                    <span className={`badge ${
                      cert.status === 'ISSUED' ? 'badge-issued' :
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
                    <button
                      onClick={() => setSelectedCert(cert)}
                      className="btn btn-secondary btn-sm"
                      style={{ padding: '6px 12px', gap: '6px' }}
                    >
                      <Eye className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Inspect</span>
                    </button>
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
    </div>
  );
};
