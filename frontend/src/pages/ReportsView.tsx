import React, { useState } from 'react';
import { pkiApi } from '../api/pkiApi';
import { 
  FileText, 
  Download, 
  FileSpreadsheet, 
  ShieldCheck, 
  Award, 
  Sparkles
} from 'lucide-react';

export const ReportsView: React.FC = () => {
  const [engine, setEngine] = useState<'jasper' | 'openpdf'>('jasper');
  const [downloading, setDownloading] = useState<string | null>(null);

  const handleDownloadReport = async (reportType: 'cert_pdf' | 'audit_pdf' | 'compliance_pdf' | 'cert_csv') => {
    setDownloading(reportType);
    try {
      let blob: Blob;
      let filename: string;

      if (reportType === 'cert_pdf') {
        blob = await pkiApi.downloadCertificateInventoryPdf(engine);
        filename = `Certificate_Inventory_${new Date().toISOString().split('T')[0]}.pdf`;
      } else if (reportType === 'audit_pdf') {
        blob = await pkiApi.downloadAuditTrailPdf(engine);
        filename = `Audit_Trail_Report_${new Date().toISOString().split('T')[0]}.pdf`;
      } else if (reportType === 'compliance_pdf') {
        blob = await pkiApi.downloadCompliancePdf();
        filename = `Compliance_Assessment_${new Date().toISOString().split('T')[0]}.pdf`;
      } else {
        blob = await pkiApi.downloadCertificateCsv();
        filename = `Certificate_Inventory_${new Date().toISOString().split('T')[0]}.csv`;
      }

      if (!blob || blob.size === 0) {
        throw new Error('Received empty report payload from server.');
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      let errMsg = 'Failed to generate and download report.';
      if (err && typeof err === 'object') {
        const axErr = err as { response?: { data?: Blob | string; status?: number }; message?: string };
        if (axErr.response?.status === 403) {
          errMsg = 'Permission Denied: Your current role does not have authorization to download this report. Please switch to CA_ADMIN, AUDITOR, or SECURITY_OFFICER.';
        } else if (axErr.message) {
          errMsg = axErr.message;
        }
      }
      alert(errMsg);
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.025em', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <FileText className="w-6 h-6 text-indigo-400" style={{ color: '#818cf8' }} />
            <span>Compliance &amp; Operational Reports Engine</span>
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            Digitally signed audit assessments, inventory export sheets, and ISO 27001 / eIDAS compliance readouts.
          </p>
        </div>

        {/* Engine Switcher */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(255,255,255,0.04)', padding: '6px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)' }}>
          <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>PDF Engine:</span>
          <select
            value={engine}
            onChange={(e) => setEngine(e.target.value as typeof engine)}
            className="form-control"
            style={{ padding: '4px 8px', fontSize: '0.8125rem', width: 'auto' }}
          >
            <option value="jasper">JasperReports Engine (Enterprise Layout)</option>
            <option value="openpdf">OpenPDF Engine (High Throughput)</option>
          </select>
        </div>
      </div>

      {/* Reports Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
        {/* Report 1: Certificate Inventory */}
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
              <div style={{ padding: '8px', background: 'rgba(99, 102, 241, 0.2)', borderRadius: 'var(--radius-md)' }}>
                <Award className="w-5 h-5 text-indigo-400" />
              </div>
              <div>
                <h3 style={{ fontSize: '1.0625rem', fontWeight: 700 }}>Certificate Inventory Export</h3>
                <span className="badge badge-intermediate" style={{ fontSize: '0.6875rem', marginTop: '2px' }}>Operational</span>
              </div>
            </div>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', lineHeight: '1.6' }}>
              Complete breakdown of all Root CAs, Subordinate Issuing CAs, and Leaf end-entity certificates with serials, DNs, algorithms, and expiration status.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <button
              onClick={() => handleDownloadReport('cert_pdf')}
              disabled={downloading === 'cert_pdf'}
              className="btn btn-primary btn-sm"
              style={{ flex: 1 }}
            >
              <Download className="w-3.5 h-3.5" />
              <span>{downloading === 'cert_pdf' ? 'Generating...' : 'Export PDF'}</span>
            </button>
            <button
              onClick={() => handleDownloadReport('cert_csv')}
              disabled={downloading === 'cert_csv'}
              className="btn btn-secondary btn-sm"
              style={{ flex: 1 }}
            >
              <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        {/* Report 2: Audit Trail Report */}
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
              <div style={{ padding: '8px', background: 'rgba(20, 184, 166, 0.2)', borderRadius: 'var(--radius-md)' }}>
                <ShieldCheck className="w-5 h-5 text-teal-400" />
              </div>
              <div>
                <h3 style={{ fontSize: '1.0625rem', fontWeight: 700 }}>Audit Trail &amp; Verification</h3>
                <span className="badge badge-issued" style={{ fontSize: '0.6875rem', marginTop: '2px' }}>Security Audit</span>
              </div>
            </div>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', lineHeight: '1.6' }}>
              Tamper-evident verification report certifying that all administrative, cryptographic signing, and revocation events retain intact SHA-256 hash chaining.
            </p>
          </div>

          <button
            onClick={() => handleDownloadReport('audit_pdf')}
            disabled={downloading === 'audit_pdf'}
            className="btn btn-primary btn-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{downloading === 'audit_pdf' ? 'Generating...' : 'Download Signed Audit PDF'}</span>
          </button>
        </div>

        {/* Report 3: Executive Compliance Assessment */}
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
              <div style={{ padding: '8px', background: 'rgba(168, 85, 247, 0.2)', borderRadius: 'var(--radius-md)' }}>
                <Sparkles className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <h3 style={{ fontSize: '1.0625rem', fontWeight: 700 }}>Executive Compliance Assessment</h3>
                <span className="badge badge-root" style={{ fontSize: '0.6875rem', marginTop: '2px' }}>ISO 27001 / eIDAS</span>
              </div>
            </div>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', lineHeight: '1.6' }}>
              Executive compliance summary validating CA policy controls, non-exportable hardware key boundaries (FIPS 140-3 Level 2+), and high-availability CRL/OCSP uptime.
            </p>
          </div>

          <button
            onClick={() => handleDownloadReport('compliance_pdf')}
            disabled={downloading === 'compliance_pdf'}
            className="btn btn-primary btn-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{downloading === 'compliance_pdf' ? 'Generating...' : 'Download Executive Report PDF'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
