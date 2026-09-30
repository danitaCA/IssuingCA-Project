import { apiClient } from './client';

export interface KeyPairItem {
  id: number;
  algorithm: string;
  keySize: number;
  publicKeyPEM: string;
  privateKeyPEM?: string;
  createdAt: string;
  user?: {
    id: number;
    username: string;
  };
}

export interface CertificateItem {
  id: number;
  serialNumber: string;
  subjectDN: string;
  issuerDN: string;
  notBefore?: string;
  notAfter?: string;
  publicKeyPEM: string;
  status: 'ISSUED' | 'REVOKED' | 'SUSPENDED' | 'PENDING_ACTIVATION';
  revocationReason?: string;
  revocationDate?: string;
  pemContent: string;
  certificateType: 'ROOT' | 'INTERMEDIATE' | 'END_ENTITY' | 'OCSP_SIGNER';
  profileName: string;
}

export interface CertificateProfile {
  id?: number;
  name: string;
  description?: string;
  keyUsage?: string;
  extendedKeyUsage?: string;
  basicConstraints: boolean;
  pathLenConstraint?: number;
  validityDays: number;
  signatureAlgorithm: string;
  caSerialNumber?: string;
  tokenType?: 'ADVISED_GENERATED' | 'USER_GENERATED';
  crlDistributionPoint?: string;
  ocspUrl?: string;
}

export interface SubCaCsrResponse {
  serialNumber: string;
  subjectDN: string;
  csrPem: string;
  publicKeyPEM: string;
  keyAlgorithm: string;
  keySize: number;
}

export interface EndEntityEnrollRequest {
  username: string;
  email?: string;
  commonName: string;
  organization?: string;
  country?: string;
  orgUnit?: string;
  state?: string;
  locality?: string;
  profileName: string;
  caSerialNumber?: string;
  keyGenerationMode: 'ADVISED_GENERATED' | 'USER_GENERATED';
  keyType?: 'RSA' | 'EC';
  keySize?: number;
  csrPem?: string;
  adminPassword?: string;
}

export interface EndEntityEnrollResponse {
  certificate: CertificateItem;
  pkcs12Base64?: string;
  certificatePem: string;
  chainPem: string;
  message: string;
}

export interface CrlItem {
  id: number;
  caSerialNumber: string;
  crlNumber: number;
  crlType: 'FULL' | 'DELTA';
  thisUpdate: string;
  nextUpdate: string;
  crlPem?: string;
  createdAt: string;
}

export interface AuditLogItem {
  id: number;
  timestamp: string;
  username: string;
  action: string;
  details: string;
  status: string;
  ipAddress: string;
  prevHash?: string;
  currentHash?: string;
}

export const pkiApi = {
  // Keys & Tokens
  generateKey: async (algorithm = 'RSA', keySize = 4096) => {
    const res = await apiClient.post<KeyPairItem>('/keys/generate', { algorithm, keySize });
    return res.data;
  },
  listKeys: async () => {
    const res = await apiClient.get<KeyPairItem[]>('/keys');
    return res.data;
  },
  getKey: async (id: number) => {
    const res = await apiClient.get<KeyPairItem>(`/keys/${id}`);
    return res.data;
  },
  generateCsrForKey: async (keyId: number, subjectDN?: string) => {
    const res = await apiClient.get<string>(`/keys/generate-csr/${keyId}`, {
      params: subjectDN ? { subjectDN } : undefined,
    });
    return res.data;
  },
  deleteKey: async (keyId: number) => {
    const res = await apiClient.delete(`/keys/${keyId}`);
    return res.data;
  },

  // Certificates & CAs
  initRootCa: async (data: {
    subjectDN: string;
    keyType: string;
    keySizeOrCurve: number;
    profileName?: string;
  }) => {
    const res = await apiClient.post<CertificateItem>('/certificates/cas/root', data);
    return res.data;
  },
  initIntermediateCa: async (data: {
    subjectDN: string;
    parentSerialNumber: string;
    keyType: string;
    keySizeOrCurve: number;
    profileName?: string;
  }) => {
    const res = await apiClient.post<CertificateItem>('/certificates/cas/intermediate', data);
    return res.data;
  },
  generateSubCaCsr: async (data: {
    subjectDN: string;
    keyType: string;
    keySizeOrCurve: number;
    signatureAlgorithm?: string;
  }) => {
    const res = await apiClient.post<SubCaCsrResponse>('/certificates/cas/intermediate/csr', data);
    return res.data;
  },
  importSignedCaCert: async (data: {
    caSerialNumber?: string;
    signedCertPem: string;
  }) => {
    const res = await apiClient.post<CertificateItem>('/certificates/cas/intermediate/import', data);
    return res.data;
  },
  issueOcspSigner: async (caSerialNumber: string) => {
    const res = await apiClient.post<CertificateItem>(`/certificates/cas/${caSerialNumber}/ocsp-signer`);
    return res.data;
  },
  signCsr: async (data: {
    csrPem: string;
    caSerialNumber: string;
    profileName?: string;
  }) => {
    const res = await apiClient.post<CertificateItem>('/certificates/sign', data);
    return res.data;
  },
  enrollEndEntity: async (data: EndEntityEnrollRequest) => {
    const res = await apiClient.post<EndEntityEnrollResponse>('/certificates/enroll', data);
    return res.data;
  },
  listCertificates: async () => {
    const res = await apiClient.get<CertificateItem[]>('/certificates');
    return res.data;
  },
  getCertificate: async (serialNumber: string) => {
    const res = await apiClient.get<CertificateItem>(`/certificates/${serialNumber}`);
    return res.data;
  },
  getCertificatePem: async (serialNumber: string) => {
    const res = await apiClient.get<string>(`/certificates/${serialNumber}/pem`);
    return res.data;
  },
  getCertificateChain: async (serialNumber: string) => {
    const res = await apiClient.get<string>(`/certificates/${serialNumber}/chain`);
    return res.data;
  },
  downloadPkcs12: async (serialNumber: string, password = 'changeit') => {
    const res = await apiClient.post(`/certificates/${serialNumber}/pkcs12?password=${encodeURIComponent(password)}`, null, {
      responseType: 'blob',
    });
    return res.data;
  },
  renewCertificate: async (serialNumber: string) => {
    const res = await apiClient.post<CertificateItem>(`/certificates/${serialNumber}/renew`);
    return res.data;
  },
  suspendCertificate: async (serialNumber: string) => {
    const res = await apiClient.post<CertificateItem>(`/certificates/${serialNumber}/suspend`);
    return res.data;
  },
  unsuspendCertificate: async (serialNumber: string) => {
    const res = await apiClient.post<CertificateItem>(`/certificates/${serialNumber}/unsuspend`);
    return res.data;
  },
  revokeCertificate: async (serialNumber: string, reason = 'UNSPECIFIED') => {
    const res = await apiClient.post<CertificateItem>(`/certificates/${serialNumber}/revoke`, { reason });
    return res.data;
  },

  // Profiles
  listProfiles: async () => {
    const res = await apiClient.get<CertificateProfile[]>('/profiles');
    return res.data;
  },
  getProfile: async (id: number) => {
    const res = await apiClient.get<CertificateProfile>(`/profiles/${id}`);
    return res.data;
  },
  saveProfile: async (profile: CertificateProfile) => {
    const res = await apiClient.post<CertificateProfile>('/profiles', profile);
    return res.data;
  },
  deleteProfile: async (id: number) => {
    const res = await apiClient.delete(`/profiles/${id}`);
    return res.data;
  },

  // CRL & Validation
  getLatestFullCrl: async (caSerialNumber: string) => {
    const res = await apiClient.get<CrlItem>(`/crl/${caSerialNumber}/latest`);
    return res.data;
  },
  getLatestDeltaCrl: async (caSerialNumber: string) => {
    const res = await apiClient.get<CrlItem>(`/crl/${caSerialNumber}/delta`);
    return res.data;
  },
  regenerateCrl: async (caSerialNumber: string) => {
    const res = await apiClient.post<CrlItem>(`/crl/${caSerialNumber}/regenerate`);
    return res.data;
  },
  getCrlHistory: async (caSerialNumber: string) => {
    const res = await apiClient.get<CrlItem[]>(`/crl/${caSerialNumber}/history`);
    return res.data;
  },

  // Audit
  getAuditLogs: async (page = 0, size = 50) => {
    const res = await apiClient.get<{ content: AuditLogItem[]; totalElements: number; totalPages: number }>(`/audit/logs?page=${page}&size=${size}`);
    return res.data;
  },
  verifyAuditIntegrity: async () => {
    const res = await apiClient.get<{ valid: boolean; totalRecords: number; rootHash?: string; message?: string }>('/audit/verify-integrity');
    return res.data;
  },
  exportSiemEvents: async () => {
    const res = await apiClient.get<Record<string, unknown>[]>('/audit/export/siem');
    return res.data;
  },

  // Reports
  downloadCertificateInventoryPdf: async (engine = 'jasper') => {
    const res = await apiClient.get(`/reports/certificates/pdf?engine=${engine}`, { responseType: 'blob' });
    return res.data;
  },
  downloadAuditTrailPdf: async (engine = 'jasper') => {
    const res = await apiClient.get(`/reports/audit/pdf?engine=${engine}`, { responseType: 'blob' });
    return res.data;
  },
  downloadCompliancePdf: async () => {
    const res = await apiClient.get('/reports/compliance/pdf', { responseType: 'blob' });
    return res.data;
  },
  downloadCertificateCsv: async () => {
    const res = await apiClient.get('/reports/certificates/csv', { responseType: 'blob' });
    return res.data;
  },
};
