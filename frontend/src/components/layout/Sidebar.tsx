import React from 'react';
import { useAuth, type UserRole } from '../../context/AuthContext';
import { 
  LayoutDashboard, 
  GitFork, 
  FileCheck2, 
  KeyRound, 
  FileText, 
  ShieldCheck, 
  ScrollText, 
  Award,
  Layers
} from 'lucide-react';

export type TabId = 
  | 'dashboard' 
  | 'chain' 
  | 'certificates' 
  | 'operations' 
  | 'crl' 
  | 'audit' 
  | 'reports' 
  | 'keys';

interface NavItem {
  id: TabId;
  label: string;
  icon: React.ReactNode;
  allowedRoles: UserRole[];
}

const NAV_ITEMS: NavItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: <LayoutDashboard className="w-5 h-5" />,
    allowedRoles: ['ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR', 'ROLE_SECURITY_OFFICER', 'ROLE_AUDITOR', 'ROLE_END_ENTITY'],
  },
  {
    id: 'chain',
    label: 'CA Hierarchy Tree',
    icon: <GitFork className="w-5 h-5" />,
    allowedRoles: ['ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR', 'ROLE_SECURITY_OFFICER', 'ROLE_AUDITOR'],
  },
  {
    id: 'certificates',
    label: 'Certificates',
    icon: <Award className="w-5 h-5" />,
    allowedRoles: ['ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR', 'ROLE_SECURITY_OFFICER', 'ROLE_AUDITOR', 'ROLE_END_ENTITY'],
  },
  {
    id: 'operations',
    label: 'CA Operations & Sign',
    icon: <FileCheck2 className="w-5 h-5" />,
    allowedRoles: ['ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR'],
  },
  {
    id: 'crl',
    label: 'CRL & OCSP',
    icon: <ScrollText className="w-5 h-5" />,
    allowedRoles: ['ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR', 'ROLE_SECURITY_OFFICER', 'ROLE_AUDITOR'],
  },
  {
    id: 'audit',
    label: 'Immutable Audit Logs',
    icon: <ShieldCheck className="w-5 h-5" />,
    allowedRoles: ['ROLE_CA_ADMIN', 'ROLE_SECURITY_OFFICER', 'ROLE_AUDITOR'],
  },
  {
    id: 'reports',
    label: 'Compliance Reports',
    icon: <FileText className="w-5 h-5" />,
    allowedRoles: ['ROLE_CA_ADMIN', 'ROLE_RA_OPERATOR', 'ROLE_SECURITY_OFFICER', 'ROLE_AUDITOR'],
  },
  {
    id: 'keys',
    label: 'HSM & Key Vault',
    icon: <KeyRound className="w-5 h-5" />,
    allowedRoles: ['ROLE_CA_ADMIN', 'ROLE_SECURITY_OFFICER'],
  },
];

interface SidebarProps {
  activeTab: TabId;
  onSelectTab: (tab: TabId) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onSelectTab }) => {
  const { hasRole } = useAuth();

  return (
    <aside style={{
      width: 'var(--sidebar-width)',
      background: 'var(--bg-secondary)',
      borderRight: '1px solid var(--border-color)',
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      position: 'sticky',
      top: 0,
    }}>
      {/* Brand Header */}
      <div style={{
        height: 'var(--header-height)',
        padding: '0 20px',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        borderBottom: '1px solid var(--border-color)',
      }}>
        <div style={{
          width: '36px',
          height: '36px',
          borderRadius: 'var(--radius-md)',
          background: 'var(--accent-gradient)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: 'var(--shadow-glow)',
        }}>
          <Layers className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 style={{ fontSize: '1rem', fontWeight: 700, letterSpacing: '-0.02em' }}>INSA PKI CA</h1>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Trust Authority v5.0</p>
        </div>
      </div>

      {/* Navigation List */}
      <nav style={{ padding: '16px 12px', display: 'flex', flexDirection: 'column', gap: '6px', flex: 1, overflowY: 'auto' }}>
        <div style={{ padding: '4px 12px', fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Management
        </div>
        {NAV_ITEMS.map((item) => {
          const isAllowed = hasRole(item.allowedRoles);
          if (!isAllowed) return null; // Strictly hide if not allowed by RBAC

          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '10px 14px',
                borderRadius: 'var(--radius-md)',
                fontSize: '0.875rem',
                fontWeight: isActive ? 600 : 500,
                color: isActive ? 'white' : 'var(--text-secondary)',
                background: isActive ? 'rgba(99, 102, 241, 0.15)' : 'transparent',
                border: isActive ? '1px solid rgba(99, 102, 241, 0.3)' : '1px solid transparent',
                cursor: 'pointer',
                textAlign: 'left',
                width: '100%',
                transition: 'all 0.15s ease',
              }}
              onMouseEnter={(e) => {
                if (!isActive) e.currentTarget.style.background = 'rgba(255, 255, 255, 0.04)';
              }}
              onMouseLeave={(e) => {
                if (!isActive) e.currentTarget.style.background = 'transparent';
              }}
            >
              <span style={{ color: isActive ? 'var(--accent-secondary)' : 'inherit' }}>
                {item.icon}
              </span>
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div style={{
        padding: '16px',
        borderTop: '1px solid var(--border-color)',
        fontSize: '0.75rem',
        color: 'var(--text-muted)',
      }}>
        <div>INSA PKI Issuing CA Platform</div>
        <div style={{ fontSize: '0.6875rem', color: '#6366f1' }}>FIPS 140-2 / RFC 5280 Ready</div>
      </div>
    </aside>
  );
};
