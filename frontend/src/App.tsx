import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ToastProvider } from './context/ToastContext';
import { AppLayout } from './components/layout/AppLayout';
import type { TabId } from './components/layout/Sidebar';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { ChainView } from './pages/ChainView';
import { CertificatesList } from './pages/CertificatesList';
import { Operations } from './pages/Operations';
import { CrlView } from './pages/CrlView';
import { AuditView } from './pages/AuditView';
import { ReportsView } from './pages/ReportsView';
import { KeysView } from './pages/KeysView';

const MainContent: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const [activeTab, setActiveTab] = useState<TabId>('dashboard');

  if (!isAuthenticated) {
    return <Login />;
  }

  const renderTab = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard onNavigate={(tab) => setActiveTab(tab)} />;
      case 'chain':
        return <ChainView />;
      case 'certificates':
        return <CertificatesList />;
      case 'operations':
        return <Operations />;
      case 'crl':
        return <CrlView />;
      case 'audit':
        return <AuditView />;
      case 'reports':
        return <ReportsView />;
      case 'keys':
        return <KeysView />;
      default:
        return <Dashboard onNavigate={(tab) => setActiveTab(tab)} />;
    }
  };

  return (
    <AppLayout activeTab={activeTab} onSelectTab={setActiveTab}>
      {renderTab()}
    </AppLayout>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <ToastProvider>
        <MainContent />
      </ToastProvider>
    </AuthProvider>
  );
};

export default App;
