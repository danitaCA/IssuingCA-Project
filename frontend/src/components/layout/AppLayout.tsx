import React from 'react';
import { Sidebar, type TabId } from './Sidebar';
import { Navbar } from './Navbar';

interface AppLayoutProps {
  activeTab: TabId;
  onSelectTab: (tab: TabId) => void;
  children: React.ReactNode;
}

export const AppLayout: React.FC<AppLayoutProps> = ({ activeTab, onSelectTab, children }) => {
  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-primary)' }}>
      <Sidebar activeTab={activeTab} onSelectTab={onSelectTab} />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <Navbar />
        <main style={{ padding: '28px', flex: 1 }}>
          {children}
        </main>
      </div>
    </div>
  );
};
