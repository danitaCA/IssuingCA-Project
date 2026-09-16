import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, User as UserIcon, ArrowRight, AlertCircle } from 'lucide-react';

export const Login: React.FC = () => {
  const { login } = useAuth();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('adminpassword');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const getPersonaPassword = (uname: string) => {
    switch (uname.toLowerCase()) {
      case 'admin': return 'adminpassword';
      case 'operator': return 'operatorpassword';
      case 'secofficer': return 'secofficerpassword';
      case 'auditor': return 'auditorpassword';
      case 'endentity': return 'endentitypassword';
      default: return 'password';
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await login(username, password);
    } catch (err: unknown) {
      setError((err as { response?: { data?: string } })?.response?.data || 'Authentication failed. Please verify username and password.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickLogin = async (userKey: string) => {
    const pass = getPersonaPassword(userKey);
    setUsername(userKey);
    setPassword(pass);
    setLoading(true);
    setError(null);
    try {
      await login(userKey, pass);
    } catch (err: unknown) {
      setError((err as { response?: { data?: string } })?.response?.data || 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'radial-gradient(circle at 50% 20%, #1e1b4b 0%, #0b0f19 80%)',
      padding: '20px',
    }}>
      <div className="glass-panel animate-fade-in" style={{
        maxWidth: '480px',
        width: '100%',
        padding: '36px',
        boxShadow: 'var(--shadow-lg)',
      }}>
        {/* Brand Icon */}
        <div style={{ textAlign: 'center', marginBottom: '28px' }}>
          <div style={{
            width: '56px',
            height: '56px',
            borderRadius: '16px',
            background: 'var(--accent-gradient)',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: 'var(--shadow-glow)',
            marginBottom: '16px',
          }}>
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.025em' }}>
            INSA PKI Issuing CA
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: '4px' }}>
            Enterprise Trust Authority &amp; Lifecycle Manager
          </p>
        </div>

        {error && (
          <div style={{
            padding: '12px 14px',
            borderRadius: 'var(--radius-md)',
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            color: '#fca5a5',
            fontSize: '0.875rem',
            marginBottom: '20px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}>
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} autoComplete="off">
          <div className="form-group">
            <label className="form-label" htmlFor="username">Username / Identity</label>
            <div style={{ position: 'relative' }}>
              <input
                id="username"
                name="pki_user_name"
                type="text"
                autoComplete="off"
                className="form-control"
                style={{ paddingLeft: '38px' }}
                value={username}
                onChange={(e) => {
                  const val = e.target.value;
                  setUsername(val);
                  setPassword(getPersonaPassword(val));
                }}
                required
              />
              <UserIcon className="w-4 h-4 text-muted" style={{ position: 'absolute', left: '12px', top: '14px', color: 'var(--text-muted)' }} />
            </div>
          </div>

          <div className="form-group" style={{ marginBottom: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <label className="form-label" htmlFor="password" style={{ margin: 0 }}>Passphrase / Secret</label>
              <span style={{ fontSize: '0.75rem', color: 'var(--accent-secondary)' }}>
                Default: {username}password
              </span>
            </div>
            <div style={{ position: 'relative' }}>
              <input
                id="password"
                name="pki_user_secret"
                type="password"
                autoComplete="new-password"
                className="form-control"
                style={{ paddingLeft: '38px' }}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <Lock className="w-4 h-4 text-muted" style={{ position: 'absolute', left: '12px', top: '14px', color: 'var(--text-muted)' }} />
            </div>
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: '100%', padding: '12px', fontSize: '0.9375rem' }}
            disabled={loading}
          >
            {loading ? 'Authenticating...' : 'Sign In to CA Platform'}
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {/* Demo Persona Quick Selectors */}
        <div style={{ marginTop: '28px', paddingTop: '20px', borderTop: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '10px', textAlign: 'center' }}>
            Quick 1-click login as verified persona:
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
            <button
              type="button"
              onClick={() => handleQuickLogin('admin')}
              className="btn btn-secondary btn-sm"
              style={{ fontSize: '0.75rem', justifyContent: 'flex-start' }}
            >
              <span className="badge badge-root" style={{ padding: '2px 6px' }}>CA Admin</span>
            </button>
            <button
              type="button"
              onClick={() => handleQuickLogin('operator')}
              className="btn btn-secondary btn-sm"
              style={{ fontSize: '0.75rem', justifyContent: 'flex-start' }}
            >
              <span className="badge badge-intermediate" style={{ padding: '2px 6px' }}>RA Operator</span>
            </button>
            <button
              type="button"
              onClick={() => handleQuickLogin('secofficer')}
              className="btn btn-secondary btn-sm"
              style={{ fontSize: '0.75rem', justifyContent: 'flex-start' }}
            >
              <span className="badge badge-suspended" style={{ padding: '2px 6px' }}>Sec Officer</span>
            </button>
            <button
              type="button"
              onClick={() => handleQuickLogin('auditor')}
              className="btn btn-secondary btn-sm"
              style={{ fontSize: '0.75rem', justifyContent: 'flex-start' }}
            >
              <span className="badge badge-issued" style={{ padding: '2px 6px' }}>Auditor</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
