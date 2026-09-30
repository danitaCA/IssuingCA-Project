import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, User as UserIcon, ArrowRight, AlertCircle, Activity } from 'lucide-react';

export const Login: React.FC = () => {
  const { login } = useAuth();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('adminpassword');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [focusedField, setFocusedField] = useState<string | null>(null);

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
    <>
      <style>
        {`
          @keyframes ambient-glow {
            0% { transform: translate(0, 0) scale(1); opacity: 0.3; }
            33% { transform: translate(5%, 10%) scale(1.1); opacity: 0.5; }
            66% { transform: translate(-5%, 5%) scale(0.9); opacity: 0.4; }
            100% { transform: translate(0, 0) scale(1); opacity: 0.3; }
          }
          @keyframes pulse-shield {
            0% { box-shadow: 0 0 15px rgba(56, 189, 248, 0.4), inset 0 0 10px rgba(56, 189, 248, 0.2); }
            50% { box-shadow: 0 0 35px rgba(56, 189, 248, 0.8), inset 0 0 20px rgba(56, 189, 248, 0.4); }
            100% { box-shadow: 0 0 15px rgba(56, 189, 248, 0.4), inset 0 0 10px rgba(56, 189, 248, 0.2); }
          }
          @keyframes slide-up {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
          }
          .login-page-root {
            min-height: 100vh;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            background-color: #020617;
            background-image:
              radial-gradient(circle at 15% 50%, rgba(56, 189, 248, 0.08) 0%, transparent 40%),
              radial-gradient(circle at 85% 30%, rgba(99, 102, 241, 0.08) 0%, transparent 40%);
            overflow: hidden;
            padding: 20px;
            box-sizing: border-box;
          }
          .login-page-root::before {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0IiBoZWlnaHQ9IjQiPgo8cmVjdCB3aWR0aD0iNCIgaGVpZ2h0PSI0IiBmaWxsPSIjZmZmIiBmaWxsLW9wYWNpdHk9IjAuMDUiLz4KPC9zdmc+') repeat;
            opacity: 0.3;
            pointer-events: none;
          }
          .login-card {
            position: relative;
            z-index: 10;
            max-width: 440px;
            width: 100%;
            padding: 48px 40px;
            background: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 24px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6), inset 0 1px 0 rgba(255,255,255,0.1);
            animation: slide-up 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards;
          }
          .shield-icon-container {
            width: 72px;
            height: 72px;
            border-radius: 20px;
            background: linear-gradient(135deg, #0ea5e9, #3b82f6);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            animation: pulse-shield 3s ease-in-out infinite;
            margin: 0 auto 28px auto;
            transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            border: 1px solid rgba(255, 255, 255, 0.2);
          }
          .shield-icon-container:hover {
            transform: scale(1.1) rotate(5deg);
          }
          .input-animated {
            transition: all 0.3s ease;
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #f8fafc;
          }
          .input-animated:focus {
            background: rgba(15, 23, 42, 1);
            border-color: #38bdf8;
            box-shadow: 0 0 0 4px rgba(56, 189, 248, 0.15);
            transform: translateY(-2px);
          }
          .input-icon {
            transition: color 0.3s ease;
          }
          .input-animated:focus + .input-icon {
            color: #38bdf8 !important;
          }
          .btn-login {
            background: linear-gradient(135deg, #0ea5e9 0%, #3b82f6 100%);
            border: none;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
            transform: translateY(0);
            box-shadow: 0 10px 20px -10px rgba(56, 189, 248, 0.5);
            color: white;
            cursor: pointer;
          }
          .btn-login:hover {
            transform: translateY(-3px);
            box-shadow: 0 15px 25px -10px rgba(56, 189, 248, 0.7);
          }
          .btn-login:active {
            transform: translateY(1px);
          }
          .stagger-item {
            opacity: 0;
            animation: slide-up 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
          }
          .stagger-1 { animation-delay: 0.1s; }
          .stagger-2 { animation-delay: 0.2s; }
          .stagger-3 { animation-delay: 0.3s; }
          .stagger-4 { animation-delay: 0.4s; }
        `}
      </style>

      <div className="login-page-root">
        <div className="login-card">

          <div style={{ textAlign: 'center', marginBottom: '36px' }}>
            <div className="shield-icon-container stagger-item stagger-1">
              <Shield className="w-9 h-9 text-white" />
            </div>
            <h2 className="stagger-item stagger-2" style={{ fontSize: '1.85rem', fontWeight: 800, letterSpacing: '-0.025em', color: '#f8fafc', margin: '0 0 8px 0' }}>
              INSA PKI CA Vault
            </h2>
            <p className="stagger-item stagger-2" style={{ color: '#94a3b8', fontSize: '0.95rem', margin: 0, fontWeight: 500 }}>
              Secure Authentication Gateway
            </p>
          </div>

          {error && (
            <div className="stagger-item stagger-2" style={{
              padding: '14px',
              borderRadius: '12px',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.2)',
              color: '#fca5a5',
              fontSize: '0.875rem',
              marginBottom: '24px',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              animation: 'slide-up 0.3s ease-out'
            }}>
              <AlertCircle className="w-5 h-5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} autoComplete="off">
            <div className="form-group stagger-item stagger-3">
              <label className="form-label" htmlFor="username" style={{ color: focusedField === 'username' ? '#38bdf8' : '#cbd5e1', transition: 'color 0.3s ease', fontWeight: 600, fontSize: '0.85rem', marginBottom: '8px', display: 'block' }}>
                Identity Principal
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  id="username"
                  type="text"
                  autoComplete="off"
                  className="form-control input-animated"
                  style={{ paddingLeft: '48px', height: '52px', fontSize: '1rem', borderRadius: '12px' }}
                  value={username}
                  onFocus={() => setFocusedField('username')}
                  onBlur={() => setFocusedField(null)}
                  onChange={(e) => {
                    const val = e.target.value;
                    setUsername(val);
                    setPassword(getPersonaPassword(val));
                  }}
                  required
                />
                <UserIcon className="w-5 h-5 input-icon" style={{ position: 'absolute', left: '16px', top: '16px', color: focusedField === 'username' ? '#38bdf8' : '#64748b', pointerEvents: 'none' }} />
              </div>
            </div>

            <div className="form-group stagger-item stagger-3" style={{ marginBottom: '36px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <label className="form-label" htmlFor="password" style={{ margin: 0, color: focusedField === 'password' ? '#38bdf8' : '#cbd5e1', transition: 'color 0.3s ease', fontWeight: 600, fontSize: '0.85rem' }}>
                  Cryptographic Secret
                </label>
              </div>
              <div style={{ position: 'relative' }}>
                <input
                  id="password"
                  type="password"
                  autoComplete="new-password"
                  className="form-control input-animated"
                  style={{ paddingLeft: '48px', height: '52px', fontSize: '1rem', borderRadius: '12px', letterSpacing: '2px' }}
                  value={password}
                  onFocus={() => setFocusedField('password')}
                  onBlur={() => setFocusedField(null)}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
                <Lock className="w-5 h-5 input-icon" style={{ position: 'absolute', left: '16px', top: '16px', color: focusedField === 'password' ? '#38bdf8' : '#64748b', pointerEvents: 'none' }} />
              </div>
            </div>

            <button
              type="submit"
              className="btn-login stagger-item stagger-4"
              style={{ width: '100%', height: '56px', fontSize: '1.05rem', fontWeight: 700, borderRadius: '12px', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '10px' }}
              disabled={loading}
            >
              {loading ? (
                <>
                  <Activity className="w-5 h-5 animate-spin" />
                  Establishing Secure Session...
                </>
              ) : (
                <>
                  Initialize Secure Context
                  <ArrowRight className="w-5 h-5" />
                </>
              )}
            </button>
          </form>

          {/* Demo Persona Quick Selectors */}
          <div className="stagger-item stagger-4" style={{ marginTop: '40px', paddingTop: '28px', borderTop: '1px solid rgba(255,255,255,0.08)' }}>
            <div style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '16px', textAlign: 'center', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 800 }}>
              Quick Persona Inject
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px' }}>
              <button
                type="button"
                onClick={() => handleQuickLogin('admin')}
                className="btn btn-secondary btn-sm"
                style={{ fontSize: '0.75rem', padding: '12px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '10px', cursor: 'pointer' }}
              >
                <span className="badge badge-root" style={{ padding: '4px 8px', width: '100%', background: 'rgba(168, 85, 247, 0.2)', color: '#d8b4fe' }}>CA Admin</span>
              </button>
              <button
                type="button"
                onClick={() => handleQuickLogin('operator')}
                className="btn btn-secondary btn-sm"
                style={{ fontSize: '0.75rem', padding: '12px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '10px', cursor: 'pointer' }}
              >
                <span className="badge badge-intermediate" style={{ padding: '4px 8px', width: '100%', background: 'rgba(56, 189, 248, 0.2)', color: '#7dd3fc' }}>RA Operator</span>
              </button>
              <button
                type="button"
                onClick={() => handleQuickLogin('secofficer')}
                className="btn btn-secondary btn-sm"
                style={{ fontSize: '0.75rem', padding: '12px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '10px', cursor: 'pointer' }}
              >
                <span className="badge badge-suspended" style={{ padding: '4px 8px', width: '100%', background: 'rgba(245, 158, 11, 0.2)', color: '#fcd34d' }}>Sec Officer</span>
              </button>
              <button
                type="button"
                onClick={() => handleQuickLogin('auditor')}
                className="btn btn-secondary btn-sm"
                style={{ fontSize: '0.75rem', padding: '12px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '10px', cursor: 'pointer' }}
              >
                <span className="badge badge-issued" style={{ padding: '4px 8px', width: '100%', background: 'rgba(16, 185, 129, 0.2)', color: '#6ee7b7' }}>Auditor</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};
