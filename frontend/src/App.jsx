import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import UrlScanner from './pages/UrlScanner';
import EmailScanner from './pages/EmailScanner';
import ScanHistory from './pages/ScanHistory';
import ModelPerformance from './pages/ModelPerformance';
import Settings from './pages/Settings';
import api from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [darkMode, setDarkMode] = useState(true);
  const [isOnline, setIsOnline] = useState(false);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const checkHealth = async () => {
    try {
      const data = await api.getHealth();
      setIsOnline(data.status === 'healthy' || data.status === 'degraded');
    } catch {
      setIsOnline(false);
    }
  };

  const renderActivePage = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard onNavigate={(tab) => setActiveTab(tab)} />;
      case 'url-scanner':
        return <UrlScanner />;
      case 'email-scanner':
        return <EmailScanner />;
      case 'history':
        return <ScanHistory />;
      case 'models':
        return <ModelPerformance />;
      case 'settings':
        return <Settings />;
      default:
        return <Dashboard onNavigate={(tab) => setActiveTab(tab)} />;
    }
  };

  return (
    <div className={`min-h-screen ${darkMode ? 'dark bg-slate-950 text-slate-100' : 'bg-slate-50 text-slate-900'}`}>
      <Navbar 
        isOnline={isOnline} 
        darkMode={darkMode} 
        setDarkMode={setDarkMode} 
      />

      <div className="flex h-[calc(100vh-4rem)] overflow-hidden">
        <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
        
        <main className="flex-1 overflow-y-auto p-8">
          <div className="mx-auto max-w-7xl">
            {renderActivePage()}
          </div>
        </main>
      </div>
    </div>
  );
}
