import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Login } from './pages/Login';
import { Sidebar, NavTab } from './components/common/Sidebar';
import { Navbar } from './components/common/Navbar';
import { Dashboard } from './pages/Dashboard';
import { LogsExplorer } from './pages/LogsExplorer';
import { AlertsManagement } from './pages/AlertsManagement';
import { ThreatGraph } from './pages/ThreatGraph';
import { AIAssistant } from './pages/AIAssistant';
import { ServersManagement } from './pages/ServersManagement';
import { RulesManagement } from './pages/RulesManagement';

const MainLayout: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  if (!isAuthenticated) {
    return <Login />;
  }

  const handleRefresh = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  const renderActiveView = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard key={refreshTrigger} setActiveTab={setActiveTab} />;
      case 'logs':
        return <LogsExplorer key={refreshTrigger} />;
      case 'alerts':
        return <AlertsManagement key={refreshTrigger} />;
      case 'graph':
        return <ThreatGraph key={refreshTrigger} />;
      case 'ai':
        return <AIAssistant key={refreshTrigger} />;
      case 'servers':
        return <ServersManagement key={refreshTrigger} />;
      case 'rules':
        return <RulesManagement key={refreshTrigger} />;
      default:
        return <Dashboard setActiveTab={setActiveTab} />;
    }
  };

  return (
    <div className="flex min-h-screen bg-[#080b11] text-slate-100 font-sans">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      <div className="flex-1 flex flex-col min-w-0">
        <Navbar activeTab={activeTab} onRefresh={handleRefresh} />
        <main className="flex-1 p-8 overflow-y-auto max-w-7xl w-full mx-auto">
          {renderActiveView()}
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <MainLayout />
    </AuthProvider>
  );
};

export default App;
