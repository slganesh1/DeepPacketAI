import { BrowserRouter, Routes, Route } from "react-router-dom";
import { useEffect, useState } from "react";
import { api } from "./api/client";
import AppLayout from "./layouts/AppLayout";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import CapturePage from "./pages/CapturePage";
import PacketsPage from "./pages/PacketsPage";
import JobsPage from "./pages/JobsPage";
import JobDetailPage from "./pages/JobDetailPage";
import EntityDetailPage from "./pages/EntityDetailPage";
import ChatPage from "./pages/ChatPage";
import AlertsPage from "./pages/AlertsPage";
import AnalyticsPage from "./pages/AnalyticsPage";
import UploadPage from "./pages/UploadPage";
import TelecomTracePage from "./pages/TelecomTracePage";
import SecurityPage from "./pages/SecurityPage";
import ObservabilityPage from "./pages/ObservabilityPage";
import PluginsPage from "./pages/PluginsPage";
import AlertingPage from "./pages/AlertingPage";
import DetectionRulesPage from "./pages/DetectionRulesPage";
import GeoPage from "./pages/GeoPage";
import AgentsPage from "./pages/AgentsPage";

export default function App() {
  const [authUser, setAuthUser] = useState<string | null>(null);
  const [authChecked, setAuthChecked] = useState(false);

  // On mount, see if we already have a valid session
  useEffect(() => {
    api.get("/auth/me")
      .then(res => setAuthUser(res.data.username))
      .catch(() => setAuthUser(null))
      .finally(() => setAuthChecked(true));
  }, []);

  const handleLogout = async () => {
    await api.post("/auth/logout").catch(() => {});
    setAuthUser(null);
  };

  if (!authChecked) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-slate-500 text-sm animate-pulse">Loading…</div>
      </div>
    );
  }

  if (!authUser) {
    return <LoginPage onLogin={setAuthUser} />;
  }

  return (
    <BrowserRouter>
      <AppLayout username={authUser} onLogout={handleLogout}>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/capture" element={<CapturePage />} />
          <Route path="/packets" element={<PacketsPage />} />
          <Route path="/jobs" element={<JobsPage />} />
          <Route path="/jobs/:jobId" element={<JobDetailPage />} />
          <Route path="/entities/:entityId" element={<EntityDetailPage />} />
          <Route path="/upload" element={<UploadPage />} />
          <Route path="/chat" element={<ChatPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/telecom" element={<TelecomTracePage />} />
          <Route path="/security" element={<SecurityPage />} />
          <Route path="/observability" element={<ObservabilityPage />} />
          <Route path="/plugins" element={<PluginsPage />} />
          <Route path="/alerting" element={<AlertingPage />} />
          <Route path="/detection-rules" element={<DetectionRulesPage />} />
          <Route path="/geo" element={<GeoPage />} />
          <Route path="/agents" element={<AgentsPage />} />
        </Routes>
      </AppLayout>
    </BrowserRouter>
  );
}
