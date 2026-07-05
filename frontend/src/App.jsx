import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  BarChart3,
  Brain,
  CheckCircle2,
  ListChecks,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { getAlerts, getAttackStats, getLogs } from "./api";

const POLL_MS = 5000;

export default function App() {
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [nextLogs, nextAlerts, nextStats] = await Promise.all([
        getLogs(),
        getAlerts(),
        getAttackStats()
      ]);
      setLogs(nextLogs);
      setAlerts(nextAlerts);
      setStats(nextStats);
      setLastUpdated(new Date());
      setError("");
    } catch (err) {
      setError(err.message || "Unable to reach backend");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, POLL_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  const activeAlerts = useMemo(
    () => alerts.filter((alert) => alert.status !== "resolved"),
    [alerts]
  );

  const blockedCount = useMemo(
    () => alerts.filter((alert) => alert.status === "blocked").length,
    [alerts]
  );

  return (
    <main className="app-shell">
      <section className="topbar">
        <div>
          <p className="eyebrow">AI-Agent SIEM MVP</p>
          <h1>Security Operations Dashboard</h1>
        </div>
        <div className="topbar-actions">
          <span className={error ? "status-pill danger" : "status-pill"}>
            {error ? "Backend offline" : "Live"}
          </span>
          <button className="icon-button" type="button" title="Refresh dashboard" onClick={refresh}>
            <RefreshCw size={18} />
          </button>
        </div>
      </section>

      <section className="metric-grid" aria-label="SIEM metrics">
        <Metric icon={<TerminalSquare size={20} />} label="Logs" value={logs.length} tone="blue" />
        <Metric icon={<ShieldAlert size={20} />} label="Active Alerts" value={activeAlerts.length} tone="red" />
        <Metric icon={<ShieldCheck size={20} />} label="Blocked IPs" value={blockedCount} tone="green" />
        <Metric
          icon={<CheckCircle2 size={20} />}
          label="Last Poll"
          value={lastUpdated ? lastUpdated.toLocaleTimeString() : "--"}
          tone="amber"
        />
      </section>

      {error && <div className="error-banner">{error}</div>}

      <section className="dashboard-grid">
        <div className="panel logs-panel">
          <PanelTitle icon={<TerminalSquare size={18} />} title="Live Log Feed" />
          <LogTable logs={logs} loading={loading} />
        </div>

        <div className="panel alerts-panel">
          <PanelTitle icon={<ShieldAlert size={18} />} title="AI Alerts" />
          <AlertPanel alerts={alerts} loading={loading} />
        </div>

        <div className="panel chart-panel">
          <PanelTitle icon={<BarChart3 size={18} />} title="Attack Types" />
          <AttackTypeChart stats={stats} />
        </div>
      </section>
    </main>
  );
}

function Metric({ icon, label, value, tone }) {
  return (
    <div className={`metric metric-${tone}`}>
      <div className="metric-icon">{icon}</div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function PanelTitle({ icon, title }) {
  return (
    <div className="panel-title">
      {icon}
      <h2>{title}</h2>
    </div>
  );
}

function LogTable({ logs, loading }) {
  if (loading) {
    return <EmptyState text="Loading logs" />;
  }

  if (!logs.length) {
    return <EmptyState text="Waiting for ingested logs" />;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Event</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log) => (
            <tr key={log.log_id}>
              <td>{formatTime(log.timestamp)}</td>
              <td className="mono">{log.source_ip}</td>
              <td className="mono">{log.destination_ip}</td>
              <td>{labelize(log.event_type)}</td>
              <td>
                <span className={`severity severity-${log.severity}`}>{log.severity}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AlertPanel({ alerts, loading }) {
  if (loading) {
    return <EmptyState text="Loading alerts" />;
  }

  if (!alerts.length) {
    return <EmptyState text="No alerts yet" />;
  }

  return (
    <div className="alert-list">
      {alerts.map((alert) => (
        <article className="alert-item" key={alert.alert_id}>
          <div className="alert-heading">
            <AlertTriangle size={18} />
            <div>
              <h3>{labelize(alert.threat_type)}</h3>
              <span className="mono">{alert.source_ip}</span>
            </div>
            <span className={`alert-status status-${alert.status}`}>{alert.status}</span>
          </div>
          <p>{alert.summary || "The NLP report agent is preparing a summary."}</p>
          <div className="intel-grid">
            <div>
              <span className="intel-label">
                <Brain size={14} />
                Likely Attack
              </span>
              <strong>{alert.likely_attack || labelize(alert.threat_type)}</strong>
            </div>
            <div>
              <span className="intel-label">Tactic</span>
              <strong>{alert.mitre_tactic || "Unknown"}</strong>
            </div>
          </div>
          {alert.analyst_notes && <p className="analyst-notes">{alert.analyst_notes}</p>}
          <RecommendedActions actions={alert.recommended_actions} />
          <div className="alert-meta">
            <span className={`severity severity-${alert.severity}`}>{alert.severity}</span>
            <span className={`risk risk-${alert.risk_level || alert.severity}`}>{alert.risk_level || alert.severity}</span>
            <span>{Math.round((alert.confidence_score || 0) * 100)}% confidence</span>
            <span>{alert.llm_provider === "llm" ? "LLM analyzed" : "Fallback analyzed"}</span>
            <span>{(alert.attack_chain || []).map(labelize).join(" / ")}</span>
          </div>
        </article>
      ))}
    </div>
  );
}

function RecommendedActions({ actions = [] }) {
  if (!actions.length) {
    return null;
  }

  return (
    <div className="recommendations">
      <span className="intel-label">
        <ListChecks size={14} />
        Recommended Countermeasures
      </span>
      <ul>
        {actions.map((action) => (
          <li key={action}>{action}</li>
        ))}
      </ul>
    </div>
  );
}

function AttackTypeChart({ stats }) {
  const data = stats.map((item) => ({
    name: labelize(item.threat_type),
    count: item.count
  }));

  if (!data.length) {
    return <EmptyState text="No alert frequencies yet" />;
  }

  return (
    <div className="chart-box">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="name" tick={{ fontSize: 12 }} interval={0} angle={-12} textAnchor="end" height={72} />
          <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
          <Tooltip cursor={{ fill: "rgba(15, 23, 42, 0.06)" }} />
          <Bar dataKey="count" fill="#2563eb" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function EmptyState({ text }) {
  return <div className="empty-state">{text}</div>;
}

function labelize(value = "") {
  return String(value)
    .replaceAll("_", " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatTime(value) {
  if (!value) return "--";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "--" : date.toLocaleTimeString();
}
