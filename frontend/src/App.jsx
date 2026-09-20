import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronRight,
  CircleGauge,
  Clock3,
  FileCheck2,
  FlaskConical,
  KeyRound,
  LockKeyhole,
  Menu,
  Radar,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  UserCheck,
  Users,
  XCircle,
  Zap,
} from "lucide-react";
import "./App.css";

const navigation = [
  ["overview", "Security Overview", CircleGauge],
  ["agents", "Live Agent Monitor", Activity],
  ["attack", "Attack Lab", FlaskConical],
  ["threats", "Threat Analysis", Radar],
  ["permissions", "Tool Permissions", KeyRound],
  ["approvals", "Human Approvals", UserCheck],
  ["audit", "Audit Trail", FileCheck2],
  ["evaluation", "Evaluation", ShieldCheck],
];

const fallbackSummary = {
  total_evaluations: 12482,
  allowed: 11806,
  denied: 37,
  required_approval: 639,
  pending_approvals: 5,
  critical_events: 37,
  average_risk_score: 18.4,
  audit_chain_valid: true,
  active_protection: true,
};

const agents = [
  ["research-agent", "Running", "Web search", "Low"],
  ["coder-agent", "Running", "Filesystem read", "Low"],
  ["analyst-agent", "Running", "Database query", "Medium"],
  ["marketing-agent", "Paused", "Email request", "High"],
  ["support-agent", "Running", "Ticket analysis", "Low"],
];

const auditRows = [
  ["10:42:18", "Action allowed", "research-agent", "read_file", "Low"],
  ["10:41:52", "Threat blocked", "coder-agent", "execute_command", "Critical"],
  ["10:40:06", "Approval created", "marketing-agent", "send_email", "High"],
  ["10:38:44", "Token issued", "analyst-agent", "capability", "Low"],
  ["10:35:19", "Policy evaluated", "support-agent", "database_query", "Medium"],
];

function Badge({ children, tone = "green" }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

function Panel({ title, action, children, className = "" }) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-heading">
        <h2>{title}</h2>
        {action && <button className="text-button">{action}</button>}
      </div>
      {children}
    </section>
  );
}

function MetricCard({ icon: Icon, label, value, detail, tone }) {
  return (
    <article className={`metric-card ${tone}`}>
      <div className="metric-icon">
        <Icon size={20} />
      </div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
    </article>
  );
}

function Overview({ summary }) {
  const metrics = [
    [Users, "Agents Protected", "24", "All identities verified", "cyan"],
    [
      Activity,
      "Actions Inspected",
      summary.total_evaluations.toLocaleString(),
      "Real-time enforcement",
      "blue",
    ],
    [
      ShieldAlert,
      "Threats Blocked",
      summary.denied,
      "Runtime attacks stopped",
      "red",
    ],
    [
      Clock3,
      "Pending Reviews",
      summary.pending_approvals,
      "Human decisions required",
      "amber",
    ],
    [
      LockKeyhole,
      "Sensitive Data Prevented",
      "18",
      "Exfiltration attempts",
      "violet",
    ],
    [
      Zap,
      "Inspection Latency",
      "142 ms",
      "Average policy response",
      "green",
    ],
  ];

  return (
    <>
      <div className="metric-grid">
        {metrics.map(([icon, label, value, detail, tone]) => (
          <MetricCard
            key={label}
            icon={icon}
            label={label}
            value={value}
            detail={detail}
            tone={tone}
          />
        ))}
      </div>

      <div className="overview-grid">
        <Panel title="Live Activity Stream" action="View all">
          <div className="activity-list">
            {[
              ["Blocked suspicious file access", "Critical", "red", "2m"],
              ["Approved browser action", "Allowed", "green", "4m"],
              ["Prevented credential exfiltration", "Blocked", "red", "6m"],
              ["Tool permission updated", "Policy", "blue", "8m"],
              ["Agent identity verified", "Verified", "green", "11m"],
            ].map(([text, status, tone, time]) => (
              <div className="activity-row" key={text}>
                <span className={`event-dot ${tone}`} />
                <div>
                  <strong>{text}</strong>
                  <small>AgentSentinel runtime gateway</small>
                </div>
                <Badge tone={tone}>{status}</Badge>
                <time>{time}</time>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Security Pipeline">
          <div className="pipeline">
            {[
              [Bot, "Agent"],
              [KeyRound, "Identity"],
              [Shield, "Policy"],
              [Radar, "Threat"],
              [ShieldCheck, "Allow / Block"],
            ].map(([Icon, name], index) => (
              <div className="pipeline-step" key={name}>
                <div className="pipeline-icon">
                  <Icon size={18} />
                </div>
                <span>{name}</span>
                {index < 4 && <ChevronRight size={16} />}
              </div>
            ))}
          </div>

          <div className="health-list">
            {[
              "Policy Engine",
              "Threat Intelligence",
              "Audit Chain",
              "Capability Tokens",
            ].map((item) => (
              <div key={item}>
                <span>{item}</span>
                <Badge>Healthy</Badge>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <div className="bottom-grid">
        <Panel title="Risk Distribution">
          <div className="risk-bars">
            {[
              ["Low risk", 72, "green"],
              ["Medium risk", 18, "amber"],
              ["High risk", 7, "orange"],
              ["Critical", 3, "red"],
            ].map(([label, value, tone]) => (
              <div className="risk-row" key={label}>
                <span>{label}</span>
                <div className="bar">
                  <i
                    className={tone}
                    style={{ width: `${value}%` }}
                  />
                </div>
                <strong>{value}%</strong>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Zero-Trust Status">
          <div className="zero-trust-card">
            <ShieldCheck size={42} />
            <div>
              <strong>Protection Active</strong>
              <span>
                Every agent action is authenticated, inspected and logged.
              </span>
            </div>
          </div>
        </Panel>
      </div>
    </>
  );
}

function AgentMonitor() {
  return (
    <Panel title="Connected Autonomous Agents" action="Refresh">
      <div className="filter-row">
        <button className="filter active">All agents</button>
        <button className="filter">Running</button>
        <button className="filter">High risk</button>
        <div className="search">
          <Search size={16} />
          <span>Search agents...</span>
        </div>
      </div>
      <div className="data-table">
        <div className="table-head">
          <span>Agent</span>
          <span>Status</span>
          <span>Current activity</span>
          <span>Risk</span>
        </div>
        {agents.map(([agent, status, activity, risk]) => (
          <div className="table-row" key={agent}>
            <strong>{agent}</strong>
            <Badge>{status}</Badge>
            <span>{activity}</span>
            <Badge
              tone={
                risk === "High"
                  ? "red"
                  : risk === "Medium"
                    ? "amber"
                    : "green"
              }
            >
              {risk}
            </Badge>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function AttackLab() {
  return (
    <div className="attack-layout">
      <Panel title="Without AgentSentinel" className="danger-panel">
        <div className="attack-state danger">
          <XCircle size={42} />
          <h3>Attack Succeeds</h3>
          <p>
            Malicious prompt obtains credentials and attempts command
            execution without inspection.
          </p>
          <code>../../.env && powershell execute_command</code>
          <Badge tone="red">Sensitive data exposed</Badge>
        </div>
      </Panel>

      <div className="versus">VS</div>

      <Panel title="With AgentSentinel" className="safe-panel">
        <div className="attack-state safe">
          <ShieldCheck size={42} />
          <h3>Attack Blocked</h3>
          <p>
            Identity, policy and threat controls stop the action before
            tool execution.
          </p>
          <div className="control-list">
            <span>✓ Prompt injection detected</span>
            <span>✓ Path traversal blocked</span>
            <span>✓ Secret access prevented</span>
            <span>✓ Evidence written to audit chain</span>
          </div>
          <Badge>Protection active</Badge>
        </div>
      </Panel>
    </div>
  );
}

function ThreatAnalysis() {
  return (
    <div className="two-column">
      <Panel title="Threat Intelligence">
        <div className="threat-score">
          <div className="score-ring">
            <strong>92</strong>
            <span>/100</span>
          </div>
          <div>
            <Badge tone="red">Critical threat</Badge>
            <h3>Multi-vector runtime attack</h3>
            <p>
              Prompt injection, command injection and credential access
              were detected in one tool request.
            </p>
          </div>
        </div>
        <div className="finding-list">
          {[
            ["Prompt injection", 90],
            ["Command injection", 90],
            ["Secret access", 85],
            ["Path traversal", 70],
          ].map(([name, score]) => (
            <div key={name}>
              <span>{name}</span>
              <div className="bar">
                <i
                  className={score >= 85 ? "red" : "amber"}
                  style={{ width: `${score}%` }}
                />
              </div>
              <strong>{score}</strong>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Protection Decision">
        <div className="decision-card">
          <ShieldAlert size={44} />
          <Badge tone="red">Execution denied</Badge>
          <h3>Runtime threat block activated</h3>
          <p>
            No tool action was executed. The request and explainable
            decision were preserved in the tamper-evident audit trail.
          </p>
        </div>
      </Panel>
    </div>
  );
}

function ToolPermissions() {
  const rows = [
    ["research-agent", "Read", "Blocked", "Read", "Blocked", "Allowed"],
    ["coder-agent", "Write", "Allowed", "Blocked", "Blocked", "Allowed"],
    ["analyst-agent", "Read", "Blocked", "Write", "Blocked", "Approval"],
    ["marketing-agent", "Blocked", "Blocked", "Blocked", "Approval", "Read"],
  ];

  return (
    <Panel title="Least-Privilege Permission Matrix" action="Edit policy">
      <div className="permission-table">
        <div className="permission-head">
          <span>Agent</span>
          <span>Filesystem</span>
          <span>Shell</span>
          <span>Database</span>
          <span>Email</span>
          <span>MCP tools</span>
        </div>
        {rows.map((row) => (
          <div className="permission-row" key={row[0]}>
            {row.map((cell, index) =>
              index === 0 ? (
                <strong key={cell}>{cell}</strong>
              ) : (
                <Badge
                  key={`${row[0]}-${index}`}
                  tone={
                    cell === "Blocked"
                      ? "red"
                      : cell === "Approval"
                        ? "amber"
                        : "green"
                  }
                >
                  {cell}
                </Badge>
              ),
            )}
          </div>
        ))}
      </div>
    </Panel>
  );
}

function HumanApprovals() {
  return (
    <Panel title="Pending Human Approvals">
      <div className="approval-list">
        {[
          ["Filesystem write", "coder-agent", "High", "2 minutes ago"],
          ["External API call", "research-agent", "Medium", "5 minutes ago"],
          ["Database query", "analyst-agent", "High", "8 minutes ago"],
          ["Email send", "marketing-agent", "Medium", "12 minutes ago"],
        ].map(([action, agent, risk, time]) => (
          <article className="approval-card" key={action}>
            <div className="approval-icon">
              <AlertTriangle size={20} />
            </div>
            <div>
              <h3>{action}</h3>
              <span>
                {agent} · {time}
              </span>
              <p>Requires explicit user approval before execution.</p>
            </div>
            <Badge tone={risk === "High" ? "red" : "amber"}>
              {risk} risk
            </Badge>
            <button className="approve">Approve</button>
            <button className="reject">Reject</button>
          </article>
        ))}
      </div>
    </Panel>
  );
}

function AuditTrail() {
  return (
    <>
      <Panel title="Tamper-Evident Audit Trail" action="Verify chain">
        <div className="data-table audit-table">
          <div className="table-head">
            <span>Time</span>
            <span>Event</span>
            <span>Agent</span>
            <span>Action</span>
            <span>Risk</span>
          </div>
          {auditRows.map((row) => (
            <div className="table-row" key={`${row[0]}-${row[1]}`}>
              {row.map((cell, index) =>
                index === 4 ? (
                  <Badge
                    key={cell}
                    tone={
                      cell === "Critical"
                        ? "red"
                        : cell === "Medium"
                          ? "amber"
                          : "green"
                    }
                  >
                    {cell}
                  </Badge>
                ) : (
                  <span key={`${cell}-${index}`}>{cell}</span>
                ),
              )}
            </div>
          ))}
        </div>
      </Panel>

      <div className="chain">
        {["8bc1…92af", "f10d…72c9", "91f4…593a", "a104…5241"].map(
          (hash, index) => (
            <div className="hash-node" key={hash}>
              <LockKeyhole size={16} />
              <code>{hash}</code>
              {index < 3 && <ChevronRight size={16} />}
            </div>
          ),
        )}
        <Badge>Chain valid</Badge>
      </div>
    </>
  );
}

function Evaluation() {
  return (
    <div className="two-column evaluation-layout">
      <Panel title="Overall Safety Score">
        <div className="evaluation-score">
          <div className="score-ring large">
            <strong>92</strong>
            <span>/100</span>
          </div>
          <Badge>Strong safety posture</Badge>
          <p>
            AgentSentinel prevented high-risk actions while preserving
            safe agent productivity.
          </p>
          <button className="primary-button">Run new evaluation</button>
        </div>
      </Panel>

      <Panel title="Evaluation Results">
        <div className="finding-list">
          {[
            ["Prompt-injection resistance", 96],
            ["Data-exfiltration prevention", 94],
            ["Tool-misuse detection", 89],
            ["Policy compliance", 91],
            ["Human-control enforcement", 88],
          ].map(([name, score]) => (
            <div key={name}>
              <span>{name}</span>
              <div className="bar">
                <i className="green" style={{ width: `${score}%` }} />
              </div>
              <strong>{score}</strong>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function PageContent({ active, summary }) {
  if (active === "overview") return <Overview summary={summary} />;
  if (active === "agents") return <AgentMonitor />;
  if (active === "attack") return <AttackLab />;
  if (active === "threats") return <ThreatAnalysis />;
  if (active === "permissions") return <ToolPermissions />;
  if (active === "approvals") return <HumanApprovals />;
  if (active === "audit") return <AuditTrail />;
  return <Evaluation />;
}

export default function App() {
  const [active, setActive] = useState("overview");
  const [summary, setSummary] = useState(fallbackSummary);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const activeItem = navigation.find(([id]) => id === active);

  useEffect(() => {
    const token = import.meta.env.VITE_AGENTSENTINEL_TOKEN;

    if (!token) return;

    fetch("http://127.0.0.1:8000/v1/dashboard/summary", {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((response) => {
        if (!response.ok) throw new Error("Dashboard API unavailable");
        return response.json();
      })
      .then(setSummary)
      .catch(() => setSummary(fallbackSummary));
  }, []);

  return (
    <div className="app-shell">
      <aside className={sidebarOpen ? "sidebar open" : "sidebar"}>
        <div className="brand">
          <div className="brand-mark">
            <Shield size={25} />
          </div>
          <div>
            <strong>AGENT<span>SENTINEL</span></strong>
            <small>ZERO-TRUST AI SECURITY</small>
          </div>
        </div>

        <nav>
          {navigation.map(([id, label, Icon]) => (
            <button
              key={id}
              className={active === id ? "nav-item active" : "nav-item"}
              onClick={() => {
                setActive(id);
                setSidebarOpen(false);
              }}
            >
              <Icon size={18} />
              <span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="protection-orbit">
            <ShieldCheck size={27} />
          </div>
          <strong>Protection Active</strong>
          <span>Safe agents. Safer outcomes.</span>
        </div>
      </aside>

      <main>
        <header className="topbar">
          <button
            className="mobile-menu"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            aria-label="Toggle navigation"
          >
            <Menu size={21} />
          </button>

          <div>
            <h1>{activeItem[1]}</h1>
            <p>
              Real-time protection for autonomous AI agents and MCP tools
            </p>
          </div>

          <div className="topbar-actions">
            <Badge>
              <span className="pulse" />
              Zero-Trust Active
            </Badge>
            <button className="icon-button" aria-label="Refresh">
              <RefreshCw size={17} />
            </button>
            <div className="operator">
              <span>HM</span>
              <div>
                <strong>Harshitha M</strong>
                <small>Security Operator</small>
              </div>
            </div>
          </div>
        </header>

        <div className="page-content">
          <PageContent active={active} summary={summary} />
        </div>
      </main>
    </div>
  );
}