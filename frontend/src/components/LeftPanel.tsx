import { useState } from "react";
import type { Command, PayloadType, ScanStats } from "../types";

interface LeftPanelProps {
  target: string;
  onTargetChange: (v: string) => void;
  loading: boolean;
  stats: ScanStats;
  payloadType: PayloadType;
  onPayloadTypeChange: (v: PayloadType) => void;
  onRun: (cmd: Command) => void;
  activeCmd: Command | null;
}

function Btn({
  label,
  icon,
  active,
  disabled,
  full,
  primary,
  onClick,
}: {
  label: string;
  icon: string;
  active?: boolean;
  disabled?: boolean;
  full?: boolean;
  primary?: boolean;
  onClick: () => void;
}) {
  const [hov, setHov] = useState(false);
  const lit = active || hov || primary;
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        gridColumn: full ? "1 / -1" : undefined,
        padding: "9px 8px",
        borderRadius: 8,
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: "0.7rem",
        letterSpacing: 1,
        textTransform: "uppercase" as const,
        cursor: disabled ? "not-allowed" : "pointer",
        border: `1px solid ${lit ? "var(--border-h)" : "var(--border)"}`,
        background: lit ? "var(--lime-dim)" : "var(--surface)",
        color: lit ? "var(--lime)" : "var(--text-dim)",
        boxShadow: active ? "0 0 10px var(--lime-dim)" : "none",
        opacity: disabled ? 0.38 : 1,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: 5,
        width: "100%",
        transition: "all 0.15s",
      }}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
    >
      <span style={{ fontSize: "0.75rem" }}>{icon}</span>
      <span>{label}</span>
    </button>
  );
}

function Divider() {
  return (
    <div style={{ height: 1, background: "var(--border)", margin: "2px 0" }} />
  );
}

function SectionLabel({ label }: { label: string }) {
  return (
    <div
      style={{
        fontSize: "0.58rem",
        letterSpacing: 3,
        textTransform: "uppercase" as const,
        color: "var(--text-muted)",
        marginBottom: 7,
      }}
    >
      {label}
    </div>
  );
}

function StatPill({ label, value }: { label: string; value: string }) {
  return (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        padding: "5px 10px",
        background: "var(--surface2)",
        borderRadius: 6,
        border: "1px solid var(--border)",
        fontSize: "0.68rem",
      }}
    >
      <span
        style={{
          color: "var(--text-muted)",
          letterSpacing: 1,
          textTransform: "uppercase" as const,
        }}
      >
        {label}
      </span>
      <span
        style={{
          color: value === "—" ? "var(--text-muted)" : "var(--lime)",
          fontWeight: 500,
        }}
      >
        {value}
      </span>
    </div>
  );
}

const PAYLOAD_TYPES: PayloadType[] = [
  "xss",
  "sqli",
  "lfi",
  "ssrf",
  "open_redirect",
  "idor",
];

export default function LeftPanel({
  target,
  onTargetChange,
  loading,
  stats,
  payloadType,
  onPayloadTypeChange,
  onRun,
  activeCmd,
}: LeftPanelProps) {
  const [focused, setFocused] = useState(false);

  return (
    <aside
      style={{
        borderRight: "1px solid var(--border)",
        padding: "20px 16px",
        display: "flex",
        flexDirection: "column",
        gap: 16,
        position: "sticky",
        top: 49,
        height: "calc(100vh - 49px)",
        overflowY: "auto",
      }}
    >
      {/* Target */}
      <div>
        <SectionLabel label="Target" />
        <input
          type="text"
          placeholder="example.com"
          value={target}
          onChange={(e) => onTargetChange(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && target && onRun("recon")}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          style={{
            width: "100%",
            background: "var(--surface2)",
            border: `1px solid ${focused ? "var(--border-h)" : "var(--border)"}`,
            boxShadow: focused ? "0 0 0 2px var(--lime-dim)" : "none",
            borderRadius: 8,
            padding: "9px 12px",
            color: "var(--lime)",
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: "0.8rem",
            outline: "none",
            caretColor: "var(--lime)",
          }}
        />
      </div>

      {/* Main Commands */}
      <div>
        <SectionLabel label="Commands" />
        <div
          style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 7 }}
        >
          <Btn
            label="Workflow"
            icon="⚡"
            full
            primary
            active={activeCmd === "workflow"}
            disabled={loading || !target}
            onClick={() => onRun("workflow")}
          />
          <Btn
            label="Recon"
            icon="◎"
            active={activeCmd === "recon"}
            disabled={loading || !target}
            onClick={() => onRun("recon")}
          />
          <Btn
            label="Analyze"
            icon="⟳"
            active={activeCmd === "analyze"}
            disabled={loading || !target}
            onClick={() => onRun("analyze")}
          />
          <Btn
            label="BB Scan"
            icon="◈"
            active={activeCmd === "bb-scan"}
            disabled={loading || !target}
            onClick={() => onRun("bb-scan")}
          />
          <Btn
            label="Last Scan"
            icon="⊙"
            full
            active={activeCmd === "last-scan"}
            disabled={loading}
            onClick={() => onRun("last-scan")}
          />
        </div>
      </div>

      <Divider />

      {/* Workflow Variants */}
      <div>
        <SectionLabel label="Workflows" />
        <div
          style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 7 }}
        >
          <Btn
            label="Express"
            icon="🚀"
            active={activeCmd === "workflow-express"}
            disabled={loading || !target}
            onClick={() => onRun("workflow-express")}
          />
          <Btn
            label="Bug Bounty"
            icon="◉"
            active={activeCmd === "workflow-bugbounty"}
            disabled={loading || !target}
            onClick={() => onRun("workflow-bugbounty")}
          />
          <Btn
            label="Subdomains"
            icon="⊹"
            active={activeCmd === "workflow-subdomains"}
            disabled={loading || !target}
            onClick={() => onRun("workflow-subdomains")}
          />
          <Btn
            label="API Scan"
            icon="⊠"
            active={activeCmd === "workflow-api"}
            disabled={loading || !target}
            onClick={() => onRun("workflow-api")}
          />
        </div>
      </div>

      <Divider />

      {/* Recon Tools */}
      <div>
        <SectionLabel label="Recon Tools" />
        <div
          style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 7 }}
        >
          <Btn
            label="Expand"
            icon="⊞"
            full
            active={activeCmd === "expand"}
            disabled={loading || !target}
            onClick={() => onRun("expand")}
          />
          <Btn
            label="Endpoints"
            icon="⊡"
            active={activeCmd === "endpoints"}
            disabled={loading || !target}
            onClick={() => onRun("endpoints")}
          />
          <Btn
            label="Params"
            icon="⊟"
            active={activeCmd === "params"}
            disabled={loading || !target}
            onClick={() => onRun("params")}
          />
        </div>
      </div>

      <Divider />

      {/* Payloads */}
      <div>
        <SectionLabel label="Payloads" />
        <div
          style={{
            display: "flex",
            gap: 5,
            flexWrap: "wrap" as const,
            marginBottom: 7,
          }}
        >
          {PAYLOAD_TYPES.map((pt) => (
            <button
              key={pt}
              onClick={() => onPayloadTypeChange(pt)}
              style={{
                padding: "3px 8px",
                borderRadius: 4,
                fontSize: "0.62rem",
                letterSpacing: 0.5,
                textTransform: "uppercase" as const,
                border: `1px solid ${payloadType === pt ? "var(--border-h)" : "var(--border)"}`,
                background:
                  payloadType === pt ? "var(--lime-dim)" : "transparent",
                color: payloadType === pt ? "var(--lime)" : "var(--text-muted)",
                cursor: "pointer",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              {pt}
            </button>
          ))}
        </div>
        <Btn
          label={`Get ${payloadType.toUpperCase()}`}
          icon="◇"
          full
          active={activeCmd === "payloads"}
          disabled={loading}
          onClick={() => onRun("payloads")}
        />
      </div>

      <Divider />

      {/* Stats */}
      <div>
        <SectionLabel label="Last Scan Stats" />
        <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
          <StatPill label="IP" value={stats.ip} />
          <StatPill label="Status" value={stats.status} />
          <StatPill label="SSL" value={stats.ssl} />
        </div>
      </div>
    </aside>
  );
}
