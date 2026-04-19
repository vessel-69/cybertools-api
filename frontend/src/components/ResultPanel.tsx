import type { AnyResult, Command } from "../types";
import type {
  ReconResult,
  AnalyzeResult,
  BBScanResult,
  PayloadResult,
  WorkflowResult,
  LastScanResult,
  ExpandResult,
  EndpointsResult,
  ParamsResult,
  ExpressWorkflowResult,
  BugBountyWorkflowResult,
  SubdomainsWorkflowResult,
  ApiWorkflowResult,
} from "../types";
import {
  ReconSection,
  AnalyzeSection,
  BBScanSection,
  PayloadSection,
  WorkflowSection,
  LastScanSection,
  ExpandSection,
  EndpointsSection,
  ParamsSection,
  ExpressWorkflowSection,
  BugBountyWorkflowSection,
  SubdomainsWorkflowSection,
  ApiWorkflowSection,
} from "./results";

interface ResultPanelProps {
  result: AnyResult | null;
  loading: boolean;
  loadingMsg: string;
  error: string | null;
  activeCmd: Command | null;
}

function EmptyState() {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "100%",
        gap: 16,
        color: "var(--text-muted)",
      }}
    >
      <div style={{ fontSize: "2.5rem", opacity: 0.2 }}>⌖</div>
      <div
        style={{
          fontSize: "0.72rem",
          letterSpacing: 2,
          textTransform: "uppercase" as const,
        }}
      >
        Enter a target and run a command
      </div>
      <div
        style={{
          fontSize: "0.63rem",
          color: "var(--text-muted)",
          opacity: 0.5,
          textAlign: "center" as const,
          maxWidth: 280,
          lineHeight: 1.9,
        }}
      >
        Start with <span style={{ color: "var(--lime)" }}>Workflow</span> for a
        full scan, or <span style={{ color: "var(--lime)" }}>Recon</span> for
        host intelligence. Use{" "}
        <span style={{ color: "var(--lime)" }}>Bug Bounty</span> for targeted
        recon.
      </div>
    </div>
  );
}

function LoadingState({ msg }: { msg: string }) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "100%",
        gap: 20,
      }}
    >
      <div
        style={{
          width: 38,
          height: 38,
          borderRadius: "50%",
          border: "2px solid var(--border)",
          borderTopColor: "var(--lime)",
          animation: "spin 0.8s linear infinite",
        }}
      />
      <div
        style={{
          fontSize: "0.75rem",
          color: "var(--text-dim)",
          letterSpacing: 1,
        }}
      >
        {msg}
      </div>
      <div
        style={{
          fontSize: "0.62rem",
          color: "var(--text-muted)",
          letterSpacing: 2,
          textTransform: "uppercase" as const,
          animation: "blink 1.5s step-end infinite",
        }}
      >
        scanning target...
      </div>
    </div>
  );
}

function ErrorState({ msg }: { msg: string }) {
  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        padding: "14px 16px",
        background: "var(--red-dim)",
        margin: "24px",
      }}
    >
      <div
        style={{
          fontSize: "0.68rem",
          letterSpacing: 2,
          textTransform: "uppercase" as const,
          color: "var(--red)",
          marginBottom: 8,
        }}
      >
        ✗ Error
      </div>
      <div
        style={{ fontSize: "0.76rem", color: "var(--text)", lineHeight: 1.6 }}
      >
        {msg}
      </div>
    </div>
  );
}

function renderResult(result: AnyResult, cmd: Command | null) {
  switch (cmd) {
    case "recon":
      return <ReconSection d={result as ReconResult} />;
    case "analyze":
      return <AnalyzeSection d={result as AnalyzeResult} />;
    case "bb-scan":
      return <BBScanSection d={result as BBScanResult} />;
    case "payloads":
      return <PayloadSection d={result as PayloadResult} />;
    case "workflow":
      return <WorkflowSection d={result as WorkflowResult} />;
    case "last-scan":
      return <LastScanSection d={result as LastScanResult} />;
    case "expand":
      return <ExpandSection d={result as ExpandResult} />;
    case "endpoints":
      return <EndpointsSection d={result as EndpointsResult} />;
    case "params":
      return <ParamsSection d={result as ParamsResult} />;
    case "workflow-express":
      return <ExpressWorkflowSection d={result as ExpressWorkflowResult} />;
    case "workflow-bugbounty":
      return <BugBountyWorkflowSection d={result as BugBountyWorkflowResult} />;
    case "workflow-subdomains":
      return (
        <SubdomainsWorkflowSection d={result as SubdomainsWorkflowResult} />
      );
    case "workflow-api":
      return <ApiWorkflowSection d={result as ApiWorkflowResult} />;
    default:
      return null;
  }
}

const CMD_LABELS: Partial<Record<Command, string>> = {
  "workflow-express": "Workflow › Express",
  "workflow-bugbounty": "Workflow › Bug Bounty",
  "workflow-subdomains": "Workflow › Subdomains",
  "workflow-api": "Workflow › API Scan",
};

export default function ResultPanel({
  result,
  loading,
  loadingMsg,
  error,
  activeCmd,
}: ResultPanelProps) {
  const label = activeCmd ? (CMD_LABELS[activeCmd] ?? activeCmd) : "Output";

  return (
    <main
      style={{
        padding: "22px 26px",
        overflowY: "auto",
        height: "calc(100vh - 49px)",
        position: "relative",
        zIndex: 1,
      }}
    >
      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: 20,
          paddingBottom: 13,
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div
          style={{
            fontSize: "0.58rem",
            letterSpacing: 3,
            textTransform: "uppercase" as const,
            color: "var(--text-muted)",
          }}
        >
          {label}
        </div>
        <div
          style={{
            display: "flex",
            gap: 14,
            fontSize: "0.63rem",
            color: "var(--text-muted)",
            letterSpacing: 1,
          }}
        >
          <span>17 endpoints</span>
          <span style={{ color: "var(--border-h)" }}>|</span>
          <span>0 auth required</span>
          <span style={{ color: "var(--border-h)" }}>|</span>
          <span>∞ free</span>
        </div>
      </div>

      {loading ? (
        <LoadingState msg={loadingMsg} />
      ) : error ? (
        <ErrorState msg={error} />
      ) : result ? (
        renderResult(result, activeCmd)
      ) : (
        <EmptyState />
      )}
    </main>
  );
}
