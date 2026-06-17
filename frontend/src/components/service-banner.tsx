import { AlertTriangle } from "lucide-react";
import { ApiError } from "../lib/api";
import { SERVICE_META } from "../config";

export function ServiceBanner({ error }: { error: unknown }) {
  if (!(error instanceof ApiError) || error.status !== 0) return null;
  const meta = SERVICE_META[error.service];
  return (
    <div
      role="alert"
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: 10,
        padding: "12px 14px",
        background: "var(--amber-light)",
        border: "1px solid var(--amber)",
        borderRadius: 8,
        color: "var(--amber)",
        marginBottom: 20,
        fontSize: 13,
      }}
    >
      <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: 1 }} />
      <div style={{ color: "var(--text-primary)" }}>
        <strong>{meta.name} unreachable</strong> — Make sure <span className="mono">honcho start</span> is running and port{" "}
        <span className="mono">{meta.port}</span> is accessible.
      </div>
    </div>
  );
}