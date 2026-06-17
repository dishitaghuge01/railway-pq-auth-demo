import { useEffect, useState } from "react";
import { RefreshCw, ShieldCheck, Search, Loader2, Copy, Check } from "lucide-react";
import type { AuditEvent, AuditStats, DuplicateEntry, VerifyResultCode } from "../types";
import { api, ApiError } from "../lib/api";
import { useToast } from "./toast";
import { ServiceBanner } from "./service-banner";

const STAT_KEYS: { key: VerifyResultCode | "TOTAL"; label: string; cls: string }[] = [
  { key: "TOTAL", label: "Total Verifications", cls: "badge-accent" },
  { key: "VALID", label: "Valid", cls: "badge-green" },
  { key: "FORGED", label: "Forged", cls: "badge-red" },
  { key: "DUPLICATE", label: "Duplicate", cls: "badge-amber" },
  { key: "EXPIRED", label: "Expired", cls: "badge-amber" },
];

const formatAuditTimestamp = (value: number) =>
  new Date(value * 1000).toLocaleString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: true,
  });

export function AuditPage() {
  const toast = useToast();
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [dupes, setDupes] = useState<DuplicateEntry[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [bannerErr, setBannerErr] = useState<unknown>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [events, setEvents] = useState<Record<string, AuditEvent[]>>({});
  const [lookup, setLookup] = useState("");
  const [lookupResult, setLookupResult] = useState<AuditEvent[] | null>(null);

  const refresh = async () => {
    setLoading(true);
    setBannerErr(null);
    try {
      const [s, d] = await Promise.all([api.stats<AuditStats>(), api.duplicates<DuplicateEntry[]>()]);
      setStats(s);
      setDupes(Array.isArray(d) ? d : []);
    } catch (err) {
      setBannerErr(err);
      const msg = err instanceof ApiError ? `${err.status || "ERR"} — ${err.message}` : (err as Error).message;
      toast.push("error", msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); /* eslint-disable-next-line */ }, []);

  const toggleExpand = async (uuid: string) => {
    if (expanded === uuid) { setExpanded(null); return; }
    setExpanded(uuid);
    if (!events[uuid]) {
      try {
        const ev = await api.log<AuditEvent[]>(uuid);
        setEvents((m) => ({ ...m, [uuid]: Array.isArray(ev) ? ev : [] }));
      } catch (err) {
        toast.push("error", (err as Error).message);
      }
    }
  };

  const doLookup = async () => {
    if (!lookup.trim()) return;
    try {
      const ev = await api.log<AuditEvent[]>(lookup.trim());
      setLookupResult(Array.isArray(ev) ? ev : []);
    } catch (err) {
      toast.push("error", (err as Error).message);
      setLookupResult([]);
    }
  };

  const total = stats
    ? Object.values(stats).reduce((a, b) => a + (typeof b === "number" ? b : 0), 0)
    : 0;
  const duplicateCount = dupes?.length ?? 0;

  const formatAuditTimestamp = (value: number) =>
    new Date(value * 1000).toLocaleString("en-IN", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: true,
    });

  return (
    <div>
      <ServiceBanner error={bannerErr} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h2 style={{ margin: 0, fontSize: 20 }}>Audit</h2>
        <button onClick={refresh} className="btn btn-ghost" disabled={loading} style={{ padding: "8px 14px", fontSize: 13 }}>
          {loading ? <Loader2 size={14} className="spin" /> : <RefreshCw size={14} />}
          Refresh
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 14, marginTop: 18 }}>
        {STAT_KEYS.map((k) => {
          const value = k.key === "TOTAL"
            ? total
            : k.key === "DUPLICATE"
            ? duplicateCount
            : (stats?.[k.key] ?? 0);
          return (
            <div key={k.key} className="card" style={{ padding: "20px 24px" }}>
              <div style={{ fontSize: 32, fontWeight: 700, color: "var(--text-primary)" }}>{value}</div>
              <div style={{ marginTop: 6, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>{k.label}</span>
                {k.key !== "TOTAL" && <span className={`badge ${k.cls}`}>{k.key}</span>}
              </div>
            </div>
          );
        })}
        {stats && Object.entries(stats).filter(([k, v]) => !["VALID", "FORGED", "DUPLICATE", "EXPIRED"].includes(k) && v).map(([k, v]) => (
          <div key={k} className="card" style={{ padding: "20px 24px" }}>
            <div style={{ fontSize: 32, fontWeight: 700, color: "var(--text-muted)" }}>{v}</div>
            <div style={{ marginTop: 6, fontSize: 13, color: "var(--text-secondary)" }}>{k}</div>
          </div>
        ))}
      </div>

      <h3 style={{ marginTop: 32, fontSize: 16 }}>Duplicate Flags</h3>
      {dupes === null ? (
        <p style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading…</p>
      ) : dupes.length === 0 ? (
        <div className="card" style={{ display: "flex", alignItems: "center", gap: 12, color: "var(--green)" }}>
          <ShieldCheck size={20} /> No duplicates detected.
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ textAlign: "left", color: "var(--text-secondary)", background: "var(--bg)" }}>
                <th style={{ padding: "12px 16px" }}>UUID</th>
                <th style={{ padding: "12px 16px" }}>Times Scanned</th>
                <th style={{ padding: "12px 16px" }}>First Seen</th>
                <th style={{ padding: "12px 16px" }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {dupes.map((d) => (
                <FragmentRow key={d.uuid} d={d} expanded={expanded === d.uuid} onToggle={() => toggleExpand(d.uuid)} events={events[d.uuid]} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h3 style={{ marginTop: 32, fontSize: 16 }}>Lookup by UUID</h3>
      <div style={{ display: "flex", gap: 8, maxWidth: 540 }}>
        <input className="input mono" placeholder="ticket UUID" value={lookup} onChange={(e) => setLookup(e.target.value)} />
        <button className="btn btn-primary" onClick={doLookup} style={{ padding: "9px 16px" }}>
          <Search size={14} /> Lookup
        </button>
      </div>
      {lookupResult !== null && <EventList events={lookupResult} />}
    </div>
  );
}

function FragmentRow({ d, expanded, onToggle, events }: { d: DuplicateEntry; expanded: boolean; onToggle: () => void; events?: AuditEvent[] }) {
  const [copied, setCopied] = useState(false);
  const copy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    await navigator.clipboard.writeText(d.uuid);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <>
      <tr onClick={onToggle} style={{ borderTop: "1px solid var(--border-c)", cursor: "pointer" }}>
        <td style={{ padding: "12px 16px" }} className="mono">
          {d.uuid.slice(0, 16)}…
          <button onClick={copy} aria-label="Copy UUID" style={{ marginLeft: 8, background: "transparent", border: 0, cursor: "pointer", color: "var(--text-muted)", verticalAlign: "middle" }}>
            {copied ? <Check size={12} /> : <Copy size={12} />}
          </button>
        </td>
        <td style={{ padding: "12px 16px" }}>{d.count}</td>
        <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{formatAuditTimestamp(d.first_seen)}</td>
        <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>{formatAuditTimestamp(d.last_seen)}</td>
        <td style={{ padding: "12px 16px" }}><span className="badge badge-amber">DUPLICATE</span></td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={5} style={{ padding: "0 16px 16px", background: "var(--bg)" }}>
            <EventList events={events ?? []} compact />
          </td>
        </tr>
      )}
    </>
  );
}

function EventList({ events, compact }: { events: AuditEvent[]; compact?: boolean }) {
  if (events.length === 0) {
    return <p style={{ color: "var(--text-muted)", fontSize: 13, marginTop: 10 }}>No events.</p>;
  }
  return (
    <div className={compact ? "" : "card"} style={{ marginTop: 12, padding: compact ? "12px 0" : 16 }}>
      <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ textAlign: "left", color: "var(--text-secondary)" }}>
            <th style={{ padding: "6px 8px" }}>Timestamp</th>
            <th style={{ padding: "6px 8px" }}>TTE ID</th>
            <th style={{ padding: "6px 8px" }}>Train</th>
            <th style={{ padding: "6px 8px" }}>Result</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={i} style={{ borderTop: "1px solid var(--border-c)" }}>
              <td style={{ padding: "8px" }} className="mono">{formatAuditTimestamp(e.timestamp)}</td>
              <td style={{ padding: "8px" }} className="mono">{e.tte_id}</td>
              <td style={{ padding: "8px" }} className="mono">{e.train}</td>
              <td style={{ padding: "8px" }}><ResultBadge code={e.result} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ResultBadge({ code }: { code: string }) {
  const cls =
    code === "VALID" ? "badge-green" :
    code === "DUPLICATE" || code === "EXPIRED" || code === "NOT_YET_VALID" ? "badge-amber" :
    "badge-red";
  return <span className={`badge ${cls}`}>{code}</span>;
}