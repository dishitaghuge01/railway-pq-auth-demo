import { useState } from "react";
import { Trash2, ListTree, Loader2, ChevronDown, ChevronRight, Check, X as XIcon } from "lucide-react";
import type { ChartPassenger, ChartResponse } from "../types";
import { api, ApiError } from "../lib/api";
import { useToast } from "./toast";
import { ServiceBanner } from "./service-banner";

export function ChartPage() {
  const toast = useToast();
  const [train, setTrain] = useState("");
  const [date, setDate] = useState("");
  const [chart, setChart] = useState<ChartResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [bannerErr, setBannerErr] = useState<unknown>(null);
  const [confirm, setConfirm] = useState(false);

  const load = async () => {
    if (!train || !date) return;
    setLoading(true);
    setBannerErr(null);
    try {
      const r = await api.chart<ChartResponse | ChartPassenger[]>(train, date);
      const passengers = Array.isArray(r) ? r : (r.passengers ?? []);
      setChart({ train, date, passengers });
    } catch (err) {
      setBannerErr(err);
      const msg = err instanceof ApiError ? `${err.status || "ERR"} — ${err.message}` : (err as Error).message;
      toast.push("error", msg);
    } finally {
      setLoading(false);
    }
  };

  const clear = async () => {
    setConfirm(false);
    try {
      await api.clearChart(train, date);
      toast.push("success", `Chart cleared for ${train} on ${date}.`);
      setChart({ train, date, passengers: [] });
    } catch (err) {
      const msg = err instanceof ApiError ? `${err.status || "ERR"} — ${err.message}` : (err as Error).message;
      toast.push("error", msg);
    }
  };

  const grouped = chart
    ? chart.passengers.reduce<Record<string, ChartPassenger[]>>((m, p) => {
        const k = p.coach ?? "—";
        (m[k] ??= []).push(p);
        return m;
      }, {})
    : {};

  return (
    <div style={{ maxWidth: 720, margin: "0 auto" }}>
      <ServiceBanner error={bannerErr} />
      <h2 style={{ display: "flex", alignItems: "center", gap: 8, margin: 0, fontSize: 20 }}>
        <ListTree size={20} color="var(--accent-c)" /> Passenger Chart
      </h2>
      <p style={{ color: "var(--text-secondary)", fontSize: 13, marginTop: 6 }}>
        Load the manifest a TTE sees on the HHT terminal.
      </p>

      <div className="card" style={{ marginTop: 16 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: 12, alignItems: "end" }}>
          <div>
            <label className="label">Train Number</label>
            <input className="input mono" value={train} onChange={(e) => setTrain(e.target.value)} placeholder="e.g. 12051" />
          </div>
          <div>
            <label className="label">Date</label>
            <input className="input" type="date" value={date} onChange={(e) => setDate(e.target.value)} />
          </div>
          <button className="btn btn-primary" onClick={load} disabled={loading || !train || !date} style={{ padding: "10px 18px" }}>
            {loading ? <Loader2 size={14} className="spin" /> : <ListTree size={14} />} Load Chart
          </button>
        </div>
      </div>

      {chart && (
        <div style={{ marginTop: 20 }}>
          {chart.passengers.length === 0 ? (
            <p style={{ color: "var(--text-muted)", fontSize: 14 }}>No passengers loaded for this train and date.</p>
          ) : (
            Object.entries(grouped).map(([coach, list]) => (
              <CoachSection key={coach} coach={coach} list={list} />
            ))
          )}

          <div style={{ marginTop: 28, padding: 16, border: "1px dashed var(--red)", borderRadius: 8 }}>
            <strong style={{ color: "var(--red)", fontSize: 13, textTransform: "uppercase", letterSpacing: "0.04em" }}>Danger zone</strong>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", margin: "6px 0 12px" }}>
              Wipe the entire chart after the journey ends. This cannot be undone.
            </p>
            <button className="btn btn-danger-ghost" onClick={() => setConfirm(true)}>
              <Trash2 size={14} /> Clear Chart
            </button>
          </div>
        </div>
      )}

      {confirm && (
        <div
          role="dialog"
          aria-modal="true"
          style={{
            position: "fixed", inset: 0, background: "rgba(26,20,16,0.4)", display: "flex",
            alignItems: "center", justifyContent: "center", zIndex: 90, padding: 16,
          }}
          onClick={() => setConfirm(false)}
        >
          <div className="card" style={{ maxWidth: 420, width: "100%" }} onClick={(e) => e.stopPropagation()}>
            <h3 style={{ margin: 0, fontSize: 17 }}>Clear passenger chart?</h3>
            <p style={{ color: "var(--text-secondary)", fontSize: 13, marginTop: 8 }}>
              Clear chart for train <span className="mono">{train}</span> on <span className="mono">{date}</span>? This simulates an end-of-journey wipe and cannot be undone.
            </p>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 16 }}>
              <button className="btn btn-ghost" onClick={() => setConfirm(false)} style={{ borderColor: "var(--border-c)", color: "var(--text-primary)" }}>Cancel</button>
              <button className="btn btn-primary" onClick={clear} style={{ background: "var(--red)" }}>Clear Chart</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function CoachSection({ coach, list }: { coach: string; list: ChartPassenger[] }) {
  const [open, setOpen] = useState(true);
  return (
    <div className="card" style={{ marginBottom: 12, padding: 0 }}>
      <button
        onClick={() => setOpen(!open)}
        style={{
          width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center",
          padding: "14px 20px", background: "transparent", border: 0, cursor: "pointer", color: "var(--text-primary)",
        }}
      >
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          <strong className="mono" style={{ fontSize: 14 }}>{coach}</strong>
          <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>{list.length} passenger{list.length === 1 ? "" : "s"}</span>
        </span>
      </button>
      {open && (
        <table style={{ width: "100%", fontSize: 13, borderCollapse: "collapse", borderTop: "1px solid var(--border-c)" }}>
          <thead>
            <tr style={{ textAlign: "left", color: "var(--text-secondary)", background: "var(--bg)" }}>
              <th style={{ padding: "10px 16px" }}>Berth</th>
              <th style={{ padding: "10px 16px" }}>Name</th>
              <th style={{ padding: "10px 16px" }}>ID Hash</th>
              <th style={{ padding: "10px 16px" }}>Verified</th>
            </tr>
          </thead>
          <tbody>
            {list.map((p, i) => (
              <tr key={i} style={{ borderTop: "1px solid var(--border-c)" }}>
                <td style={{ padding: "10px 16px" }} className="mono">{p.berth}</td>
                <td style={{ padding: "10px 16px" }}>{p.name}</td>
                <td style={{ padding: "10px 16px", color: "var(--text-muted)" }} className="mono">{p.id_hash?.slice(0, 8) ?? "—"}</td>
                <td style={{ padding: "10px 16px" }}>
                  {p.verified ? <Check size={14} color="var(--green)" /> : <XIcon size={14} color="var(--text-muted)" />}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}