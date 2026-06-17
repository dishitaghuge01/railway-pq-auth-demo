import { useState } from "react";
import {
  ShieldCheck, ShieldX, ScanLine, Clock, CalendarClock, Train, CalendarX, SearchX, Copy,
  Check, X as XIcon, Minus, Loader2, Upload,
} from "lucide-react";
import type { RawTicket, VerifyResult, VerifyResultCode } from "../types";
import { api, ApiError } from "../lib/api";
import { useToast } from "./toast";
import { ServiceBanner } from "./service-banner";

type Mode = "pnr" | "upload";

export function VerifyPage() {
  const toast = useToast();
  const [mode, setMode] = useState<Mode>("pnr");
  const [pnr, setPnr] = useState("");
  const [tte, setTte] = useState("");
  const [train, setTrain] = useState("");
  const [withId, setWithId] = useState(false);
  const [aadhaar, setAadhaar] = useState("");
  const [dob, setDob] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [bannerErr, setBannerErr] = useState<unknown>(null);

  const fileToB64 = (f: File): Promise<string> =>
    new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => {
        const s = String(r.result);
        resolve(s.includes(",") ? s.split(",")[1] : s);
      };
      r.onerror = () => reject(r.error);
      r.readAsDataURL(f);
    });

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setBannerErr(null);
    try {
      let barcode_b64: string;
      let usePnr = pnr;
      if (mode === "pnr") {
        const raw = await api.rawTicket<RawTicket>(pnr);
        barcode_b64 = raw.barcode_b64;
      } else {
        if (!file) throw new Error("Please upload a barcode PNG.");
        barcode_b64 = await fileToB64(file);
        if (!usePnr) usePnr = "UPLOADED";
      }
      const body: Record<string, unknown> = {
        pnr: usePnr,
        tte_id: tte,
        train,
        barcode_b64,
      };
      if (withId) {
        body.aadhaar = aadhaar;
        body.dob = dob;
      }
      const r = await api.verify<VerifyResult>(body);
      setResult(r);
      const kind = r.result === "VALID" ? "success" : r.result === "DUPLICATE" || r.result === "EXPIRED" || r.result === "NOT_YET_VALID" ? "warning" : "error";
      toast.push(kind, `Result: ${r.result}`);
    } catch (err) {
      setBannerErr(err);
      const msg = err instanceof ApiError ? `${err.status || "ERR"} — ${err.message}` : (err as Error).message;
      toast.push("error", msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 640, margin: "0 auto" }}>
      <ServiceBanner error={bannerErr} />
      <h2 style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 20, margin: 0 }}>
        <ShieldCheck size={20} color="var(--accent-c)" /> Verify Ticket
      </h2>
      <p style={{ color: "var(--text-secondary)", fontSize: 13, marginTop: 6 }}>
        Runs Falcon signature check, validity window, train/date match, chart lookup, identity and duplicate detection.
      </p>

      <div style={{ display: "flex", gap: 0, border: "1px solid var(--border-c)", borderRadius: 6, overflow: "hidden", marginTop: 18 }}>
        {(["pnr", "upload"] as Mode[]).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => setMode(m)}
            style={{
              flex: 1,
              padding: "10px",
              border: 0,
              background: mode === m ? "var(--accent-light)" : "var(--surface)",
              color: mode === m ? "var(--accent-c)" : "var(--text-primary)",
              fontWeight: 500,
              fontSize: 13,
              cursor: "pointer",
            }}
          >
            {m === "pnr" ? "By PNR" : "Upload Barcode Image"}
          </button>
        ))}
      </div>

      <form className="card" onSubmit={submit} style={{ marginTop: 12 }}>
        {mode === "pnr" ? (
          <div>
            <label className="label">PNR</label>
            <input className="input mono" placeholder="e.g. PNR8472910" value={pnr}
              onChange={(e) => setPnr(e.target.value)} required />
          </div>
        ) : (
          <div>
            <label className="label">Barcode PNG</label>
            <label className="btn btn-ghost" style={{ cursor: "pointer", display: "inline-flex" }}>
              <Upload size={14} /> {file ? file.name : "Choose file"}
              <input type="file" accept="image/png" style={{ display: "none" }} onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            </label>
            <div style={{ marginTop: 12 }}>
              <label className="label">PNR (optional, for logging)</label>
              <input className="input mono" value={pnr} onChange={(e) => setPnr(e.target.value)} />
            </div>
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 14 }}>
          <div>
            <label className="label">TTE ID</label>
            <input className="input mono" placeholder="e.g. TTE-MUM-047" value={tte} onChange={(e) => setTte(e.target.value)} required />
          </div>
          <div>
            <label className="label">Train Number</label>
            <input className="input mono" placeholder="e.g. 12051" value={train} onChange={(e) => setTrain(e.target.value)} required />
          </div>
        </div>

        <div style={{ marginTop: 18, display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 14px", border: "1px solid var(--border-c)", borderRadius: 6 }}>
          <span style={{ fontSize: 13 }}>Include Aadhaar identity check</span>
          <button type="button" role="switch" aria-checked={withId} onClick={() => setWithId(!withId)}
            style={{
              width: 40, height: 22, borderRadius: 999, border: 0, position: "relative",
              background: withId ? "var(--accent-c)" : "var(--border-c)", cursor: "pointer", transition: "background 0.15s",
            }}>
            <span style={{
              position: "absolute", top: 3, left: withId ? 21 : 3, width: 16, height: 16,
              borderRadius: "50%", background: "#fff", transition: "left 0.15s",
            }} />
          </button>
        </div>
        {withId && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 12 }}>
            <div>
              <label className="label">Aadhaar Number</label>
              <input className="input mono" inputMode="numeric" maxLength={12} value={aadhaar}
                onChange={(e) => setAadhaar(e.target.value.replace(/\D/g, ""))} required />
            </div>
            <div>
              <label className="label">Date of Birth</label>
              <input className="input" type="date" value={dob} onChange={(e) => setDob(e.target.value)} required />
            </div>
          </div>
        )}

        <button type="submit" className="btn btn-primary" disabled={loading} style={{ width: "100%", marginTop: 18, padding: "12px 16px", fontSize: 15 }}>
          {loading ? <Loader2 size={16} className="spin" /> : <ScanLine size={16} />}
          {loading ? "Verifying…" : "Verify Ticket"}
        </button>
      </form>

      {result && <ResultCard result={result} identityRequested={withId} />}
    </div>
  );
}

const RESULT_STYLE: Record<VerifyResultCode, { color: string; bg: string; Icon: React.ComponentType<{ size?: number }> }> = {
  VALID: { color: "var(--green)", bg: "var(--green-light)", Icon: ShieldCheck },
  FORGED: { color: "var(--red)", bg: "var(--red-light)", Icon: ShieldX },
  DUPLICATE: { color: "var(--amber)", bg: "var(--amber-light)", Icon: Copy },
  EXPIRED: { color: "var(--amber)", bg: "var(--amber-light)", Icon: Clock },
  NOT_YET_VALID: { color: "var(--amber)", bg: "var(--amber-light)", Icon: CalendarClock },
  WRONG_TRAIN: { color: "var(--red)", bg: "var(--red-light)", Icon: Train },
  WRONG_DATE: { color: "var(--red)", bg: "var(--red-light)", Icon: CalendarX },
  INVALID_PNR: { color: "var(--red)", bg: "var(--red-light)", Icon: SearchX },
};

function ResultCard({ result, identityRequested }: { result: VerifyResult; identityRequested: boolean }) {
  const style = RESULT_STYLE[result.result] ?? RESULT_STYLE.FORGED;
  const { Icon } = style;

  const rows: { label: string; ok: boolean | null; valueOk: string; valueBad: string; valueSkip?: string }[] = [
    { label: "Falcon Signature", ok: result.signature_valid, valueOk: "VALID", valueBad: "INVALID" },
    { label: "Validity Window", ok: result.validity_window === "active", valueOk: "ACTIVE", valueBad: result.validity_window?.toUpperCase() ?? "INVALID" },
    { label: "Train Match", ok: result.train_match, valueOk: "MATCHED", valueBad: "MISMATCH" },
    { label: "Date Match", ok: result.date_match, valueOk: "MATCHED", valueBad: "MISMATCH" },
    { label: "Chart Lookup", ok: result.chart_match, valueOk: "FOUND", valueBad: "MISSING" },
    {
      label: "Identity Check",
      ok: identityRequested ? result.identity_check === "passed" : null,
      valueOk: "PASSED", valueBad: "FAILED", valueSkip: "SKIPPED",
    },
    { label: "Duplicate Detection", ok: !result.is_duplicate, valueOk: "FIRST SCAN", valueBad: "DUPLICATE" },
  ];

  return (
    <div
      className="card"
      style={{ borderLeft: `4px solid ${style.color}`, marginTop: 18, padding: 22 }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span className="badge" style={{ background: style.bg, color: style.color, padding: "6px 14px", fontSize: 13 }}>
          <Icon size={14} /> {result.result}
        </span>
        <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>
          Key used: <span className="mono">{result.key_used}</span>
        </span>
      </div>

      <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 2 }}>
        {rows.map((r, i) => (
          <ChecklistRow key={r.label} row={r} index={i} />
        ))}
      </div>

      {result.payload && (
        <details style={{ marginTop: 16 }}>
          <summary style={{ cursor: "pointer", fontSize: 13, color: "var(--text-secondary)" }}>Decoded payload</summary>
          <pre className="mono" style={{
            marginTop: 10, padding: 14, background: "var(--surface)", border: "1px solid var(--border-c)",
            borderRadius: 6, fontSize: 12, overflow: "auto", color: "var(--text-primary)",
          }}>
{JSON.stringify(result.payload, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
}

function ChecklistRow({ row, index }: {
  row: { label: string; ok: boolean | null; valueOk: string; valueBad: string; valueSkip?: string };
  index: number;
}) {
  const skipped = row.ok === null;
  const color = skipped ? "var(--text-muted)" : row.ok ? "var(--green)" : "var(--red)";
  const Icon = skipped ? Minus : row.ok ? Check : XIcon;
  const value = skipped ? row.valueSkip ?? "—" : row.ok ? row.valueOk : row.valueBad;
  return (
    <div
      className="slide-in"
      style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        padding: "10px 0", borderBottom: "1px solid var(--border-c)",
        animationDelay: `${index * 60}ms`,
      }}
    >
      <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>{row.label}</span>
      <span style={{ display: "inline-flex", alignItems: "center", gap: 6, color, fontSize: 13, fontWeight: 500 }}>
        <Icon size={14} /> {value}
      </span>
    </div>
  );
}