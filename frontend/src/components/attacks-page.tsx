import { useState, type ReactNode } from "react";
import {
  ShieldAlert,
  Pen,
  Copy,
  Train,
  Clock,
  UserX,
  Code,
  Loader2,
} from "lucide-react";
import type { AttackHistoryEntry, RawTicketResponse, VerifyResult } from "../types";
import { api, getTicketRaw, ApiError } from "../lib/api";
import { useToast } from "./toast";
import { ServiceBanner } from "./service-banner";
import { ResultBadge } from "./verify-page";

const JSON_TEMPLATE = `{
  "v": 1,
  "type": "R",
  "uuid": "00000000-0000-0000-0000-000000000000",
  "train": "12051",
  "from": "FAKE",
  "to": "FAKE",
  "class": "SL",
  "date": "2026-01-01",
  "vf": 0,
  "vu": 9999999999,
  "iat": 0,
  "pax": [{ "b": "B1/1", "id": null }]
}`;

const timestampOptions: Intl.DateTimeFormatOptions = {
  day: "2-digit",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: true,
};

const formatTime = (date: Date) => date.toLocaleString("en-IN", timestampOptions);

const base64ToUint8 = (base64: string) => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

const uint8ToBase64 = (bytes: Uint8Array) => {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

const utf8ToBase64 = (text: string) => {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const AttackCard = ({
  icon,
  title,
  description,
  children,
}: {
  icon: ReactNode;
  title: string;
  description: string;
  children: ReactNode;
}) => (
  <div className="card" style={{ padding: 20 }}>
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
      <div style={{ width: 36, height: 36, borderRadius: 999, background: "var(--surface)", display: "inline-flex", alignItems: "center", justifyContent: "center", color: "var(--accent-c)" }}>
        {icon}
      </div>
      <div>
        <h3 style={{ margin: 0, fontSize: 16 }}>{title}</h3>
        <p style={{ margin: "6px 0 0", color: "var(--text-secondary)", fontSize: 13, lineHeight: 1.5 }}>{description}</p>
      </div>
    </div>
    {children}
  </div>
);

export function AttacksPage() {
  const toast = useToast();
  const [bannerErr, setBannerErr] = useState<unknown>(null);
  const [history, setHistory] = useState<AttackHistoryEntry[]>([]);

  const [forgeryPnr, setForgeryPnr] = useState("");
  const [forgeryTte, setForgeryTte] = useState("");
  const [forgeryTrain, setForgeryTrain] = useState("");
  const [forgeryResult, setForgeryResult] = useState<VerifyResult | null>(null);
  const [forgeryLoading, setForgeryLoading] = useState(false);

  const [replayPnr, setReplayPnr] = useState("");
  const [replayTte, setReplayTte] = useState("");
  const [replayTrain, setReplayTrain] = useState("");
  const [replayResults, setReplayResults] = useState<Array<{ label: string; result: VerifyResult }>>([]);
  const [replayLoading, setReplayLoading] = useState(false);

  const [wrongTrainPnr, setWrongTrainPnr] = useState("");
  const [wrongTrainActual, setWrongTrainActual] = useState("");
  const [wrongTrainClaim, setWrongTrainClaim] = useState("");
  const [wrongTrainTte, setWrongTrainTte] = useState("");
  const [wrongTrainResult, setWrongTrainResult] = useState<VerifyResult | null>(null);
  const [wrongTrainLoading, setWrongTrainLoading] = useState(false);

  const [expiredPnr, setExpiredPnr] = useState("");
  const [expiredTte, setExpiredTte] = useState("");
  const [expiredTrain, setExpiredTrain] = useState("");
  const [expiredResult, setExpiredResult] = useState<VerifyResult | null>(null);
  const [expiredLoading, setExpiredLoading] = useState(false);

  const [identityPnr, setIdentityPnr] = useState("");
  const [identityTte, setIdentityTte] = useState("");
  const [identityTrain, setIdentityTrain] = useState("");
  const [identityAadhaar, setIdentityAadhaar] = useState("");
  const [identityDob, setIdentityDob] = useState("");
  const [identityResult, setIdentityResult] = useState<VerifyResult | null>(null);
  const [identityLoading, setIdentityLoading] = useState(false);

  const [payloadText, setPayloadText] = useState(JSON_TEMPLATE);
  const [injectionTte, setInjectionTte] = useState("");
  const [injectionTrain, setInjectionTrain] = useState("");
  const [injectionResult, setInjectionResult] = useState<VerifyResult | null>(null);
  const [injectionLoading, setInjectionLoading] = useState(false);

  const addHistory = (attack: string, pnr: string, result: string) => {
    setHistory((prev) => [{ attack, pnr, result, timestamp: new Date() }, ...prev].slice(0, 20));
  };

  const runSignatureForgery = async () => {
    setForgeryLoading(true);
    setBannerErr(null);
    setForgeryResult(null);
    try {
      if (!forgeryPnr.trim()) throw new Error("PNR is required.");
      if (!forgeryTte.trim()) throw new Error("TTE ID is required.");
      if (!forgeryTrain.trim()) throw new Error("Train Number is required.");

      const raw = await getTicketRaw(forgeryPnr.trim());
      const bytes = base64ToUint8(raw.barcode_b64);
      const start = Math.floor(bytes.length * 0.8);
      const end = bytes.length;
      for (let i = 0; i < 8; i++) {
        const idx = start + Math.floor(Math.random() * Math.max(1, end - start));
        bytes[idx] ^= 0xff;
      }
      const corrupted = uint8ToBase64(bytes);
      const result = await api.verify<VerifyResult>({ barcode_b64: corrupted, tte_id: forgeryTte.trim(), train: forgeryTrain.trim() });
      setForgeryResult(result);
      addHistory("Signature Forgery", forgeryPnr.trim(), result.result);
    } catch (err) {
      setBannerErr(err);
      const message = err instanceof ApiError ? `${err.status || "ERR"} — ${err.message}` : (err as Error).message;
      toast.push("error", message);
    } finally {
      setForgeryLoading(false);
    }
  };

  const runReplayAttack = async () => {
    setReplayLoading(true);
    setBannerErr(null);
    setReplayResults([]);
    try {
      if (!replayPnr.trim()) throw new Error("PNR is required.");
      if (!replayTte.trim()) throw new Error("TTE ID is required.");
      if (!replayTrain.trim()) throw new Error("Train Number is required.");

      const raw = await getTicketRaw(replayPnr.trim());
      const first = await api.verify<VerifyResult>({ barcode_b64: raw.barcode_b64, tte_id: replayTte.trim(), train: replayTrain.trim() });
      await sleep(500);
      const second = await api.verify<VerifyResult>({ barcode_b64: raw.barcode_b64, tte_id: replayTte.trim(), train: replayTrain.trim() });
      setReplayResults([
        { label: "First Scan", result: first },
        { label: "Replay Attempt", result: second },
      ]);
      addHistory("Replay Attack", replayPnr.trim(), second.result);
    } catch (err) {
      setBannerErr(err);
      const message = err instanceof ApiError ? `${err.status || "ERR"} — ${err.message}` : (err as Error).message;
      toast.push("error", message);
    } finally {
      setReplayLoading(false);
    }
  };

  const runWrongTrainAttack = async () => {
    setWrongTrainLoading(true);
    setBannerErr(null);
    setWrongTrainResult(null);
    try {
      if (!wrongTrainPnr.trim()) throw new Error("PNR is required.");
      if (!wrongTrainClaim.trim()) throw new Error("Attacker Claims Train is required.");
      if (!wrongTrainTte.trim()) throw new Error("TTE ID is required.");

      const raw = await getTicketRaw(wrongTrainPnr.trim());
      setWrongTrainActual(raw.payload.train);
      const result = await api.verify<VerifyResult>({ barcode_b64: raw.barcode_b64, tte_id: wrongTrainTte.trim(), train: wrongTrainClaim.trim() });
      setWrongTrainResult(result);
      addHistory("Wrong Train Boarding", wrongTrainPnr.trim(), result.result);
    } catch (err) {
      setBannerErr(err);
      const message = err instanceof ApiError ? `${err.status || "ERR"} — ${err.message}` : (err as Error).message;
      toast.push("error", message);
    } finally {
      setWrongTrainLoading(false);
    }
  };

  const runExpiredAttack = async () => {
    setExpiredLoading(true);
    setBannerErr(null);
    setExpiredResult(null);
    try {
      if (!expiredPnr.trim()) throw new Error("PNR is required.");
      if (!expiredTte.trim()) throw new Error("TTE ID is required.");
      if (!expiredTrain.trim()) throw new Error("Train Number is required.");

      const raw = await getTicketRaw(expiredPnr.trim());
      const result = await api.verify<VerifyResult>({ barcode_b64: raw.barcode_b64, tte_id: expiredTte.trim(), train: expiredTrain.trim() });
      setExpiredResult(result);
      addHistory("Expired Ticket", expiredPnr.trim(), result.result);
    } catch (err) {
      setBannerErr(err);
      const message = err instanceof ApiError ? `${err.status || "ERR"} — ${err.message}` : (err as Error).message;
      toast.push("error", message);
    } finally {
      setExpiredLoading(false);
    }
  };

  const runIdentityAttack = async () => {
    setIdentityLoading(true);
    setBannerErr(null);
    setIdentityResult(null);
    try {
      if (!identityPnr.trim()) throw new Error("PNR is required.");
      if (!identityTte.trim()) throw new Error("TTE ID is required.");
      if (!identityTrain.trim()) throw new Error("Train Number is required.");
      if (!identityAadhaar.trim()) throw new Error("Fake Aadhaar is required.");
      if (!identityDob.trim()) throw new Error("Date of Birth is required.");

      const raw = await getTicketRaw(identityPnr.trim());
      const result = await api.verify<VerifyResult>({
        barcode_b64: raw.barcode_b64,
        tte_id: identityTte.trim(),
        train: identityTrain.trim(),
        aadhaar: identityAadhaar.trim(),
        dob: identityDob,
      });
      setIdentityResult(result);
      addHistory("Identity Fraud", identityPnr.trim(), result.result);
    } catch (err) {
      setBannerErr(err);
      const message = err instanceof ApiError ? `${err.status || "ERR"} — ${err.message}` : (err as Error).message;
      toast.push("error", message);
    } finally {
      setIdentityLoading(false);
    }
  };

  const runInjectionAttack = async () => {
    setInjectionLoading(true);
    setBannerErr(null);
    setInjectionResult(null);
    try {
      if (!payloadText.trim()) throw new Error("Payload JSON is required.");
      if (!injectionTte.trim()) throw new Error("TTE ID is required.");
      if (!injectionTrain.trim()) throw new Error("Train Number is required.");

      const parsed = JSON.parse(payloadText);
      const barcode_b64 = utf8ToBase64(JSON.stringify(parsed));
      const result = await api.verify<VerifyResult>({
        barcode_b64,
        tte_id: injectionTte.trim(),
        train: injectionTrain.trim(),
      });
      setInjectionResult(result);
      addHistory("Payload Injection", "CUSTOM", result.result);
    } catch (err) {
      setBannerErr(err);
      const message = err instanceof ApiError ? `${err.status || "ERR"} — ${err.message}` : (err as Error).message;
      toast.push("error", message);
    } finally {
      setInjectionLoading(false);
    }
  };

  return (
    <div>
      <ServiceBanner error={bannerErr} />
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <ShieldAlert size={20} color="var(--accent-c)" />
        <div>
          <h2 style={{ margin: 0, fontSize: 20 }}>Attack Simulator</h2>
          <p style={{ margin: "6px 0 0", color: "var(--text-secondary)", fontSize: 13 }}>
            Simulate adversarial scenarios to demonstrate post-quantum resilience.
          </p>
        </div>
      </div>

      <div style={{ background: "var(--amber-light)", border: "1px solid var(--amber)", borderRadius: 8, padding: 16, marginTop: 18 }}>
        <strong>⚠ These simulations run against your local backend only. All attacks are expected to be detected and rejected.</strong>
      </div>

      <div style={{ display: "grid", gap: 18, marginTop: 22 }}>
        <AttackCard
          icon={<Pen size={18} />}
          title="Signature Forgery"
          description="Tamper with the barcode payload and attempt to verify it. The Falcon-padded-512 signature will be invalid."
        >
          <div style={{ display: "grid", gap: 12 }}>
            <input className="input mono" placeholder="PNR" value={forgeryPnr} onChange={(e) => setForgeryPnr(e.target.value)} />
            <input className="input" placeholder="TTE ID" value={forgeryTte} onChange={(e) => setForgeryTte(e.target.value)} />
            <input className="input" placeholder="Train Number" value={forgeryTrain} onChange={(e) => setForgeryTrain(e.target.value)} />
            <button className="btn btn-primary" onClick={runSignatureForgery} disabled={forgeryLoading} style={{ width: "100%" }}>
              {forgeryLoading ? <Loader2 size={16} className="spin" /> : "Run Attack"}
            </button>
            {forgeryResult && (
              <div style={{ marginTop: 12 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}><ResultBadge code={forgeryResult.result} /><span style={{ color: "var(--text-secondary)" }}>{forgeryResult.signature_valid ? "Signature valid" : "Signature invalid"}</span></div>
              </div>
            )}
          </div>
        </AttackCard>

        <AttackCard
          icon={<Copy size={18} />}
          title="Replay Attack (Duplicate Scan)"
          description="Scan the same valid ticket twice. The audit server detects the duplicate UUID and rejects the second scan."
        >
          <div style={{ display: "grid", gap: 12 }}>
            <input className="input mono" placeholder="PNR" value={replayPnr} onChange={(e) => setReplayPnr(e.target.value)} />
            <input className="input" placeholder="TTE ID" value={replayTte} onChange={(e) => setReplayTte(e.target.value)} />
            <input className="input" placeholder="Train Number" value={replayTrain} onChange={(e) => setReplayTrain(e.target.value)} />
            <button className="btn btn-primary" onClick={runReplayAttack} disabled={replayLoading} style={{ width: "100%" }}>
              {replayLoading ? <Loader2 size={16} className="spin" /> : "Run Attack"}
            </button>
            {replayResults.length > 0 && (
              <div style={{ marginTop: 12, display: "grid", gap: 10 }}>
                {replayResults.map((entry) => (
                  <div key={entry.label} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <strong style={{ minWidth: 96, fontSize: 13 }}>{entry.label}:</strong>
                    <ResultBadge code={entry.result.result} />
                  </div>
                ))}
              </div>
            )}
          </div>
        </AttackCard>

        <AttackCard
          icon={<Train size={18} />}
          title="Wrong Train Boarding"
          description="Present a valid ticket but claim the passenger is on a different train. The HHT cross-checks the chart."
        >
          <div style={{ display: "grid", gap: 12 }}>
            <input className="input mono" placeholder="PNR" value={wrongTrainPnr} onChange={(e) => setWrongTrainPnr(e.target.value)} />
            <input className="input" placeholder="Actual Train" value={wrongTrainActual} onChange={(e) => setWrongTrainActual(e.target.value)} />
            <input className="input" placeholder="Attacker Claims Train (e.g. 99999)" value={wrongTrainClaim} onChange={(e) => setWrongTrainClaim(e.target.value)} />
            <input className="input" placeholder="TTE ID" value={wrongTrainTte} onChange={(e) => setWrongTrainTte(e.target.value)} />
            <button className="btn btn-primary" onClick={runWrongTrainAttack} disabled={wrongTrainLoading} style={{ width: "100%" }}>
              {wrongTrainLoading ? <Loader2 size={16} className="spin" /> : "Run Attack"}
            </button>
            {wrongTrainResult && (
              <div style={{ marginTop: 12 }}>
                <ResultBadge code={wrongTrainResult.result} />
              </div>
            )}
          </div>
        </AttackCard>

        <AttackCard
          icon={<Clock size={18} />}
          title="Expired Ticket"
          description="Attempt to board using a ticket whose validity window has passed."
        >
          <div style={{ display: "grid", gap: 12 }}>
            <input className="input mono" placeholder="PNR" value={expiredPnr} onChange={(e) => setExpiredPnr(e.target.value)} />
            <input className="input" placeholder="TTE ID" value={expiredTte} onChange={(e) => setExpiredTte(e.target.value)} />
            <input className="input" placeholder="Train Number" value={expiredTrain} onChange={(e) => setExpiredTrain(e.target.value)} />
            <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 0 }}>
              Book a ticket with a past travel date first, then enter that PNR here.
            </div>
            <button className="btn btn-primary" onClick={runExpiredAttack} disabled={expiredLoading} style={{ width: "100%" }}>
              {expiredLoading ? <Loader2 size={16} className="spin" /> : "Run Attack"}
            </button>
            {expiredResult && (
              <div style={{ marginTop: 12 }}>
                <ResultBadge code={expiredResult.result} />
              </div>
            )}
          </div>
        </AttackCard>

        <AttackCard
          icon={<UserX size={18} />}
          title="Identity Fraud"
          description="Present a valid ticket but claim a different Aadhaar number. The biometric hash will not match."
        >
          <div style={{ display: "grid", gap: 12 }}>
            <input className="input mono" placeholder="PNR" value={identityPnr} onChange={(e) => setIdentityPnr(e.target.value)} />
            <input className="input" placeholder="TTE ID" value={identityTte} onChange={(e) => setIdentityTte(e.target.value)} />
            <input className="input" placeholder="Train Number" value={identityTrain} onChange={(e) => setIdentityTrain(e.target.value)} />
            <input className="input" placeholder="Enter a wrong 12-digit number" value={identityAadhaar} onChange={(e) => setIdentityAadhaar(e.target.value)} inputMode="numeric" />
            <input className="input" type="date" value={identityDob} onChange={(e) => setIdentityDob(e.target.value)} />
            <button className="btn btn-primary" onClick={runIdentityAttack} disabled={identityLoading} style={{ width: "100%" }}>
              {identityLoading ? <Loader2 size={16} className="spin" /> : "Run Attack"}
            </button>
            {identityResult && (
              <div style={{ marginTop: 12 }}>
                <ResultBadge code={identityResult.result} />
                <div style={{ marginTop: 6, color: "var(--text-secondary)", fontSize: 13 }}>
                  identity_check: <strong>{identityResult.identity_check}</strong>
                </div>
              </div>
            )}
          </div>
        </AttackCard>

        <AttackCard
          icon={<Code size={18} />}
          title="Payload Injection"
          description="Manually craft a fake barcode payload and attempt to verify it without a valid Falcon signature."
        >
          <div style={{ display: "grid", gap: 12 }}>
            <textarea
              className="input mono"
              style={{ minHeight: 180, fontFamily: "monospace" }}
              value={payloadText}
              onChange={(e) => setPayloadText(e.target.value)}
            />
            <input className="input" placeholder="TTE ID" value={injectionTte} onChange={(e) => setInjectionTte(e.target.value)} />
            <input className="input" placeholder="Train Number" value={injectionTrain} onChange={(e) => setInjectionTrain(e.target.value)} />
            <button className="btn btn-primary" onClick={runInjectionAttack} disabled={injectionLoading} style={{ width: "100%" }}>
              {injectionLoading ? <Loader2 size={16} className="spin" /> : "Run Attack"}
            </button>
            {injectionResult && (
              <div style={{ marginTop: 12 }}>
                <ResultBadge code={injectionResult.result} />
              </div>
            )}
          </div>
        </AttackCard>
      </div>

      <div style={{ marginTop: 28 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
          <h3 style={{ margin: 0, fontSize: 16 }}>Attack History</h3>
          <button className="btn btn-ghost" onClick={() => setHistory([])} style={{ whiteSpace: "nowrap" }}>
            Clear History
          </button>
        </div>
        {history.length === 0 ? (
          <p style={{ color: "var(--text-muted)", fontSize: 13, marginTop: 10 }}>No attacks run yet.</p>
        ) : (
          <div className="card" style={{ marginTop: 12, overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ textAlign: "left", color: "var(--text-secondary)", background: "var(--bg)" }}>
                  <th style={{ padding: "10px 12px" }}>Time</th>
                  <th style={{ padding: "10px 12px" }}>Attack Type</th>
                  <th style={{ padding: "10px 12px" }}>PNR</th>
                  <th style={{ padding: "10px 12px" }}>Result</th>
                </tr>
              </thead>
              <tbody>
                {history.map((entry, index) => (
                  <tr key={`${entry.attack}-${entry.timestamp.toISOString()}-${index}`} style={{ borderTop: "1px solid var(--border-c)" }}>
                    <td style={{ padding: "10px 12px" }}>{formatTime(entry.timestamp)}</td>
                    <td style={{ padding: "10px 12px" }}>{entry.attack}</td>
                    <td style={{ padding: "10px 12px" }} className="mono">{entry.pnr}</td>
                    <td style={{ padding: "10px 12px" }}><ResultBadge code={entry.result} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
