import { useState } from "react";
import { Ticket, Send, Plus, Trash2, FileText, Copy, Check, Loader2, Download } from "lucide-react";
import type { BookRequest, BookResponse, PassengerInput, RawTicket, TicketType } from "../types";
import { api, ApiError } from "../lib/api";
import { useToast } from "./toast";
import { ServiceBanner } from "./service-banner";

const CLASSES = ["SL", "3A", "2A", "1A", "CC", "EC", "2S", "GN"];

interface FormState {
  ticket_type: TicketType;
  train: string;
  from_stn: string;
  to_stn: string;
  ticket_class: string;
  travel_date: string;
  departure_time: string;
  arrival_time: string;
  passengers: PassengerInput[];
}

const empty = (): PassengerInput => ({ name: "", berth: "", aadhaar: "", dob: "" });

export function BookPage({
  ticket,
  setTicket,
}: {
  ticket: { book: BookResponse; raw: RawTicket } | null;
  setTicket: (t: { book: BookResponse; raw: RawTicket } | null) => void;
}) {
  const toast = useToast();
  const [form, setForm] = useState<FormState>({
    ticket_type: "R",
    train: "",
    from_stn: "",
    to_stn: "",
    ticket_class: "3A",
    travel_date: "",
    departure_time: "",
    arrival_time: "",
    passengers: [empty()],
  });
  const [loading, setLoading] = useState(false);
  const [bannerErr, setBannerErr] = useState<unknown>(null);
  const [copied, setCopied] = useState(false);

  const isTatkal = form.ticket_type === "T";
  const isUnreserved = form.ticket_type === "U";

  const updateP = (i: number, patch: Partial<PassengerInput>) => {
    setForm((f) => ({
      ...f,
      passengers: f.passengers.map((p, idx) => (idx === i ? { ...p, ...patch } : p)),
    }));
  };

  const addP = () => {
    if (form.passengers.length >= 6) return;
    setForm((f) => ({ ...f, passengers: [...f.passengers, empty()] }));
  };
  const removeP = (i: number) =>
    setForm((f) => ({ ...f, passengers: f.passengers.filter((_, idx) => idx !== i) }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setBannerErr(null);
    try {
      const payload: BookRequest = {
        ticket_type: form.ticket_type,
        train: form.train,
        from_stn: form.from_stn,
        to_stn: form.to_stn,
        ticket_class: form.ticket_class,
        travel_date: form.travel_date,
        departure_time: form.departure_time,
        arrival_time: form.arrival_time,
        passengers: form.passengers.map((p) => {
          const o: PassengerInput = { name: p.name };
          if (!isUnreserved && p.berth) o.berth = p.berth;
          if (p.aadhaar && p.aadhaar.trim()) {
            o.aadhaar = p.aadhaar.trim();
            if (p.dob) o.dob = p.dob;
          }
          return o;
        }),
      };
      const book = await api.book<BookResponse>(payload);
      const raw = await api.rawTicket<RawTicket>(book.pnr);
      setTicket({ book, raw });
      toast.push("success", `Ticket ${book.pnr} issued and quantum-signed.`);
    } catch (err) {
      setBannerErr(err);
      const msg = err instanceof ApiError ? `${err.status || "ERR"} — ${err.message}` : (err as Error).message;
      toast.push("error", msg);
    } finally {
      setLoading(false);
    }
  };

  const copyPnr = async () => {
    if (!ticket) return;
    await navigator.clipboard.writeText(ticket.book.pnr);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div>
      <ServiceBanner error={bannerErr} />
      <div className="book-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
        <form
          className="card"
          onSubmit={submit}
          style={{ borderLeft: isTatkal ? "4px solid var(--orange)" : "1px solid var(--border-c)" }}
        >
          <h2 style={{ display: "flex", alignItems: "center", gap: 8, margin: 0, fontSize: 18 }}>
            <Ticket size={18} color="var(--accent-c)" /> Issue New Ticket
          </h2>
          <p style={{ color: "var(--text-secondary)", fontSize: 13, marginTop: 6 }}>
            Falcon-padded-512 signature is applied automatically by the CRIS service.
          </p>

          <div style={{ marginTop: 18 }}>
            <label className="label">Ticket Type</label>
            <div style={{ display: "flex", border: "1px solid var(--border-c)", borderRadius: 6, overflow: "hidden" }}>
              {(["R", "U", "T"] as TicketType[]).map((t) => (
                <button
                  type="button"
                  key={t}
                  onClick={() => setForm((f) => ({ ...f, ticket_type: t }))}
                  style={{
                    flex: 1,
                    padding: "9px 8px",
                    border: 0,
                    background: form.ticket_type === t ? (t === "T" ? "var(--orange)" : "var(--accent-c)") : "var(--surface)",
                    color: form.ticket_type === t ? "#fff" : "var(--text-primary)",
                    fontWeight: 500,
                    fontSize: 13,
                    cursor: "pointer",
                  }}
                >
                  {t === "R" ? "R — Reserved" : t === "U" ? "U — Unreserved" : "T — Tatkal"}
                </button>
              ))}
            </div>
          </div>

          <div className="form-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginTop: 16 }}>
            <Field label="Train Number">
              <input className="input mono" maxLength={5} placeholder="e.g. 12051" value={form.train}
                onChange={(e) => setForm({ ...form, train: e.target.value })} required />
            </Field>
            <Field label="From Station">
              <input className="input mono" maxLength={4} placeholder="e.g. CSMT" value={form.from_stn}
                onChange={(e) => setForm({ ...form, from_stn: e.target.value.toUpperCase() })} required />
            </Field>
            <Field label="To Station">
              <input className="input mono" maxLength={4} placeholder="e.g. NDLS" value={form.to_stn}
                onChange={(e) => setForm({ ...form, to_stn: e.target.value.toUpperCase() })} required />
            </Field>
            <Field label="Class">
              <select className="input select" value={form.ticket_class} onChange={(e) => setForm({ ...form, ticket_class: e.target.value })}>
                {CLASSES.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </Field>
            <Field label="Travel Date">
              <input className="input" type="date" value={form.travel_date} onChange={(e) => setForm({ ...form, travel_date: e.target.value })} required />
            </Field>
            <Field label="Departure">
              <input className="input" type="time" value={form.departure_time} onChange={(e) => setForm({ ...form, departure_time: e.target.value })} required />
            </Field>
            <Field label="Arrival">
              <input className="input" type="time" value={form.arrival_time} onChange={(e) => setForm({ ...form, arrival_time: e.target.value })} required />
            </Field>
          </div>

          <div style={{ marginTop: 22, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h3 style={{ margin: 0, fontSize: 14, color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.04em" }}>
              Passengers ({form.passengers.length})
            </h3>
            <button type="button" className="btn btn-ghost" onClick={addP} disabled={form.passengers.length >= 6} style={{ padding: "6px 12px", fontSize: 13 }}>
              <Plus size={14} /> Add Passenger
            </button>
          </div>
          {form.passengers.length >= 6 && (
            <p style={{ fontSize: 12, color: "var(--amber)", marginTop: 6 }}>Max 6 passengers.</p>
          )}

          <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 12 }}>
            {form.passengers.map((p, i) => (
              <div key={i} style={{ border: "1px solid var(--border-c)", borderRadius: 8, padding: 14 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                  <strong style={{ fontSize: 13, color: "var(--text-secondary)" }}>Passenger {i + 1}</strong>
                  {form.passengers.length > 1 && (
                    <button type="button" onClick={() => removeP(i)} aria-label="Remove" style={{ background: "transparent", border: 0, color: "var(--red)", cursor: "pointer", padding: 4, display: "inline-flex" }}>
                      <Trash2 size={14} />
                    </button>
                  )}
                </div>
                <div style={{ display: "grid", gridTemplateColumns: isUnreserved ? "1fr" : "1fr 120px", gap: 10 }}>
                  <Field label="Name">
                    <input className="input" value={p.name} onChange={(e) => updateP(i, { name: e.target.value })} required />
                  </Field>
                  {!isUnreserved && (
                    <Field label="Berth">
                      <input className="input mono" placeholder="B2/14" value={p.berth ?? ""} onChange={(e) => updateP(i, { berth: e.target.value })} />
                    </Field>
                  )}
                  <Field label="Aadhaar (optional)">
                    <input className="input mono" inputMode="numeric" maxLength={12} placeholder="12-digit number"
                      value={p.aadhaar ?? ""} onChange={(e) => updateP(i, { aadhaar: e.target.value.replace(/\D/g, "") })} />
                  </Field>
                  <Field label="Date of Birth">
                    <input className="input" type="date" value={p.dob ?? ""} onChange={(e) => updateP(i, { dob: e.target.value })} required={!!(p.aadhaar && p.aadhaar.trim())} />
                  </Field>
                </div>
              </div>
            ))}
          </div>

          <button type="submit" className="btn btn-primary" disabled={loading} style={{ width: "100%", marginTop: 22, padding: "12px 16px", fontSize: 15 }}>
            {loading ? <Loader2 size={16} className="spin" /> : <Send size={16} />}
            {loading ? "Issuing…" : "Issue Ticket"}
          </button>
        </form>

        <div>
          {ticket ? (
            <TicketCard ticket={ticket} copied={copied} onCopy={copyPnr} />
          ) : (
            <div style={{
              border: "2px dashed var(--border-c)", borderRadius: 8, padding: "60px 24px",
              textAlign: "center", color: "var(--text-muted)", display: "flex", flexDirection: "column",
              alignItems: "center", gap: 12, background: "var(--surface)",
            }}>
              <FileText size={32} />
              <p style={{ margin: 0, fontSize: 14 }}>Your issued ticket will appear here.</p>
            </div>
          )}
        </div>
      </div>

      <style>{`
        .spin { animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        @media (max-width: 768px) {
          .book-grid { grid-template-columns: 1fr !important; }
          .form-grid { grid-template-columns: 1fr 1fr !important; }
        }
      `}</style>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="label">{label}</label>
      {children}
    </div>
  );
}

function TicketCard({ ticket, copied, onCopy }: { ticket: { book: BookResponse; raw: RawTicket }; copied: boolean; onCopy: () => void }) {
  const { raw, book } = ticket;
  const p = raw.payload;
  const isTatkal = p.type === "T";
  const qr = api.ticketQrUrl(book.pnr);
  return (
    <div style={{ background: "var(--surface)", border: "1px solid var(--border-c)", borderRadius: 8, overflow: "hidden" }}>
      <div style={{ height: 8, background: isTatkal ? "var(--orange)" : "linear-gradient(135deg, var(--accent-c) 0%, var(--orange) 100%)" }} />
      <div style={{ padding: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
          <strong style={{ color: "var(--accent-c)", letterSpacing: "0.02em", fontSize: 13, textTransform: "uppercase" }}>Indian Railways</strong>
          <span className="mono" style={{ fontSize: 13, color: "var(--text-secondary)" }}>{book.pnr}</span>
        </div>
        <div style={{ marginTop: 14, fontSize: 22, fontWeight: 600 }} className="mono">{p.train}</div>
        <div style={{ marginTop: 12, display: "flex", justifyContent: "space-between", gap: 16, alignItems: "center" }}>
          <div>
            <div className="mono" style={{ fontSize: 18, fontWeight: 600 }}>{p.from} → {p.to}</div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 4 }}>{p.date}</div>
          </div>
          <span className="badge badge-accent">{p.class}</span>
        </div>
        <table style={{ width: "100%", marginTop: 18, fontSize: 13, borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left", color: "var(--text-secondary)", fontWeight: 500, borderBottom: "1px solid var(--border-c)" }}>
              <th style={{ padding: "8px 6px" }}>Name</th>
              <th style={{ padding: "8px 6px" }}>Berth</th>
              <th style={{ padding: "8px 6px" }}>ID Hash</th>
            </tr>
          </thead>
          <tbody>
            {p.pax.map((px, i) => (
              <tr key={i} style={{ borderBottom: "1px solid var(--border-c)" }}>
                <td style={{ padding: "8px 6px" }}>Passenger {i + 1}</td>
                <td style={{ padding: "8px 6px" }} className="mono">{px.b ?? "—"}</td>
                <td style={{ padding: "8px 6px", color: "var(--text-muted)" }} className="mono">{px.id ? px.id.slice(0, 8) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <div style={{ marginTop: 16, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span className={`badge ${isTatkal ? "badge-amber" : "badge-accent"}`}>{p.type === "R" ? "Reserved" : p.type === "U" ? "Unreserved" : "Tatkal"}</span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--green)", fontSize: 12, fontWeight: 500 }}>
            <Check size={14} /> Quantum-signed
          </span>
        </div>

        <div style={{ marginTop: 18, display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
          <div style={{ background: "#fff", padding: 16, border: "1px solid var(--border-c)", borderRadius: 6 }}>
            <img src={qr} alt="DataMatrix barcode"
              style={{ width: 200, height: 200, imageRendering: "pixelated", display: "block" }} />
          </div>
          <p style={{ margin: 0, fontSize: 11, color: "var(--text-muted)" }}>
            DataMatrix ECC200 — Falcon-padded-512 signed
          </p>
          <div style={{ display: "flex", gap: 10, marginTop: 6 }}>
            <a href={qr} download={`${book.pnr}.png`} className="btn btn-ghost" style={{ padding: "6px 12px", fontSize: 12, textDecoration: "none" }}>
              <Download size={13} /> Download PNG
            </a>
            <button onClick={onCopy} className="btn btn-ghost" style={{ padding: "6px 12px", fontSize: 12 }}>
              {copied ? <Check size={13} /> : <Copy size={13} />} {copied ? "Copied!" : "Copy PNR"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}