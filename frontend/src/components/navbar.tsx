import { useEffect, useState } from "react";
import { Menu, X, Swords } from "lucide-react";
import { SERVICE_META, type ServiceKey } from "../config";
import { api } from "../lib/api";

export type PageKey = "book" | "verify" | "audit" | "chart" | "attacks";

const NAV: { key: PageKey; label: string }[] = [
  { key: "book", label: "Book" },
  { key: "verify", label: "Verify" },
  { key: "audit", label: "Audit" },
  { key: "chart", label: "Chart" },
  { key: "attacks", label: "Attacks" },
];

export function Navbar({
  active,
  onChange,
}: {
  active: PageKey;
  onChange: (p: PageKey) => void;
}) {
  const [open, setOpen] = useState(false);
  const [health, setHealth] = useState<Record<ServiceKey, boolean | null>>({
    prs: null,
    cris: null,
    audit: null,
    hht: null,
  });

  useEffect(() => {
    let cancelled = false;
    const check = async () => {
      const keys: ServiceKey[] = ["prs", "cris", "audit", "hht"];
      const results = await Promise.all(keys.map((k) => api.health(k)));
      if (cancelled) return;
      const next: Record<ServiceKey, boolean> = {} as Record<ServiceKey, boolean>;
      keys.forEach((k, i) => (next[k] = results[i]));
      setHealth(next);
    };
    check();
    const id = setInterval(check, 30000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const pick = (p: PageKey) => {
    onChange(p);
    setOpen(false);
  };

  return (
    <header style={{ position: "sticky", top: 0, zIndex: 50 }}>
      <div
        style={{
          background: "var(--surface)",
          borderBottom: "3px solid var(--accent-c)",
        }}
      >
        <div
          style={{
            maxWidth: 1200,
            margin: "0 auto",
            padding: "14px 24px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 16,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Logo />
            <span style={{ color: "var(--accent-c)", fontWeight: 700, fontSize: 17, letterSpacing: "-0.01em" }}>
              PQ Rail Auth
            </span>
          </div>
          <nav className="nav-desktop" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {NAV.map((n) => (
              <NavLink key={n.key} active={active === n.key} onClick={() => pick(n.key)}>
                {n.key === "attacks" ? <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}><Swords size={14} />{n.label}</span> : n.label}
              </NavLink>
            ))}
            <div style={{ display: "flex", gap: 6, marginLeft: 14, paddingLeft: 14, borderLeft: "1px solid var(--border-c)" }}>
              {(Object.keys(SERVICE_META) as ServiceKey[]).map((k) => (
                <HealthDot key={k} svc={k} ok={health[k]} />
              ))}
            </div>
          </nav>
          <button
            aria-label="Toggle menu"
            onClick={() => setOpen((o) => !o)}
            className="nav-mobile-btn"
            style={{
              display: "none",
              background: "transparent",
              border: "1px solid var(--border-c)",
              borderRadius: 6,
              padding: 8,
              cursor: "pointer",
              color: "var(--text-primary)",
            }}
          >
            {open ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>
        {open && (
          <div className="nav-mobile-drawer" style={{ borderTop: "1px solid var(--border-c)", padding: 12 }}>
            {NAV.map((n) => (
              <button
                key={n.key}
                onClick={() => pick(n.key)}
                style={{
                  display: "block",
                  width: "100%",
                  textAlign: "left",
                  padding: "10px 12px",
                  border: 0,
                  background: active === n.key ? "var(--accent-light)" : "transparent",
                  color: active === n.key ? "var(--accent-c)" : "var(--text-primary)",
                  fontWeight: 500,
                  borderRadius: 6,
                  cursor: "pointer",
                }}
              >
                {n.label}
              </button>
            ))}
            <div style={{ display: "flex", gap: 10, padding: "12px 4px 4px", flexWrap: "wrap" }}>
              {(Object.keys(SERVICE_META) as ServiceKey[]).map((k) => (
                <div key={k} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-secondary)" }}>
                  <HealthDot svc={k} ok={health[k]} />
                  {SERVICE_META[k].name}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
      <div style={{ height: 4, background: "linear-gradient(135deg, var(--accent-c) 0%, var(--orange) 100%)" }} />
      <style>{`
        @media (max-width: 768px) {
          .nav-desktop { display: none !important; }
          .nav-mobile-btn { display: inline-flex !important; }
        }
      `}</style>
    </header>
  );
}

function NavLink({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      style={{
        background: "transparent",
        border: 0,
        padding: "8px 4px",
        margin: "0 6px",
        fontSize: 14,
        fontWeight: 500,
        cursor: "pointer",
        color: active ? "var(--accent-c)" : "var(--text-primary)",
        borderBottom: active ? "2px solid var(--accent-c)" : "2px solid transparent",
      }}
    >
      {children}
    </button>
  );
}

function HealthDot({ svc, ok }: { svc: ServiceKey; ok: boolean | null }) {
  const meta = SERVICE_META[svc];
  const color = ok === null ? "var(--text-muted)" : ok ? "var(--green)" : "var(--red)";
  const label = ok === null ? "checking" : ok ? "healthy" : "unreachable";
  return (
    <span
      title={`${meta.name} :${meta.port} — ${label}`}
      aria-label={`${meta.name} ${label}`}
      style={{ width: 10, height: 10, borderRadius: "50%", background: color, display: "inline-block" }}
    />
  );
}

function Logo() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true">
      <rect x="1" y="5" width="18" height="2" fill="var(--accent-c)" />
      <rect x="1" y="13" width="18" height="2" fill="var(--accent-c)" />
      <rect x="3" y="8" width="2" height="4" fill="var(--accent-c)" />
      <rect x="9" y="8" width="2" height="4" fill="var(--accent-c)" />
      <rect x="15" y="8" width="2" height="4" fill="var(--accent-c)" />
    </svg>
  );
}