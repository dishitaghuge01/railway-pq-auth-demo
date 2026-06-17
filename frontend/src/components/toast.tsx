import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { CheckCircle2, XCircle, AlertTriangle, X } from "lucide-react";

type ToastKind = "success" | "error" | "warning";
interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

interface ToastCtx {
  push: (kind: ToastKind, message: string) => void;
}
const Ctx = createContext<ToastCtx | null>(null);

export function useToast() {
  const c = useContext(Ctx);
  if (!c) throw new Error("ToastProvider missing");
  return c;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((kind: ToastKind, message: string) => {
    setToasts((t) => [...t, { id: Date.now() + Math.random(), kind, message }]);
  }, []);
  const dismiss = (id: number) => setToasts((t) => t.filter((x) => x.id !== id));

  return (
    <Ctx.Provider value={{ push }}>
      {children}
      <div
        style={{ position: "fixed", bottom: 16, right: 16, zIndex: 100, display: "flex", flexDirection: "column", gap: 8, maxWidth: 360 }}
      >
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} onClose={() => dismiss(t.id)} />
        ))}
      </div>
    </Ctx.Provider>
  );
}

function ToastItem({ toast, onClose }: { toast: Toast; onClose: () => void }) {
  useEffect(() => {
    const id = setTimeout(onClose, 5000);
    return () => clearTimeout(id);
  }, [onClose]);
  const bg = toast.kind === "success" ? "var(--green-light)" : toast.kind === "error" ? "var(--red-light)" : "var(--amber-light)";
  const fg = toast.kind === "success" ? "var(--green)" : toast.kind === "error" ? "var(--red)" : "var(--amber)";
  const Icon = toast.kind === "success" ? CheckCircle2 : toast.kind === "error" ? XCircle : AlertTriangle;
  return (
    <div
      role="status"
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: 10,
        background: "var(--surface)",
        border: `1px solid ${fg}`,
        borderLeft: `4px solid ${fg}`,
        borderRadius: 8,
        padding: "12px 14px",
        boxShadow: "0 1px 3px rgba(0,0,0,0.08)",
      }}
    >
      <div style={{ color: fg, marginTop: 2 }}>
        <Icon size={18} />
      </div>
      <div style={{ flex: 1, fontSize: 13, color: "var(--text-primary)" }}>{toast.message}</div>
      <button
        onClick={onClose}
        aria-label="Dismiss"
        style={{ background: "transparent", border: 0, cursor: "pointer", color: "var(--text-muted)", padding: 2, display: "inline-flex" }}
      >
        <X size={14} />
      </button>
    </div>
  );
}