import { SERVICES, SERVICE_META, type ServiceKey } from "../config";
import type { RawTicketResponse } from "../types";

export class ApiError extends Error {
  status: number;
  service: ServiceKey;
  constructor(service: ServiceKey, status: number, message: string) {
    super(message);
    this.status = status;
    this.service = service;
  }
}

async function call<T>(
  service: ServiceKey,
  path: string,
  init?: RequestInit,
): Promise<T> {
  const url = `${SERVICES[service]}${path}`;
  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(init?.headers ?? {}),
      },
    });
  } catch (e) {
    const meta = SERVICE_META[service];
    throw new ApiError(service, 0, `${meta.name} unreachable (:${meta.port})`);
  }
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      msg = body?.detail || body?.error || body?.message || msg;
    } catch {
      try {
        msg = (await res.text()) || msg;
      } catch {}
    }
    throw new ApiError(service, res.status, msg);
  }
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) return res.json() as Promise<T>;
  return (await res.text()) as unknown as T;
}

export const api = {
  book: <T>(body: unknown) =>
    call<T>("prs", "/book", { method: "POST", body: JSON.stringify(body) }),
  rawTicket: <T>(pnr: string) => call<T>("prs", `/ticket/${pnr}/raw`),
  ticketQrUrl: (pnr: string) => `${SERVICES.prs}/ticket/${pnr}/qr`,
  verify: <T>(body: unknown) =>
    call<T>("hht", "/verify", { method: "POST", body: JSON.stringify(body) }),
  stats: <T>() => call<T>("audit", "/stats"),
  duplicates: <T>() => call<T>("audit", "/duplicates"),
  log: <T>(uuid: string) => call<T>("audit", `/log/${uuid}`),
  chart: <T>(train: string, date: string) =>
    call<T>("hht", `/chart/${train}/${date}`),
  clearChart: <T>(train: string, date: string) =>
    call<T>("hht", `/chart/${train}/${date}`, { method: "DELETE" }),
  health: async (service: ServiceKey): Promise<boolean> => {
    try {
      const res = await fetch(`${SERVICES[service]}/health`, { method: "GET" });
      return res.ok;
    } catch {
      return false;
    }
  },
};

export async function getTicketRaw(pnr: string): Promise<RawTicketResponse> {
  return api.rawTicket<RawTicketResponse>(pnr);
}
