export const SERVICES = {
  prs: "http://localhost:8000",
  cris: "http://localhost:8001",
  audit: "http://localhost:8002",
  hht: "http://localhost:8003",
} as const;

export type ServiceKey = keyof typeof SERVICES;

export const SERVICE_META: Record<ServiceKey, { name: string; port: number }> = {
  prs: { name: "PRS Booking", port: 8000 },
  cris: { name: "CRIS Signing", port: 8001 },
  audit: { name: "Audit Server", port: 8002 },
  hht: { name: "HHT Terminal", port: 8003 },
};