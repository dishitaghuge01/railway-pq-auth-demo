export const SERVICES = {
  prs: "/api/prs",
  cris: "/api/cris",
  audit: "/api/audit",
  hht: "/api/hht",
} as const;

export type ServiceKey = keyof typeof SERVICES;

export const SERVICE_META: Record<ServiceKey, { name: string; port: number }> = {
  prs: { name: "PRS Booking", port: 8000 },
  cris: { name: "CRIS Signing", port: 8001 },
  audit: { name: "Audit Server", port: 8002 },
  hht: { name: "HHT Terminal", port: 8003 },
};