// ============================================================================
// Ticket Types
// ============================================================================

export type TicketType = "R" | "U" | "T";

export interface PassengerInput {
  name: string;
  berth?: string;
  aadhaar?: string;
  dob?: string;
}

export interface BookRequest {
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

export interface BookResponse {
  pnr: string;
  uuid: string;
  ticket_url: string;
  qr_url: string;
  barcode_size_bytes: number;
  message: string;
}

export interface TicketPayloadPax {
  b?: string;  // berth
  id?: string | null;  // SHA256 hash
}

export interface TicketPayload {
  v: number;  // version
  type: TicketType;
  uuid: string;
  train: string;
  from: string;
  to: string;
  class: string;
  date: string;
  vf: number;  // valid from (Unix timestamp)
  vu: number;  // valid until (Unix timestamp)
  iat: number;  // issued at (Unix timestamp)
  pax: TicketPayloadPax[];
}

export interface RawTicketResponse {
  pnr: string;
  barcode_b64: string;
  payload: TicketPayload;
}

// ============================================================================
// Verification Types
// ============================================================================

export type VerifyResultCode =
  | "VALID"
  | "FORGED"
  | "DUPLICATE"
  | "EXPIRED"
  | "NOT_YET_VALID"
  | "WRONG_TRAIN"
  | "WRONG_DATE"
  | "INVALID_PNR";

export type IdentityCheckResult = "passed" | "failed" | "skipped";
export type ValidityWindow = "active" | "expired" | "not_yet_valid";
export type KeyUsed = "current" | "previous";

export interface VerifyRequest {
  barcode_b64: string;
  tte_id: string;
  train: string;
  aadhaar?: string;
  dob?: string;
}

export interface VerifyResult {
  result: VerifyResultCode;
  signature_valid: boolean;
  chart_match: boolean;
  is_duplicate: boolean;
  key_used: KeyUsed;
  validity_window: ValidityWindow;
  train_match: boolean;
  date_match: boolean;
  identity_check: IdentityCheckResult;
  payload?: TicketPayload;
}

// ============================================================================
// Audit Types
// ============================================================================

export type AuditStats = Partial<Record<VerifyResultCode, number>> & Record<string, number>;

export interface DuplicateEntry {
  uuid: string;
  count: number;
  first_seen: number;
  last_seen: number;
}

export interface AuditEvent {
  timestamp: number;
  tte_id: string;
  result: VerifyResultCode | string;
  train: string;
  uuid: string;
}

// ============================================================================
// Chart Types
// ============================================================================

export interface ChartPassenger {
  berth: string;
  name: string;
  id_hash: string;
  verified?: boolean;
}

export interface ChartResponse {
  train: string;
  date: string;
  coaches: Record<string, ChartPassenger[]>;
}

// ============================================================================
// Health Types
// ============================================================================

export type ServiceName = "prs_booking" | "cris_signing" | "audit_server" | "hht_terminal";

export interface HealthResponse {
  status: "ok";
  service: ServiceName;
}

// ============================================================================
// API Error Type
// ============================================================================

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, body: unknown, message?: string) {
    super(message || `API Error: ${status}`);
    this.status = status;
    this.body = body;
    this.name = "ApiError";
  }
}