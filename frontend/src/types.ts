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
  barcode_path: string;
}

export interface TicketPayloadPax {
  b?: string;
  id?: string | null;
}

export interface TicketPayload {
  v: number;
  type: TicketType;
  uuid: string;
  train: string;
  from: string;
  to: string;
  class: string;
  date: string;
  vf: number;
  vu: number;
  iat: number;
  pax: TicketPayloadPax[];
}

export interface RawTicket {
  pnr: string;
  barcode_b64: string;
  payload: TicketPayload;
}

export type VerifyResultCode =
  | "VALID"
  | "FORGED"
  | "DUPLICATE"
  | "EXPIRED"
  | "NOT_YET_VALID"
  | "WRONG_TRAIN"
  | "WRONG_DATE"
  | "INVALID_PNR";

export interface VerifyRequest {
  pnr: string;
  tte_id: string;
  train: string;
  barcode_b64: string;
  aadhaar?: string;
  dob?: string;
}

export interface VerifyResult {
  result: VerifyResultCode;
  signature_valid: boolean;
  chart_match: boolean;
  is_duplicate: boolean;
  key_used: "current" | "previous" | string;
  validity_window: "active" | "expired" | "not_yet_valid" | string;
  train_match: boolean;
  date_match: boolean;
  identity_check?: "passed" | "failed" | "skipped" | string;
  payload?: TicketPayload;
}

export type AuditStats = Partial<Record<VerifyResultCode, number>> & Record<string, number>;

export interface DuplicateEntry {
  uuid: string;
  times_scanned: number;
  first_seen: string;
}

export interface AuditEvent {
  timestamp: string;
  tte_id: string;
  result: VerifyResultCode | string;
  train: string;
  uuid?: string;
}

export interface ChartPassenger {
  coach: string;
  berth: string;
  name: string;
  id_hash: string;
  verified?: boolean;
}

export interface ChartResponse {
  train: string;
  date: string;
  passengers: ChartPassenger[];
}