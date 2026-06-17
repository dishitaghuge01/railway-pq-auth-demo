import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Navbar, type PageKey } from "../components/navbar";
import { ToastProvider } from "../components/toast";
import { BookPage } from "../components/book-page";
import { VerifyPage } from "../components/verify-page";
import { AuditPage } from "../components/audit-page";
import { ChartPage } from "../components/chart-page";
import { AttacksPage } from "../components/attacks-page";
import type { BookResponse, RawTicketResponse } from "../types";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "PQ Rail Auth — Post-Quantum Ticket Verification" },
      { name: "description", content: "Issue, verify, and audit Indian Railway tickets signed with Falcon-padded-512 post-quantum signatures." },
      { property: "og:title", content: "PQ Rail Auth" },
      { property: "og:description", content: "Post-quantum ticket authentication for Indian Railways." },
    ],
  }),
  component: Index,
});

function Index() {
  const [page, setPage] = useState<PageKey>("book");
  const [ticket, setTicket] = useState<{ book: BookResponse; raw: RawTicketResponse } | null>(null);

  return (
    <ToastProvider>
      <div style={{ minHeight: "100vh" }}>
        <Navbar active={page} onChange={setPage} />
        <main style={{ maxWidth: 1200, margin: "0 auto", padding: "28px 24px 80px" }}>
          {page === "book" && <BookPage ticket={ticket} setTicket={setTicket} />}
          {page === "verify" && <VerifyPage />}
          {page === "audit" && <AuditPage />}
          {page === "chart" && <ChartPage />}
          {page === "attacks" && <AttacksPage />}
          {page === "attacks" && <AttacksPage />}
        </main>
      </div>
    </ToastProvider>
  );
}
