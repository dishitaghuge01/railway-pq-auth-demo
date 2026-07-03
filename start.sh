#!/bin/bash
cd /app
./venv/bin/uvicorn services.prs_booking.main:app --host 0.0.0.0 --port 8000 &
./venv/bin/uvicorn services.cris_signer.main:app --host 0.0.0.0 --port 8001 &
./venv/bin/uvicorn services.audit_server.main:app --host 0.0.0.0 --port 8002 &
./venv/bin/uvicorn services.hht_service.main:app --host 0.0.0.0 --port 8003 &
nginx -g 'daemon off;' &
wait
