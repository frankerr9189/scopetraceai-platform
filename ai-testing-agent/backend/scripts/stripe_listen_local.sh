#!/usr/bin/env bash
# Forward Stripe webhooks to local Flask backend (port 5050).
# Use the webhook signing secret (whsec_...) printed below in backend .env as STRIPE_WEBHOOK_SECRET,
# then restart the backend.
set -e
echo "Forwarding Stripe events to http://localhost:5050/api/v1/billing/webhook"
echo "Copy the 'whsec_...' secret into ai-testing-agent/backend/.env as STRIPE_WEBHOOK_SECRET, then restart the backend."
echo ""
stripe listen --forward-to localhost:5050/api/v1/billing/webhook
