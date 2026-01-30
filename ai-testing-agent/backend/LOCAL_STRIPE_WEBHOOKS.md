# Local Stripe webhooks (payment stuck on "Payment pending")

When testing checkout locally, Stripe sends webhooks to the **URL configured in the Stripe Dashboard**, not to localhost. So your local backend never receives `checkout.session.completed`, and `test.tenant_billing` never gets `status = 'active'`. The UI keeps polling and shows "Payment pending."

## Fix: forward events to localhost with Stripe CLI

1. **Install Stripe CLI** (if needed): https://stripe.com/docs/stripe-cli  
   Then log in: `stripe login`

2. **Start forwarding** (in a separate terminal):
   ```bash
   stripe listen --forward-to localhost:5050/api/v1/billing/webhook
   ```

3. **Use the CLI’s webhook secret**  
   The CLI will print something like:
   ```text
   Ready! Your webhook signing secret is whsec_xxxxxxxxxxxx (^C to quit)
   ```  
   Copy that `whsec_...` value.

4. **Point the backend at that secret**  
   In `ai-testing-agent/backend/.env` set:
   ```env
   STRIPE_WEBHOOK_SECRET=whsec_xxxxxxxxxxxx
   ```
   (Replace with the value from step 3.)

5. **Restart the Flask backend** (port 5050) so it loads the new secret.

6. **Run through checkout again** (or resend the event from Stripe Dashboard → Developers → Webhooks → select event → "Resend").

Your backend (`DB_SCHEMA=test`) will receive the event, update `test.tenant_billing` to `status = 'active'`, and the UI polling will succeed.

## Optional: script

From the repo root you can run:
```bash
./ai-testing-agent/backend/scripts/stripe_listen_local.sh
```
Then update `.env` with the printed secret and restart the backend.
