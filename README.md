# Precision Workz

Custom web design, security infrastructure, and full-stack development for businesses in Tucson, AZ. Zero templates — every site built from scratch.

**Live site:** https://precisionworkz.net

---

## Stack

| Layer | Tech |
|---|---|
| Frontend | Vanilla HTML/CSS/JS — single file (`index.html`) |
| Server | Node.js (`server.js`) — static file serving + API routes |
| Payments | Stripe Checkout (subscriptions + one-time) |
| Storage | Vercel KV (primary) with local JSON file fallback |
| Auth | Google reCAPTCHA v3, Google Sign-In |
| Fonts | Orbitron (headings), Inter (body), Phosphor Icons |
| Hosting | Vercel |

---

## Project Structure

```
precision-workz/
├── index.html        # Entire frontend (styles, markup, scripts)
├── server.js         # Express server — static + all /api routes
├── package.json
├── vercel.json       # Vercel deployment config
└── data/             # Local fallback storage (auto-created)
    ├── subscribers.json
    ├── devs.json
    └── reports.json
```

---

## Running Locally

```bash
npm install
node server.js
```

Runs at `http://localhost:3000`.

### Required Environment Variables

| Variable | Description |
|---|---|
| `STRIPE_SECRET_KEY` | Stripe secret key (test or live) |
| `STRIPE_BASIC_PRICE_ID` | Stripe Price ID for Basic plan |
| `STRIPE_PREMIUM_PRICE_ID` | Stripe Price ID for Premium plan |
| `STRIPE_DIAMOND_PRICE_ID` | Stripe Price ID for Diamond plan |
| `KV_REST_API_URL` | Vercel KV REST URL |
| `KV_REST_API_TOKEN` | Vercel KV REST token |
| `ADMIN_EMAILS` | Comma-separated admin email addresses |

Create a `.env` file at project root (never commit it):

```env
STRIPE_SECRET_KEY=sk_test_...
STRIPE_BASIC_PRICE_ID=price_...
STRIPE_PREMIUM_PRICE_ID=price_...
STRIPE_DIAMOND_PRICE_ID=price_...
KV_REST_API_URL=https://...
KV_REST_API_TOKEN=...
ADMIN_EMAILS=precisionworkz9@gmail.com
```

---

## Features

- **Security gate** — reCAPTCHA v3 verification on first visit, IP rate limiting, flagging system
- **Services** — Web Design, Security Infrastructure, Full-Stack Development
- **Pricing** — tabbed plans (Web Design / Security / Maintenance) with Stripe Checkout
- **Portfolio** — live example sites with featured Titanium package showcase
- **Admin panel** — subscriber management, dev list, IP monitor, report inbox
- **Report modal** — categorized user reports with email reply option
- **Interactive background** — canvas particle constellation that reacts to mouse movement and clicks
- **Scroll animations** — IntersectionObserver fade-in, animated stat counters
- **Dark tech aesthetic** — deep navy/black base, purple + cyan + pink accent palette

---

## Deployment

The project deploys automatically to Vercel on push to `main`.

```bash
git push origin main
```

Set all environment variables in the Vercel dashboard under **Project → Settings → Environment Variables**.

---

## Contact

**Email:** precisionworkz9@gmail.com  
**Location:** Tucson, AZ
