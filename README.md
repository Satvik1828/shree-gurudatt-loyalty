# Shree Gurudatt Washing Center — QR Loyalty & Rewards App

Production digital QR customer loyalty card, mobile OTP login, 10-wash stamp tracker, SMS & customer notifications, and Owner Dashboard.

## Features

- **Home & Counter QR Check-In**: Interactive vehicle service selector (`Cars`, `Bikes`, `Scooters`, `All Types`) and scannable Shop QR poster (`?scan=shree-gurudatt`) with PNG download.
- **Customer OTP Login**: 10-digit Indian mobile verification with 6-digit OTP (supports live Twilio SMS when configured in `.env`, or local gateway verification).
- **Digital Loyalty Card**: 1–10 stamp progress grid with scale-up + confetti animation on new stamps, personal member QR pass (`SGWC:CARD:<phone>`), wash history, and SMS/Notification inbox.
- **Owner Dashboard**: First-time PIN setup (`scrypt`-hashed on server), live KPIs, QR scanner (`jsqr`), walk-in customer registration, `+ Add Stamp (Paid Wash)`, `Redeem (Free Wash)`, manual SMS/Notification sender, reports & CSV export, and shop settings.

## Publish on GitHub Pages

This project automatically detects static hosting (like GitHub Pages) and runs seamlessly using browser `localStorage` when no Node.js server is present—or runs full-stack with Express (`server.ts`) on Node hosting.

1. Create a new repository on [github.com/new](https://github.com/new) (for example, `shree-gurudatt-loyalty`).
2. Push this project to your GitHub repository:
   ```bash
   git init
   git add .
   git commit -m "Initial Shree Gurudatt Loyalty website"
   git branch -M main
   git remote add origin https://github.com/<YOUR_USERNAME>/<YOUR_REPO>.git
   git push -u origin main
   ```
3. In your GitHub repository, open **Settings → Pages**.
4. Under **Build and deployment → Source**, select **GitHub Actions**.
5. The included `.github/workflows/deploy.yml` workflow will build and publish your live website at `https://<YOUR_USERNAME>.github.io/<YOUR_REPO>/`.

## Live SMS Configuration (Optional)

To send carrier SMS messages via Twilio on Node.js hosting, set these environment variables (see `.env.example`):

- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_FROM_NUMBER`
- `OWNER_PIN` (optional pre-configured 4–6 digit Owner PIN)

## Local Development

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.
