# Oikumene — Your Inhabited World

Track, discover, and remember every place.

## Stack
Express + nedb-promises (backend), static frontend served by Express. Google Auth for SSO.

## Run
- Dev/Prod: `npm start` or `npm run dev`
- Test: `npm test`

## Key Conventions
- Same patterns as Fortuna (Express + NeDB + Tailwind)
- IDs are strings (nedb `_id`)
- Security: Helmet + CORS + rate limiting. Google SSO needs CSP whitelist.
- Deployed on Render
