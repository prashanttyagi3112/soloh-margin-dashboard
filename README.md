# Soloh Margin Dashboard (CFO method)

Password-protected margin dashboard for Soloh Partners. It uses the same candidates as the
**Margin Dashboard** (`prashanttyagi3112/soloh-ob-dashboard`) but recalculates every pay package
with the CFO's (Peter's) method: **13% burden** and a **10% minimum net margin**.

## How the protection works
- All candidate data is **encrypted** (AES-256-GCM, key from the password via PBKDF2-SHA256, 310,000 rounds)
  and stored inside `index.html`. Nothing readable is in the page source until the right password is entered.
- No workbook, JSON dump or plaintext data is ever committed (see `.gitignore`), so the repo can be public,
  which free GitHub Pages requires.
- To change the password, rebuild with a new `--password` and push.

## Calculation (Peter's sheet, 10/16/2026)
| Column | Formula |
|---|---|
| Weeks (G) | round((End − Start) / 7) |
| Gross revenue (P) | Bill rate × Guaranteed hrs/wk × Weeks |
| Net revenue (Q) | Gross revenue × (1 − MSP %) |
| Regular (S) | Weeks × min(G, 40) × W2 × (1 + 13%) |
| OT (T) | Weeks × max(G − 40, 0) × OT rate × (1 + 13%) |
| Stipend (U) | Weekly stipend × Weeks (no burden) |
| NBO (V) | NBO hrs × W2 × (1 + 13%) |
| Client fees (W) | Recruiting + onboarding cost ($0) + candidate one-time costs |
| Net profit (X) | Q − (S + T + U + V + W) |
| Net margin (Y) | X ÷ Q, compared with the 10% target |

There is no other rounding. Target status is judged on the margin shown to one decimal place.
A candidate missing a required input is shown as "Not calculated" and flagged. Nothing is estimated or zero-filled.

## Updating
Data always comes from the latest published Margin Dashboard:
```bash
git -C ../prashanttyagi3112/soloh-ob-dashboard pull
python3 build.py --source ../prashanttyagi3112/soloh-ob-dashboard/index.html \
  --source-password "$SOURCE_PASSWORD" --password "$DASHBOARD_PASSWORD"
git add index.html && git commit -m "Update data" && git push
```

| File | Purpose |
|---|---|
| `index.html` | Published dashboard (generated; contains only encrypted data) |
| `template.html` | Dashboard source: layout, charts, logic |
| `build.py` | Decrypts the Margin Dashboard data, applies the CFO method, encrypts, writes `index.html` |
| `vendor/chart.umd.min.js` | Chart.js 4.4.1, bundled |
