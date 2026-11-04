#!/usr/bin/env python3
"""
Build the Soloh Margin Dashboard (CFO method) from the live Margin Dashboard.

Source of candidate data: the published Margin Dashboard
(prashanttyagi3112/soloh-ob-dashboard, index.html). Its encrypted dataset is
decrypted with that site's password, every candidate is recalculated with the
CFO (Peter) method below, and the result is encrypted with THIS site's password.

Usage:
    python3 build.py --source ../soloh-ob-dashboard/index.html \
        --source-password "MARGIN-DASHBOARD-PASSWORD" --password "THIS-SITE-PASSWORD"
    (or set SOURCE_PASSWORD and DASHBOARD_PASSWORD env vars)

CFO method (OB_Candidates_Pay_Packages_Soloh workbook as modified by Peter, 10/16/2026):
    Burden (load)  = 13%  (named cell "Burden" = 'Client Fees'!B10)
    Gross revenue  = Bill rate x Guaranteed hrs/wk x Weeks                 (col P)
    Net revenue    = Gross revenue x (1 - MSP %)                           (col Q)
    Regular        = Weeks x min(G,40) x W2 x (1 + Burden)                 (col S)
    OT             = Weeks x max(G-40,0) x OT rate x (1 + Burden)          (col T)
    Stipend        = Weekly stipend x Weeks                                (col U)
    NBO            = NBO hrs x W2 x (1 + Burden)                           (col V)
    Client fees    = Recruiting + onboarding cost ('Client Fees'!B11, $0)  (col W)
    Net profit     = Net revenue - (Regular + OT + Stipend + NBO + Client fees)   (col X)
    Net profit %   = Net profit / Net revenue                              (col Y, "NP Check")
    Target         = 10% minimum net profit % (Peter's email, 10/16/2026)
    Weeks          = ROUND((End - Start) / 7, 0)                           (col G)
No other rounding is applied.

One-time costs: the Margin Dashboard carries a per-candidate "One-time costs" column
(e.g. travel reimbursement). Peter's sheet has no such column; it is deducted together
is NOT deducted (Prashant's decision, 10/16/2026), matching Peter's sheet. It is shown for reference only.
"""
import argparse, base64, datetime as dt, json, os, re, secrets, sys
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
ET = ZoneInfo("America/New_York")
PBKDF2_ITER = 310000

BURDEN = 0.13
TARGET = 0.10
ONBOARDING_COST = 0.0      # Peter's 'Client Fees'!B11
ONE_TIME_IN_PROFIT = False   # Prashant 10/16/2026: leave one-time costs out (Tiana McCullom $700)
METHOD_VERSION = "CFO method v1 (Peter, 10/16/2026)"


def b64d(s): return base64.b64decode(s)
def b64e(b): return base64.b64encode(b).decode()

def kdf(pw, salt, it):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it).derive(pw.encode())

def read_source(path, pw):
    html = open(path, encoding="utf-8").read()
    m = re.search(r'const ENC = (\{"v": 1.*?\});', html, re.S)
    if not m: sys.exit("Encrypted data block not found in source dashboard.")
    blob = json.loads(m.group(1))
    try:
        pt = AESGCM(kdf(pw, b64d(blob["salt"]), blob["iter"])).decrypt(b64d(blob["iv"]), b64d(blob["ct"]), None)
    except Exception:
        sys.exit("Could not decrypt the source dashboard: wrong source password?")
    return json.loads(pt)

def encrypt(payload: bytes, pw: str):
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    ct = AESGCM(kdf(pw, salt, PBKDF2_ITER)).encrypt(iv, payload, None)
    return {"v": 1, "kdf": "PBKDF2-SHA256", "iter": PBKDF2_ITER, "salt": b64e(salt), "iv": b64e(iv), "ct": b64e(ct)}


def target_status(m):
    if m is None: return None
    r = round(m * 100, 1)             # judged on the % shown (1 decimal)
    return "above" if r > TARGET * 100 else "at" if r == TARGET * 100 else "below"

def cfo(r, dq):
    """Recalculate one record with the CFO method. Never invents missing inputs."""
    who, sheet, row = r.get("candidate"), r.get("sheet"), r.get("row")
    # Keep the original dashboard's numbers for the side-by-side comparison
    r["orig"] = {"netProfit": r.get("netProfit"), "marginPctGross": r.get("marginPct"),
                 "marginPctNet": (r["netProfit"] / r["netRev"]) if r.get("netProfit") is not None and r.get("netRev") else None}
    G, W2, OT, stip = r.get("guarHrs"), r.get("w2"), r.get("ot"), r.get("stipend")
    bill, msp, nbo, wk = r.get("bill"), r.get("msp"), r.get("nbo"), r.get("weeks")
    need = {"Bill rate": bill, "Guaranteed hrs/wk": G, "Weeks (start/end dates)": wk, "W2 rate": W2,
            "Weekly stipend": stip, "MSP fee %": msp, "NBO hours": nbo}
    if G is not None and G > 40: need["OT rate"] = OT
    missing = [k for k, v in need.items() if v is None]
    c = {"burden": BURDEN, "target": TARGET, "missing": missing}
    if missing:
        dq.append({"sev": "error", "sheet": sheet, "row": row, "who": who,
                   "msg": "Not calculated: missing " + ", ".join(missing) + ". Margin is left blank until this is supplied."})
        r.update({"netProfit": None, "marginPct": None, "weeklyProfit": None, "cfo": c, "targetStatus": None})
        return
    if G <= 0 or wk <= 0 or bill <= 0:
        dq.append({"sev": "error", "sheet": sheet, "row": row, "who": who,
                   "msg": "Not calculated: guaranteed hours, weeks and bill rate must be above zero."})
        r.update({"netProfit": None, "marginPct": None, "weeklyProfit": None, "cfo": c, "targetStatus": None})
        return
    gross = bill * G * wk
    net = gross * (1 - msp)
    reg = wk * min(G, 40) * W2 * (1 + BURDEN)
    ot = wk * (max(G - 40, 0) * (OT or 0)) * (1 + BURDEN)
    # Stipend prorated to hours worked (stipend x hours / 40) where Prashant said so, e.g. Sara Khalil
    stp = stip * (G * wk) / 40 if r.get("stipendProrated") else stip * wk
    nbo_c = nbo * (W2 * (1 + BURDEN))
    onetime = (r.get("oneTime") or 0) if (ONE_TIME_IN_PROFIT or r.get("deductOneTime")) else 0
    bonus = r.get("bonus") or 0          # candidate bonus Prashant chose to deduct (e.g. Graydon 2nd ext., $400)
    fees = ONBOARDING_COST + onetime + bonus
    profit = net - (reg + ot + stp + nbo_c + fees)
    margin = profit / net if net else None
    # Peter's column Z (kept on his sheet for reference): NBO at bill rate net of MSP
    z = net - wk * (min(G, 40) * W2 + max(G - 40, 0) * (OT or 0)) * (1 + BURDEN) - stp - nbo * bill * (1 - msp) - ONBOARDING_COST - onetime - bonus
    c.update({"gross": gross, "net": net, "mspFee": gross - net, "regular": reg, "ot": ot, "stipend": stp,
              "nbo": nbo_c, "onboarding": ONBOARDING_COST, "oneTime": onetime, "bonus": bonus, "clientFees": fees,
              "targetProfit": TARGET * net, "gapToTarget": profit - TARGET * net,
              "variance": (margin - TARGET) if margin is not None else None,
              "colZ": z, "colZMargin": z / net if net else None})
    r.update({"grossRev": gross, "netRev": net, "netProfit": profit, "marginPct": margin,
              "weeklyProfit": profit / wk, "cfo": c, "targetStatus": target_status(margin)})


# ---- Records that exist only on this dashboard (Prashant, 11/2/2026) ----
# Completed assignments and extensions from the Timedot invoice SLHINV01, confirmed one by one.
# Placement / invoice fees are NOT deducted (Prashant's instruction).
EXTRA_FEES = {
    "NYC H+H / RightSourcing": {"msp": 0.07, "nbo": 16.0, "source": "Provided by Prashant 11/2/2026"},
    "NYC H+H / RightSourcing (Allied)": {"msp": 0.07, "nbo": 8.0, "source": "Provided by Prashant 11/2/2026: 8 NBO hours on the first contract for all Allied roles"},
    "SGHS - Brunswick (BudE)": {"msp": 0.065, "nbo": 0.0, "source": "Provided by Prashant 11/4/2026"},
}
EXTRA_RECORDS = [
    {"row": 1001, "sheet": "Completed Assignments", "status": "Completed", "kind": "Contract",
     "candidate": "Graydon Massiah", "client": "NYC H+H / RightSourcing",
     "facilityUnit": "Kings County Hospital, Brooklyn NY, Radiology", "facility": "Kings County Hospital",
     "unit": "Radiologic Technologist - Radiographer", "req": "Eng 36330117",
     "start": "2025-09-08", "end": "2025-12-13", "shift": "Days", "hrsShift": None, "guarHrs": 40.0,
     "w2": 70.50, "ot": 70.00, "stipend": 0.0, "bill": 98.00, "billAfter": None, "msp": 0.07, "nbo": 8.0,
     "team": "TTT", "recruiter": "Sky (Suryakant)", "oneTime": 0, "reason": None, "extra": {},
     "note": "No-stipend contract. Pay from the signed assignment confirmation; dates confirmed by Prashant 11/2/2026."},
    {"row": 1002, "sheet": "Extensions", "status": "Completed", "kind": "Extension",
     "candidate": "Graydon Massiah", "client": "NYC H+H / RightSourcing",
     "facilityUnit": "Kings County Hospital, Brooklyn NY, Radiology", "facility": "Kings County Hospital",
     "unit": "Radiologic Technologist - Radiographer", "req": "Eng 36330117 · 1st extension",
     "start": "2025-12-14", "end": "2026-02-07", "shift": "Days", "hrsShift": None, "guarHrs": 40.0,
     "w2": 27.57, "ot": 75.00, "stipend": 1897.0, "bill": 98.00, "billAfter": None, "msp": 0.07, "nbo": 0.0,
     "team": "TTT", "recruiter": "Sky (Suryakant)", "oneTime": 0, "reason": None, "extra": {},
     "note": "1st extension. Pay from the signed extension confirmation; NBO 0 per Prashant 11/2/2026. Bill rate $98 throughout per Prashant."},
    {"row": 1003, "sheet": "Extensions", "status": "Completed", "kind": "Extension",
     "candidate": "Graydon Massiah", "client": "NYC H+H / RightSourcing",
     "facilityUnit": "Kings County Hospital, Brooklyn NY, Radiology", "facility": "Kings County Hospital",
     "unit": "Radiologic Technologist - Radiographer", "req": "Eng 36330117 · 2nd extension",
     "start": "2026-02-23", "end": "2026-04-04", "shift": "Days", "hrsShift": None, "guarHrs": 40.0,
     "w2": 70.00, "ot": 105.00, "stipend": 0.0, "bill": 98.00, "billAfter": None, "msp": 0.07, "nbo": 0.0,
     "team": "TTT", "recruiter": "Sky (Suryakant)", "oneTime": 0, "bonus": 400.0, "deductOneTime": True, "reason": None, "extra": {},
     "note": "2nd extension after a two-week break. All-W2, no stipend. $400 bonus on first paycheck (Priya, 2/3/2026), deducted from profit per Prashant 11/2/2026. Dates and pay per Prashant 11/2/2026. Bill rate $98 throughout per Prashant."},
    {"row": 1004, "sheet": "Extensions", "status": "Completed", "kind": "Extension",
     "candidate": "Graydon Massiah", "client": "NYC H+H / RightSourcing",
     "facilityUnit": "Kings County Hospital, Brooklyn NY, Radiology Diagnostic", "facility": "Kings County Hospital",
     "unit": "Radiologic Technologist - Radiographer", "req": "Eng 36330117 · 3rd extension",
     "start": "2026-04-05", "end": "2026-05-30", "shift": "Days", "hrsShift": 8.0, "guarHrs": 40.0,
     "w2": 71.00, "ot": 106.50, "stipend": 0.0, "bill": 98.00, "billAfter": None, "msp": 0.07, "nbo": 0.0,
     "team": "TTT", "recruiter": "Sky (Suryakant)", "oneTime": 0, "bonus": 500.0, "reason": None, "extra": {},
     "note": "Local assignment confirmation: $71/hr all W2, OT $106.50, $500 one-time bonus with first extension paycheck (deducted). 5x8 days. Bill rate $98 throughout per Prashant."},
    {"row": 1005, "sheet": "Extensions", "status": "Completed", "kind": "Extension",
     "candidate": "Graydon Massiah", "client": "NYC H+H / RightSourcing",
     "facilityUnit": "Kings County Hospital, Brooklyn NY, Radiology Diagnostic", "facility": "Kings County Hospital",
     "unit": "Radiologic Technologist - Radiographer", "req": "Eng 36330117 · 4th extension",
     "start": "2026-07-25", "end": "2026-09-19", "shift": "Days", "hrsShift": 8.0, "guarHrs": 40.0,
     "w2": 71.00, "ot": 106.50, "stipend": 0.0, "bill": 98.00, "billAfter": None, "msp": 0.07, "nbo": 0.0,
     "team": "TTT", "recruiter": "Sky (Suryakant)", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Local assignment confirmation: $71/hr all W2, OT $106.50. 5x8 days. Bill rate $98 throughout per Prashant."},
    {"row": 1006, "sheet": "Extensions", "status": "Started", "kind": "Extension",
     "candidate": "Graydon Massiah", "client": "NYC H+H / RightSourcing",
     "facilityUnit": "Kings County Hospital, Brooklyn NY, Radiology Diagnostic", "facility": "Kings County Hospital",
     "unit": "Radiologic Technologist - Radiographer", "req": "Eng 36330117 · 5th extension",
     "start": "2026-09-27", "end": "2026-11-14", "shift": "Days", "hrsShift": 8.0, "guarHrs": 40.0,
     "w2": 73.75, "ot": 90.00, "stipend": 0.0, "bill": 98.00, "billAfter": None, "msp": 0.07, "nbo": 0.0,
     "team": "TTT", "recruiter": "Sky (Suryakant)", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Local assignment confirmation signed 10/1/2026 (version B): $2,950/wk all W2 ($73.75 x 40), OT $90. Running; shows in Started until 11/14/2026, then moves to Completed Assignments/Extensions automatically. Off 5/31-7/24 and 9/20-9/26/2026."},
    {"row": 1007, "sheet": "Completed Assignments", "status": "Completed", "kind": "Contract",
     "candidate": "Jaime Goldberg", "client": "Atlantic Health (Allied and Nursing)",
     "facilityUnit": "Morristown Medical Center, Morristown NJ, Radiology", "facility": "Morristown Medical Center",
     "unit": "X-Ray Technician", "req": "Eng 36351713",
     "start": "2025-09-15", "end": "2025-12-13", "shift": "Nights", "hrsShift": 12.5, "guarHrs": 37.5,
     "w2": 24.00, "ot": 55.00, "stipend": 1561.0, "bill": 88.00, "billAfter": None, "msp": 0.05, "nbo": 0.0,
     "team": "TTT", "recruiter": "Shivani Bhatt", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Signed travel assignment confirmation: $24 W2 + $1,561/wk stipend ($2,521/wk at 40 hrs), OT $55, 6p-7a. Billed and paid on 37.5 hrs/wk per Prashant 11/2/2026. 0 NBO for Allied."},
    {"row": 1008, "sheet": "Extensions", "status": "Completed", "kind": "Extension",
     "candidate": "Jaime Goldberg", "client": "Atlantic Health (Allied and Nursing)",
     "facilityUnit": "Morristown Medical Center, Morristown NJ, Radiology", "facility": "Morristown Medical Center",
     "unit": "X-Ray Technician", "req": "Eng 36351713 · 1st extension",
     "start": "2025-12-14", "end": "2026-03-15", "shift": "Nights", "hrsShift": 12.5, "guarHrs": 37.5,
     "w2": 24.00, "ot": 55.00, "stipend": 1561.0, "bill": 88.00, "billAfter": None, "msp": 0.05, "nbo": 0.0,
     "team": "TTT", "recruiter": "Shivani Bhatt", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Signed extension assignment form: same pay as contract. Bill rate $88 unchanged (Magnit extension offer). Billed and paid on 37.5 hrs/wk per Prashant 11/2/2026."},
    {"row": 1009, "sheet": "Completed Assignments", "status": "Completed", "kind": "Contract",
     "candidate": "Nimatoulaye Barry", "client": "NYC H+H / RightSourcing",
     "facilityUnit": "Elmhurst Hospital Center, Elmhurst NY, Radiology (MRI)", "facility": "Elmhurst Hospital Center",
     "unit": "MRI Technologist", "req": "Eng 36559602",
     "start": "2025-11-19", "end": "2026-02-21", "shift": "Days", "hrsShift": 7.0, "guarHrs": round(516.14 / 13, 4),
     "w2": 17.80, "ot": 50.00, "stipend": 1897.0, "bill": 98.00, "billAfter": None, "msp": 0.07, "nbo": 0.0,
     "team": "TTT", "recruiter": "Ravi/Guddu", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Signed travel assignment confirmation: $17.80 W2 + $1,897/wk stipend ($2,520/wk at 35 hrs), OT $50. Revenue and pay use the actual 516.14 hrs billed and paid in Magnit (avg 39.70 hrs/wk over 13 wks), adjustment line ignored, per Prashant 11/2/2026."},
    {"row": 1010, "sheet": "Cancelled Offers", "status": "Cancelled", "kind": "Contract",
     "candidate": "Levene Cameron", "client": "Wellstar",
     "facilityUnit": "Wellstar Kennestone Regional Medical Center, Marietta GA, Acute Care (via Stability / BudE)", "facility": "Wellstar Kennestone Regional Medical Center",
     "unit": "RN - Acute Care", "req": "BudE Job 14410 · Placement 5377",
     "start": "2025-11-24", "end": "2026-02-21", "shift": "Nights", "hrsShift": 12.0, "guarHrs": 36.0,
     "w2": 17.00, "ot": 60.00, "stipend": 1246.0, "bill": 70.00, "billAfter": None, "msp": 0.065, "nbo": 24.0,
     "team": "TTT", "recruiter": "Rashika Varshney", "oneTime": 0, "bonus": 0.0, "extra": {},
     "reason": "Started 12/1/2025 but did not complete 30 days. Contract terminated by client 1/2/2026. Profit shown is the estimate for the planned 13-week contract.",
     "note": "Signed travel assignment confirmation: $17 W2 + $1,246/wk stipend ($1,858/wk at 36 hrs), OT $60. Bill rate $70 (Stability/BudE). Planned 11/24/2025-2/21/2026; RTO 2/5/2026."},
    {"row": 1011, "sheet": "Completed Assignments", "status": "Completed", "kind": "Contract",
     "candidate": "Sara Khalil", "client": "NYC H+H / RightSourcing",
     "facilityUnit": "NYC+ Community Care (home visits), New York NY", "facility": "NYC+ Community Care",
     "unit": "Registered Dietitian", "req": "Eng 36560035",
     "start": "2025-11-24", "end": "2026-02-21", "shift": "Days", "hrsShift": 8.0, "guarHrs": round(375.5 / 13, 4),
     "w2": 16.50, "ot": 60.00, "stipend": 2017.0, "stipendProrated": True, "bill": 85.00, "billAfter": None, "msp": 0.07, "nbo": 16.0,
     "team": "TTT", "recruiter": "Prashant Tyagi", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Updated travel assignment confirmation (11/4/2025): $16.50 W2 + $2,017/wk stipend ($2,677/wk at 40 hrs), OT $60. Form dates 11/17/2025-2/14/2026; first Magnit timecard w/e 11/29/2025, so start taken as 11/24/2025. Hours = 375.5 invoiced in Magnit, adjustments ignored; 16 NBO hours one time on this contract only, per Prashant. Bill rate $85 (Magnit $79.05/hr net of 7% MSP)."},
    {"row": 1012, "sheet": "Extensions", "status": "Completed", "kind": "Extension",
     "candidate": "Sara Khalil", "client": "NYC H+H / RightSourcing",
     "facilityUnit": "NYC+ Community Care (home visits), New York NY", "facility": "NYC+ Community Care",
     "unit": "Registered Dietitian", "req": "Eng 36560035 · 1st extension",
     "start": "2026-02-22", "end": "2026-04-18", "shift": "Days", "hrsShift": 8.0, "guarHrs": round(279.5 / 8, 4),
     "w2": 17.00, "ot": 60.00, "stipend": 1990.0, "stipendProrated": True, "bill": 85.00, "billAfter": None, "msp": 0.07, "nbo": 0.0,
     "team": "TTT", "recruiter": "Prashant Tyagi", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Signed extension form: $17 W2 + $1,990/wk stipend ($2,670/wk at 40 hrs), OT $60. Hours = 279.5 invoiced in Magnit. Bill rate $85."},
    {"row": 1014, "sheet": "Extensions", "status": "Completed", "kind": "Extension",
     "candidate": "Sara Khalil", "client": "NYC H+H / RightSourcing",
     "facilityUnit": "NYC+ Community Care (home visits), New York NY", "facility": "NYC+ Community Care",
     "unit": "Registered Dietitian", "req": "Eng 36560035 · 2nd extension",
     "start": "2026-04-19", "end": "2026-06-13", "shift": "Days", "hrsShift": 8.0, "guarHrs": round(199.0 / 8, 4),
     "w2": 17.00, "ot": 60.00, "stipend": 1990.0, "stipendProrated": True, "bill": 85.00, "billAfter": None, "msp": 0.07, "nbo": 0.0,
     "team": "TTT", "recruiter": "Prashant Tyagi", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Hours = 199 invoiced in Magnit (0 hrs w/e 5/2 and 5/9). Pay ASSUMED same as 1st and 3rd extensions ($17 W2 + $1,990/wk stipend) until the signed 2nd extension form is provided."},
    {"row": 1013, "sheet": "Extensions", "status": "Completed", "kind": "Extension",
     "candidate": "Sara Khalil", "client": "NYC H+H / RightSourcing",
     "facilityUnit": "NYC+ Community Care (home visits), New York NY", "facility": "NYC+ Community Care",
     "unit": "Registered Dietitian", "req": "Eng 36560035 · 3rd extension",
     "start": "2026-06-14", "end": "2026-08-08", "shift": "Days", "hrsShift": 8.0, "guarHrs": round(282.0 / 8, 4),
     "w2": 17.00, "ot": 60.00, "stipend": 1990.0, "stipendProrated": True, "bill": 85.00, "billAfter": None, "msp": 0.07, "nbo": 0.0,
     "team": "TTT", "recruiter": "Prashant Tyagi", "oneTime": 0, "bonus": 500.0, "reason": None, "extra": {},
     "note": "Signed extension form: $17 W2 + $1,990/wk stipend, OT $60, $500 extension bonus with first paycheck (deducted). Hours = 282 invoiced in Magnit. Bill rate $85."},
    {"row": 1015, "sheet": "Onboarding Candidates", "status": "Onboarding", "kind": "Contract",
     "candidate": "Benjamin Niyi Israel", "client": "Baptist Winter Reduced MSP",
     "facilityUnit": "Baptist Health Lexington, Lexington KY, Progressive Care Unit", "facility": "Baptist Health Lexington",
     "unit": "RN - Progressive Care Unit", "req": "Req 37805476",
     "start": "2026-11-30", "end": "2027-02-27", "shift": "Nights", "hrsShift": 12.0, "guarHrs": 36.0,
     "w2": 30.77, "ot": 85.00, "stipend": 1435.0, "bill": 93.00, "billAfter": None, "msp": 0.065, "nbo": 12.0,
     "team": "HST", "recruiter": "Momin Ginai", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Baptist MSP official offer 11/3/2026 (bill $93, 3x12 nights, no RTO). Pay per signed OL as summarized by Anand 11/3: $30.77 W2 x 36 + $1,435/wk stipend = $2,542.72/wk, OT $85. MSP 6.5% (net new offer 11/3/2026). Added per Prashant 11/4/2026."},
    {"row": 1016, "sheet": "Completed Assignments", "status": "Completed", "kind": "Contract",
     "candidate": "Pier Smith", "client": "Wellstar",
     "facilityUnit": "Wellstar Douglas Hospital, Douglasville GA, GI/Pulmonary Lab (via BUDe)", "facility": "Wellstar Douglas Hospital",
     "unit": "RN - GI/Pulmonary Lab", "req": "BUDe Job 43367",
     "start": "2026-07-20", "end": "2026-10-17", "shift": "Days", "hrsShift": 8.0, "guarHrs": 40.0,
     "w2": 25.25, "ot": 55.00, "stipend": 1246.0, "bill": 70.00, "billAfter": None, "msp": 0.06, "nbo": 0.0,
     "team": "TTT", "recruiter": "Amit Negi", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Signed travel assignment confirmation: $25.25 W2 + up to $1,246/wk stipend ($2,256/wk at 40 hrs), OT $55 (form's '$890 taxable base' is a typo). 40 hrs guaranteed per Prashant. Bill $70, MSP 6%, no NBO per Prashant 11/4/2026. RTO 8/10, 9/21, 9/22."},
    {"row": 1017, "sheet": "Cancelled Offers", "status": "Cancelled", "kind": "Contract",
     "candidate": "Jaide Fields", "client": "Wellstar",
     "facilityUnit": "Wellstar Kennestone Regional Medical Center, Marietta GA, Acute Care Float (via BUDe)", "facility": "Wellstar Kennestone Regional Medical Center",
     "unit": "RN - Acute Care Float", "req": "BUDe Job 43430",
     "start": "2026-06-22", "end": "2026-09-19", "shift": "Nights", "hrsShift": 12.0, "guarHrs": 36.0,
     "w2": 18.00, "ot": 50.00, "stipend": 1120.0, "bill": 70.00, "billAfter": None, "msp": 0.065, "nbo": 24.0,
     "team": "TTT", "recruiter": "Bhanu Singh", "oneTime": 0, "bonus": 0.0, "extra": {},
     "reason": "Offer accepted 6/1/2026 (signed confirmation, revised 6/4/2026) but the candidate did not start. Profit shown is the estimate for the planned 13-week contract.",
     "note": "BUDe offer 6/1/2026: RN Acute Care Float, nights 3x12 (36 hrs), 6/22-9/19/2026, bill $70. Signed confirmation: $18 W2 + up to $1,120/wk stipend ($1,768/wk at 36 hrs), OT $50. Did not start per Prashant 11/4/2026."},
    {"row": 1018, "sheet": "Completed Assignments", "status": "Completed", "kind": "Contract",
     "candidate": "Debra Poweless", "client": "MVHS (via HWL)",
     "facilityUnit": "MVHS Wynn Hospital, Utica NY, Med Surg 7th Floor", "facility": "MVHS Wynn Hospital",
     "unit": "RN - Medical / Surgical", "req": "HWL MVHS Inc.-AN-1590",
     "start": "2026-06-22", "end": "2026-09-12", "shift": "Nights", "hrsShift": 12.0, "guarHrs": 36.0,
     "w2": 33.50, "ot": 85.00, "stipend": 1246.0, "bill": 87.54, "billAfter": None, "msp": 0.0, "nbo": 0.0,
     "team": "TTT", "recruiter": "Rashika Varshney", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Signed assignment confirmation: $33.50 W2 + up to $1,246/wk stipend ($2,452/wk at 36 hrs), OT $85. Form end 9/19/2026; Extension 1 began 9/13, so contract taken as ending 9/12. Bill $87.54 per Prashant 11/4/2026. HWL clients: 0% MSP, 0 NBO per Prashant 11/4/2026."},
    {"row": 1019, "sheet": "Extensions", "status": "Started", "kind": "Extension",
     "candidate": "Debra Poweless", "client": "MVHS (via HWL)",
     "facilityUnit": "MVHS Wynn Hospital, Utica NY, Med Surg 7th Floor", "facility": "MVHS Wynn Hospital",
     "unit": "RN - Medical / Surgical", "req": "HWL MVHS Inc.-AN-1590-EXT1 · 1st extension",
     "start": "2026-09-13", "end": "2026-12-12", "shift": "Nights", "hrsShift": 12.0, "guarHrs": 36.0,
     "w2": 35.50, "ot": 85.00, "stipend": 1246.0, "bill": 87.54, "billAfter": None, "msp": 0.0, "nbo": 0.0,
     "team": "TTT", "recruiter": "Rashika Varshney", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Signed extension confirmation: $35.50 W2 + up to $1,246/wk stipend ($2,524/wk at 36 hrs), OT $85. Bill $87.54 per Prashant 11/4/2026. Currently active per Prashant 11/4/2026; only this extension was signed."},
    {"row": 1020, "sheet": "Completed Assignments", "status": "Completed", "kind": "Contract",
     "candidate": "Andrzej D Kurtyko", "client": "MVHS (via HWL)",
     "facilityUnit": "MVHS Wynn Hospital, Utica NY, Med Surg 7th Floor", "facility": "MVHS Wynn Hospital",
     "unit": "RN - Medical / Surgical", "req": "HWL MVHS Inc.-AN-1578",
     "start": "2026-06-01", "end": "2026-08-29", "shift": "Days", "hrsShift": 12.0, "guarHrs": 36.0,
     "w2": 37.62, "ot": 70.00, "stipend": 1246.0, "bill": 87.89, "billAfter": None, "msp": 0.0, "nbo": 0.0,
     "team": "TTT", "recruiter": "Vibhanshu Tyagi", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Signed assignment confirmation: $37.62 W2 + up to $1,246/wk stipend ($2,600/wk at 36 hrs), OT $70. Bill $87.89 per HWL confirmation. Start 6/1/2026 per Prashant 11/4/2026."},
    {"row": 1021, "sheet": "Extensions", "status": "Started", "kind": "Extension",
     "candidate": "Andrzej D Kurtyko", "client": "MVHS (via HWL)",
     "facilityUnit": "MVHS Wynn Hospital, Utica NY, Intermediate Care (IMCU)", "facility": "MVHS Wynn Hospital",
     "unit": "RN - Intermediate Care", "req": "HWL MVHS Inc.-AN-1757 · 1st extension",
     "start": "2026-09-07", "end": "2026-12-07", "shift": "Days", "hrsShift": 12.0, "guarHrs": 48.0,
     "w2": 45.47, "ot": 70.00, "stipend": 1246.0, "bill": 90.69, "billAfter": None, "msp": 0.0, "nbo": 0.0,
     "team": "TTT", "recruiter": "Vibhanshu Tyagi", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Signed IMCU extension: $45.47 W2 (40 hrs) + 8 OT hrs at $70 + up to $1,246/wk stipend ($3,625/wk at 48 hrs). Bill $90.69 per HWL (OT bill only after 48 hrs). End 12/7/2026 per HWL, chosen by Prashant 11/4/2026 (signed form says 1/7/2027)."},
    {"row": 1022, "sheet": "Completed Assignments", "status": "Completed", "kind": "Contract",
     "candidate": "Jeff Pradere", "client": "MVHS (via HWL)",
     "facilityUnit": "MVHS Wynn Hospital, Utica NY, Med Surg 7th Floor", "facility": "MVHS Wynn Hospital",
     "unit": "RN - Medical / Surgical", "req": "HWL MVHS Inc.-AN-1449",
     "start": "2026-03-02", "end": "2026-06-06", "shift": "Nights", "hrsShift": 12.0, "guarHrs": 36.0,
     "w2": 35.00, "ot": 52.50, "stipend": 1246.0, "bill": 87.89, "billAfter": None, "msp": 0.0, "nbo": 0.0,
     "team": "TTT", "recruiter": "Bhawna Kumari", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Signed assignment confirmation: $35 W2 + $1,246/wk stipend ($2,506/wk at 36 hrs), OT $52.50 after 48 hrs. Bill $87.89 per HWL work order and Prashant 11/4/2026. Dates 3/2-6/6/2026 per signed form and HWL work order (HWL agency note mentions 2/16)."},
    {"row": 1023, "sheet": "Extensions", "status": "Completed", "kind": "Extension",
     "candidate": "Jeff Pradere", "client": "MVHS (via HWL)",
     "facilityUnit": "MVHS Wynn Hospital, Utica NY, Med Surg 7th Floor", "facility": "MVHS Wynn Hospital",
     "unit": "RN - Medical / Surgical", "req": "HWL MVHS Inc.-AN-1449-EXT2 · 1st extension",
     "start": "2026-06-07", "end": "2026-09-05", "shift": "Nights", "hrsShift": 12.0, "guarHrs": 36.0,
     "w2": 35.00, "ot": 52.50, "stipend": 1246.0, "bill": 87.89, "billAfter": None, "msp": 0.0, "nbo": 0.0,
     "team": "TTT", "recruiter": "Bhawna Kumari", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "HWL work order AN-1449-EXT2: 6/7-9/5/2026, 36 hrs, bill $87.89. Pay same as initial contract ($35 W2 + $1,246 stipend), confirmed by Prashant 11/4/2026."},
    {"row": 1024, "sheet": "Completed Assignments", "status": "Completed", "kind": "Contract",
     "candidate": "Areriye F. Ayala", "client": "SGHS - Brunswick (BudE)",
     "facilityUnit": "Southeast Georgia Health System - Brunswick, PCU", "facility": "SGHS - Brunswick",
     "unit": "RN - PCU", "req": "BudE / Stability Managed Services",
     "start": "2026-03-02", "end": "2026-05-02", "shift": "Days", "hrsShift": 12.0, "guarHrs": 36.0,
     "w2": 16.00, "ot": 40.00, "stipend": 1224.0, "bill": 78.00, "billAfter": None, "msp": 0.065, "nbo": 0.0,
     "team": "TTT", "recruiter": "Priti Negi", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "First signed agreement: $16 W2 + $1,224/wk stipend ($1,800/wk at 36 hrs), OT $40, kept for the whole contract per Prashant 11/4/2026. Started 3/2, did not extend past 5/2. Bill $78 per Stability/BudE agency confirmation, unchanged all contract. MSP 6.5%, NBO 0."},
    {"row": 1026, "sheet": "Completed Assignments", "status": "Completed", "kind": "Contract",
     "candidate": "Hilary Chambers", "client": "SGHS - Brunswick (BudE)",
     "facilityUnit": "Southeast Georgia Health System - Brunswick, L&D", "facility": "SGHS - Brunswick",
     "unit": "RN - Labor & Delivery", "req": "BudE / Stability Managed Services",
     "start": "2025-11-10", "end": "2026-02-14", "shift": "Nights", "hrsShift": 12.0, "guarHrs": 36.0,
     "w2": 18.00, "ot": 50.00, "stipend": 1600.0, "bill": 83.00, "billAfter": None, "msp": 0.065, "nbo": 0.0,
     "team": "TTT", "recruiter": "Ruby Bisht", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Signed clinical agreement (as Hilary Engle): $18 W2 + $1,600/wk stipend ($2,248/wk at 36 hrs), OT $50. Bill $83 per Stability/BudE agency confirmation (10/16/2025), 14 weeks. MSP 6.5%, NBO 0 (SGHS Brunswick)."},
    {"row": 1027, "sheet": "Extensions", "status": "Completed", "kind": "Extension",
     "candidate": "Hilary Chambers", "client": "SGHS - Brunswick (BudE)",
     "facilityUnit": "Southeast Georgia Health System - Brunswick, L&D", "facility": "SGHS - Brunswick",
     "unit": "RN - Labor & Delivery", "req": "BudE / Stability Managed Services · 1st extension",
     "start": "2026-02-15", "end": "2026-05-16", "shift": "Nights", "hrsShift": 12.0, "guarHrs": 36.0,
     "w2": 18.00, "ot": 50.00, "stipend": 1600.0, "bill": 82.00, "billAfter": None, "msp": 0.065, "nbo": 0.0,
     "team": "TTT", "recruiter": "Ruby Bisht", "oneTime": 0, "bonus": 300.0, "reason": None, "extra": {},
     "note": "Signed extension form: $18 W2 + up to $1,600/wk stipend ($2,248/wk at 36 hrs), OT $50, $300 extension bonus (deducted). Bill $82 per Stability/BudE agency confirmation (2/5/2026), 13 weeks. MSP 6.5%, NBO 0."},
]

def add_extras(D):
    """Append this dashboard's own records and client fees; skips any already present (same name + start)."""
    D.setdefault("fees", {}).update(EXTRA_FEES)
    have = {((r.get("candidate") or "").strip().lower(), r.get("start")) for r in D["records"]}
    for x in EXTRA_RECORDS:
        if ((x["candidate"]).strip().lower(), x["start"]) in have: continue
        r = dict(x)
        d0, d1 = dt.date.fromisoformat(r["start"]), dt.date.fromisoformat(r["end"])
        r["weeks"] = float(round((d1 - d0).days / 7))
        G, W2, OT = r["guarHrs"], r["w2"], r["ot"] or 0
        if W2 is None or r["stipend"] is None:   # pay terms not on file (e.g. a cancelled offer)
            r["weeklyTaxable"] = r["weeklyGross"] = r["contractGrossPay"] = None
        else:
            r["weeklyTaxable"] = min(G, 40) * W2 + max(G - 40, 0) * OT
            r["weeklyGross"] = r["weeklyTaxable"] + r["stipend"]
            r["contractGrossPay"] = r["weeklyGross"] * r["weeks"]
        r["weeklyBill"] = r["bill"] * G
        r["orig"] = None
        D["records"].append(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=os.path.join(HERE, "..", "prashanttyagi3112", "soloh-ob-dashboard", "index.html"))
    ap.add_argument("--source-password", default=os.environ.get("SOURCE_PASSWORD"))
    ap.add_argument("--password", default=os.environ.get("DASHBOARD_PASSWORD"))
    ap.add_argument("--out", default=os.path.join(HERE, "index.html"))
    ap.add_argument("--state", help="automation state file (default: <source repo>/vault/state.json.enc)")
    ap.add_argument("--dump-json", help="also write the decrypted dataset here (never commit it)")
    a = ap.parse_args()
    if not a.password or not a.source_password:
        sys.exit("Both --password and --source-password are required.")

    D = read_source(a.source, a.source_password)
    # Candidates Prashant chose to keep off this dashboard (automation state, locked with the source password)
    st_path = a.state or os.path.join(os.path.dirname(os.path.abspath(a.source)), "vault", "state.json.enc")
    if os.path.exists(st_path):
        sb = json.loads(open(st_path, encoding="utf-8").read())
        st = json.loads(AESGCM(kdf(a.source_password, b64d(sb["salt"]), sb["iter"])).decrypt(b64d(sb["iv"]), b64d(sb["ct"]), None))
        skip = {(k or "").strip().lower() for k in st.get("skipSoloh", {})}
        if skip:
            D["records"] = [r for r in D["records"] if (r.get("candidate") or "").strip().lower() not in skip]
    add_extras(D)
    # Status moves Prashant made on this dashboard (10/28/2026): kept on every rebuild
    STATUS_OVERRIDES = {"blessing madu": "Started", "suze etienne": "Started"}
    for r in D["records"]:
        k = (r.get("candidate") or "").strip().lower()
        if k in STATUS_OVERRIDES and r.get("status") != "Cancelled":
            r["status"] = STATUS_OVERRIDES[k]
    # Team names shown on this dashboard (Prashant, 10/19/2026): Harsh's Team -> HST, Tackle's Team -> TTT
    TEAM_LABELS = {"harsh's team": "HST", "harsh team": "HST", "tackle's team": "TTT", "tackle team": "TTT"}
    for r in D["records"]:
        t = (r.get("team") or "").replace("’", "'").strip().lower()
        if t in TEAM_LABELS: r["team"] = TEAM_LABELS[t]
    # Method-dependent notes from the source are recalculated here; data notes are kept.
    dq = [q for q in D.get("quality", []) if not re.search(r"Negative net profit|well above the group median|Excel shows", q.get("msg", ""))]
    for r in D["records"]:
        cfo(r, dq)
        if r["status"] != "Cancelled" and r.get("netProfit") is not None and r["netProfit"] < 0:
            dq.append({"sev": "error", "sheet": r["sheet"], "row": r["row"], "who": r["candidate"], "msg": "Negative net profit (CFO method)."})
        if r.get("oneTime"):
            dq.append({"sev": "info", "sheet": r["sheet"], "row": r["row"], "who": r["candidate"],
                       "msg": f"One-time costs of ${r['oneTime']:,.0f} " + ("deducted with Client fees (col W)." if (ONE_TIME_IN_PROFIT or r.get("deductOneTime")) else "not deducted (left out, as in Peter's sheet).")})
    names = {}
    for r in D["records"]:
        k = (r.get("candidate") or "").strip().lower()
        if k and k in names and names[k]["status"] != "Cancelled" and r["status"] != "Cancelled":
            dq.append({"sev": "warn", "sheet": r["sheet"], "row": r["row"], "who": r["candidate"], "msg": "Same name appears more than once among active offers."})
        names.setdefault(k, r)

    D["source"] = {"dashboard": "Margin Dashboard (soloh-ob-dashboard)", "builtAt": D.get("builtAt"), "workbook": D.get("workbook")}
    D["builtAt"] = dt.datetime.now(ET).strftime("%a %m/%d/%Y %I:%M %p ET")
    D["method"] = {"version": METHOD_VERSION, "burden": BURDEN, "target": TARGET, "onboarding": ONBOARDING_COST,
                   "oneTimeIncluded": ONE_TIME_IN_PROFIT, "sourceLoad": D.get("settings", {}).get("payroll_load")}
    D["quality"] = dq
    if a.dump_json:
        with open(a.dump_json, "w") as fh: json.dump(D, fh, indent=1, default=str)
    blob = encrypt(json.dumps(D, default=str).encode(), a.password)
    html = open(os.path.join(HERE, "template.html"), encoding="utf-8").read()
    if "/*__ENCRYPTED_DATA__*/null" not in html: sys.exit("Placeholder missing from template.html")
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(html.replace("/*__ENCRYPTED_DATA__*/null", json.dumps(blob)))
    act = [r for r in D["records"] if r["status"] != "Cancelled"]
    below = [r["candidate"] for r in act if r.get("targetStatus") == "below"]
    print(f"Built {a.out}: {len(act)} active, {len(D['records'])-len(act)} cancelled; below 10% target: {', '.join(below) or 'none'}")

if __name__ == "__main__":
    main()
