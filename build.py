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
    stp = stip * wk
    nbo_c = nbo * (W2 * (1 + BURDEN))
    onetime = (r.get("oneTime") or 0) if (ONE_TIME_IN_PROFIT or r.get("deductOneTime")) else 0
    bonus = r.get("bonus") or 0          # candidate bonus Prashant chose to deduct (e.g. Graydon 2nd ext., $400)
    fees = ONBOARDING_COST + onetime + bonus
    profit = net - (reg + ot + stp + nbo_c + fees)
    margin = profit / net if net else None
    # Peter's column Z (kept on his sheet for reference): NBO at bill rate net of MSP
    z = net - wk * (min(G, 40) * W2 + max(G - 40, 0) * (OT or 0)) * (1 + BURDEN) - wk * stip - nbo * bill * (1 - msp) - ONBOARDING_COST - onetime - bonus
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
     "note": "Local assignment confirmation signed 10/1/2026 (version B): $2,950/wk all W2 ($73.75 x 40), OT $90. Running; shows in Started until 11/14/2026, then moves to Completed Assg./Extensions automatically. Off 5/31-7/24 and 9/20-9/26/2026."},
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
     "start": "2025-11-19", "end": "2026-02-21", "shift": "Days", "hrsShift": 7.0, "guarHrs": round(516.14 / 14, 4),
     "w2": 17.80, "ot": 50.00, "stipend": 1897.0, "bill": 98.00, "billAfter": None, "msp": 0.07, "nbo": 0.0,
     "team": "TTT", "recruiter": "Ravi/Guddu", "oneTime": 0, "bonus": 0.0, "reason": None, "extra": {},
     "note": "Signed travel assignment confirmation: $17.80 W2 + $1,897/wk stipend ($2,520/wk at 35 hrs), OT $50. Revenue and pay use the actual 516.14 hrs billed and paid in Magnit (avg 36.87 hrs/wk over 14 wks), adjustment line ignored, per Prashant 11/2/2026."},
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
