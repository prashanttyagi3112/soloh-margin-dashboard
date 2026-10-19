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
    onetime = (r.get("oneTime") or 0) if ONE_TIME_IN_PROFIT else 0
    fees = ONBOARDING_COST + onetime
    profit = net - (reg + ot + stp + nbo_c + fees)
    margin = profit / net if net else None
    # Peter's column Z (kept on his sheet for reference): NBO at bill rate net of MSP
    z = net - wk * (min(G, 40) * W2 + max(G - 40, 0) * (OT or 0)) * (1 + BURDEN) - wk * stip - nbo * bill * (1 - msp) - ONBOARDING_COST - onetime
    c.update({"gross": gross, "net": net, "mspFee": gross - net, "regular": reg, "ot": ot, "stipend": stp,
              "nbo": nbo_c, "onboarding": ONBOARDING_COST, "oneTime": onetime, "clientFees": fees,
              "targetProfit": TARGET * net, "gapToTarget": profit - TARGET * net,
              "variance": (margin - TARGET) if margin is not None else None,
              "colZ": z, "colZMargin": z / net if net else None})
    r.update({"grossRev": gross, "netRev": net, "netProfit": profit, "marginPct": margin,
              "weeklyProfit": profit / wk, "cfo": c, "targetStatus": target_status(margin)})


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
                       "msg": f"One-time costs of ${r['oneTime']:,.0f} " + ("deducted with Client fees (col W)." if ONE_TIME_IN_PROFIT else "not deducted (left out, as in Peter's sheet).")})
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
