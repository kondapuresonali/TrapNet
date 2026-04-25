from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from urllib.parse import urlparse
import re, pickle, os, requests, base64, difflib, json, io
from datetime import datetime, timezone 
from dotenv import load_dotenv
load_dotenv()

# ── PDF export (reportlab) ────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    pdf_enabled = True
except ImportError:
    pdf_enabled = False

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────────────────
#  VIRUSTOTAL API KEY — get free at https://virustotal.com
#  Paste key below OR:  export VT_API_KEY="your_key"
# ─────────────────────────────────────────────────────────────────────
VT_API_KEY = os.environ.get("VT_API_KEY", "e64b7be8402d9c9b31ade8ef05855949314401e842b82b259088b49e48481224")
VT_BASE    = "https://www.virustotal.com/api/v3"

# ─────────────────────────────────────────────────────────────────────
#  ANTHROPIC API KEY — get free at https://console.anthropic.com
#  Paste key below OR:  export ANTHROPIC_API_KEY="your_key"
# ─────────────────────────────────────────────────────────────────────
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyBkk3jtBldOc4VPyVEE97_DTJmiW0dGx14")

TRUSTED_BRANDS = [
    "google", "facebook", "amazon", "paypal", "microsoft", "apple",
    "netflix", "instagram", "twitter", "linkedin", "github", "youtube",
    "sbi", "hdfc", "axis", "icici", "kotak", "paytm", "phonepe", "gpay",
    "flipkart", "snapdeal", "myntra", "zomato", "swiggy", "ola", "uber",
    "whatsapp", "telegram", "discord", "spotify", "adobe", "dropbox"
]

TRUSTED_DOMAINS = [b + ".com" for b in TRUSTED_BRANDS] + [
    "sbi.co.in", "hdfcbank.com", "axisbank.com", "amazon.in"
]

# ── Load ML model ─────────────────────────────────────────────────────
import numpy as np

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    suspicious_keywords = ["login","verify","secure","update","confirm","account","signin",
        "alert","warning","bank","pay","free","prize","winner","reward",
        "password","otp","kyc","blocked","locked","suspended","urgent"]
    bad_tlds   = [".xyz",".tk",".ml",".ga",".cf",".top",".click",".pw",".work",".gq"]
    shorteners = ["bit.ly","tinyurl","t.co","goo.gl","ow.ly"]
    return [
        len(url), len(domain),
        int(url.startswith("https")),
        int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))),
        int("@" in url), url.count("-"), url.count("."),
        max(0, len(domain.split(".")) - 2),
        sum(c.isdigit() for c in url),
        sum(1 for kw in suspicious_keywords if kw in url.lower()),
        int(any(url.lower().find(t) > 0 for t in bad_tlds)),
        int(any(s in url for s in shorteners)),
    ]

ml_enabled = False
model = vectorizer = None
try:
    model      = pickle.load(open("model/model.pkl", "rb"))
    vectorizer = pickle.load(open("model/vectorizer.pkl", "rb"))
    ml_enabled = True
# ── In-memory scan history (last 100 scans) ───────────────────────────
scan_history = []


# ═══════════════════════════════════════════════════════════════════════
#  FEATURE 1 — WHOIS domain age checker
# ═══════════════════════════════════════════════════════════════════════
def get_whois_age(domain):
    """
    Returns dict with domain age in days, creation date, registrar.
    Uses RDAP (free, no pip install needed) as primary source.
    """
    try:
        clean = domain.replace("www.", "").split(":")[0]
        # Try RDAP first (no extra package)
        resp = requests.get(
            f"https://rdap.org/domain/{clean}",
            timeout=6,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            events = data.get("events", [])
            reg_date = None
            for ev in events:
                if ev.get("eventAction") == "registration":
                    reg_date = ev.get("eventDate", "")[:10]
                    break
            if reg_date:
                created = datetime.strptime(reg_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - created).days
                registrar = ""
                for entity in data.get("entities", []):
                    for role in entity.get("roles", []):
                        if role == "registrar":
                            vcard = entity.get("vcardArray", [])
                            if len(vcard) > 1:
                                for entry in vcard[1]:
                                    if entry[0] == "fn":
                                        registrar = entry[3]
                return {
                    "age_days": age_days,
                    "created": reg_date,
                    "registrar": registrar or "Unknown",
                    "new_domain": age_days < 30
                }
        return None
    except Exception as e:
        print(f"WHOIS error: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════
#  FEATURE 2 — Typosquatting detector
# ═══════════════════════════════════════════════════════════════════════
def check_typosquatting(domain):
    """
    Uses difflib to find brand impersonation attempts.
    Returns list of (brand, similarity_score) for matches above threshold.
    """
    clean = domain.replace("www.", "").split(".")[0].lower()
    matches = []
    for brand in TRUSTED_BRANDS:
        ratio = difflib.SequenceMatcher(None, clean, brand).ratio()
        if ratio >= 0.75 and clean != brand:
            # Extra check: not a subdomain of the real brand
            if brand not in domain or domain.split(".")[-2] != brand:
                matches.append({"brand": brand, "score": round(ratio * 100)})
    # Sort by similarity desc
    return sorted(matches, key=lambda x: x["score"], reverse=True)[:3]


# ═══════════════════════════════════════════════════════════════════════
#  FEATURE 3 — VirusTotal
# ═══════════════════════════════════════════════════════════════════════
def encode_url_b64(url):
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def get_vt_report(url):
    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return None
    headers = {"x-apikey": VT_API_KEY}
    url_id  = encode_url_b64(url)
    try:
        resp = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=12)
    except requests.RequestException:
        return None
    if resp.status_code == 404:
        requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url}, timeout=10)
        return {"scanning": True}
    if resp.status_code != 200:
        return None
    attr   = resp.json()["data"]["attributes"]
    stats  = attr.get("last_analysis_stats", {})
    results= attr.get("last_analysis_results", {})
    mal    = stats.get("malicious",  0)
    sus    = stats.get("suspicious", 0)
    har    = stats.get("harmless",   0)
    undet  = stats.get("undetected", 0)
    total  = mal + sus + har + undet
    flagged= [e for e,r in results.items() if r.get("category") in ("malicious","suspicious")][:6]
    cats   = list(set(attr.get("categories", {}).values()))[:3]
    score  = round((mal + sus*0.5)/total*100) if total else 0
    return {
        "scanning":   False,
        "malicious":  mal, "suspicious": sus,
        "harmless":   har, "total": total,
        "vt_score":   score, "flagged_by": flagged,
        "categories": cats,
        "vt_link":    f"https://www.virustotal.com/gui/url/{url_id}"
    }


# ═══════════════════════════════════════════════════════════════════════
#  FEATURE 4 — AI Explanation via Claude API
# ═══════════════════════════════════════════════════════════════════════
def get_ai_explanation(url, domain, threat_level, reasons, risk_score):
    if GEMINI_API_KEY == "YOUR_GEMINI_KEY_HERE":
        return None
    try:
        reason_texts = [r["text"] for r in reasons if isinstance(r, dict)]
        prompt = f"""You are a cybersecurity analyst. Explain this URL scan in 2-3 plain English sentences for a non-technical person. Be direct about the risk.

URL: {url}
Domain: {domain}
Threat Level: {threat_level}
Risk Score: {risk_score}%
Issues Found: {', '.join(reason_texts[:5])}

2-3 sentences only. No bullet points. No markdown."""

        resp = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}",
            headers={"Content-Type": "application/json"},
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=15
        )
        if resp.status_code == 200:
            return resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        else:
            print(f"Gemini error: {resp.status_code} {resp.text}")
            return None
    except Exception as e:
        print(f"AI explanation error: {e}")
        return None
# ═══════════════════════════════════════════════════════════════════════
#  CORE: URL analysis engine
# ═══════════════════════════════════════════════════════════════════════
def check_url(url):
    score   = 0
    reasons = []
    parsed  = urlparse(url)
    domain  = parsed.netloc.lower().replace("www.", "")

    # Rule-based checks
    if not url.startswith("https"):
        score += 20
        reasons.append({"icon": "🔓", "text": "No HTTPS — connection is not encrypted"})

    if len(url) > 75:
        score += 10
        reasons.append({"icon": "📏", "text": f"Unusually long URL ({len(url)} chars)"})

    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score += 20
        reasons.append({"icon": "🔢", "text": "Raw IP address used instead of domain name"})

    if "@" in url:
        score += 20
        reasons.append({"icon": "🎭", "text": "Contains '@' — classic phishing redirect trick"})

    if domain.count("-") >= 2:
        score += 10
        reasons.append({"icon": "➖", "text": f"Multiple hyphens in domain: {domain}"})

    keywords   = ["login","verify","secure","bank","update","account","confirm","password","signin","support"]
    found_kw   = [w for w in keywords if w in url.lower()]
    if found_kw:
        score += min(len(found_kw)*8, 24)
        reasons.append({"icon": "🔑", "text": f"Suspicious keywords: {', '.join(found_kw)}"})

    bad_tlds = [".xyz",".tk",".ml",".ga",".cf",".gq",".top",".click",".pw",".work"]
    for tld in bad_tlds:
        if domain.endswith(tld):
            score += 15
            reasons.append({"icon": "🌐", "text": f"High-risk TLD detected: {tld}"})
            break

    for brand in TRUSTED_DOMAINS:
        bname = brand.split(".")[0]
        if bname in domain and domain != brand:
            score += 30
            reasons.append({"icon": "⚠️", "text": f"Possible impersonation of {brand}"})
            break

    if len(parsed.netloc.split(".")) > 4:
        score += 10
        reasons.append({"icon": "🔗", "text": f"Excessive subdomains detected"})

    # ML model
    ai_confidence = None
    if ml_enabled:
        try:
            url_vec       = vectorizer.transform([url])
            prob          = model.predict_proba(url_vec)[0][1]
            ai_confidence = round(prob * 100)
            score        += prob * 40
            reasons.append({"icon": "🤖", "text": f"ML model: {ai_confidence}% phishing probability"})
        except Exception as e:
            print(f"ML error: {e}")

    # VirusTotal
    vt_data    = None
    vt_enabled = VT_API_KEY != "YOUR_VIRUSTOTAL_API_KEY_HERE"
    if vt_enabled:
        try:
            vt_data = get_vt_report(url)
            if vt_data and not vt_data.get("scanning"):
                mal = vt_data["malicious"]
                if mal > 0:
                    score += min(mal * 5, 30)
                    reasons.append({"icon": "🛡️", "text": f"VirusTotal: {mal} vendors flagged this URL"})
        except Exception as e:
            print(f"VT error: {e}")

    # WHOIS domain age
    whois_data = None
    try:
        whois_data = get_whois_age(domain)
        if whois_data:
            if whois_data["new_domain"]:
                score += 20
                reasons.append({"icon": "📅", "text": f"Brand new domain — only {whois_data['age_days']} days old (high phishing risk)"})
    except Exception as e:
        print(f"WHOIS error: {e}")

    # Typosquatting
    typo_matches = []
    try:
        typo_matches = check_typosquatting(domain)
        if typo_matches:
            top = typo_matches[0]
            score += 25
            reasons.append({"icon": "🎯", "text": f"Typosquatting detected: looks like '{top['brand']}' ({top['score']}% similar)"})
    except Exception as e:
        print(f"Typo error: {e}")

    # Final verdict
    risk = min(int(score), 100)
    if   risk >= 70: status, threat_level = "phishing",  "HIGH"
    elif risk >= 40: status, threat_level = "suspicious", "MEDIUM"
    elif risk >= 15: status, threat_level = "low",        "LOW"
    else:            status, threat_level = "safe",       "SAFE"

    if not reasons:
        reasons.append({"icon": "✅", "text": "No threats detected — URL looks clean"})

    # AI explanation
    ai_explanation = get_ai_explanation(url, domain, threat_level, reasons, risk)

    result = {
        "status":         status,
        "threat_level":   threat_level,
        "risk":           risk,
        "reasons":        reasons,
        "domain":         domain,
        "ai_confidence":  ai_confidence,
        "ai_explanation": ai_explanation,
        "vt":             vt_data,
        "vt_enabled":     vt_enabled,
        "whois":          whois_data,
        "typo_matches":   typo_matches,
        "scan_date":      datetime.utcnow().strftime("%d %b %Y, %H:%M UTC")
    }

    # Save to history
    scan_history.insert(0, {"url": url, **result})
    if len(scan_history) > 100:
        scan_history.pop()

    return result


# ═══════════════════════════════════════════════════════════════════════
#  FEATURE 5 — PDF Report Export
# ═══════════════════════════════════════════════════════════════════════
def generate_pdf_report(url, data):
    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(buf, pagesize=A4,
                               leftMargin=20*mm, rightMargin=20*mm,
                               topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    story  = []

    # Custom styles
    title_style = ParagraphStyle("title", parent=styles["Title"],
                                 fontSize=22, spaceAfter=4,
                                 textColor=colors.HexColor("#7c5cfc"))
    sub_style   = ParagraphStyle("sub", parent=styles["Normal"],
                                 fontSize=10, textColor=colors.HexColor("#888888"),
                                 spaceAfter=16)
    h2_style    = ParagraphStyle("h2", parent=styles["Heading2"],
                                 fontSize=13, spaceBefore=14, spaceAfter=6,
                                 textColor=colors.HexColor("#333333"))
    body_style  = ParagraphStyle("body", parent=styles["Normal"],
                                 fontSize=10, leading=16,
                                 textColor=colors.HexColor("#222222"))
    mono_style  = ParagraphStyle("mono", parent=styles["Normal"],
                                 fontSize=9, fontName="Courier",
                                 textColor=colors.HexColor("#555555"))

    # Verdict colors
    verdict_colors = {
        "phishing":  colors.HexColor("#ff4060"),
        "suspicious":colors.HexColor("#ffb344"),
        "low":       colors.HexColor("#ffb344"),
        "safe":      colors.HexColor("#00e096"),
    }
    vc = verdict_colors.get(data["status"], colors.HexColor("#888888"))

    # ── Title block ──
    story.append(Paragraph("TrapNet", title_style))
    story.append(Paragraph("Cyber Intelligence System — Scan Report", sub_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e0e0e0")))
    story.append(Spacer(1, 10))

    # ── Verdict ──
    verdict_text = {
        "phishing": "PHISHING DETECTED",
        "suspicious": "SUSPICIOUS URL",
        "low": "LOW THREAT DETECTED",
        "safe": "URL IS SAFE"
    }.get(data["status"], "UNKNOWN")

    verdict_style = ParagraphStyle("verdict", parent=styles["Normal"],
                                   fontSize=16, fontName="Helvetica-Bold",
                                   textColor=vc, spaceAfter=12)
    story.append(Paragraph(f"&#x25CF; {verdict_text}", verdict_style))

    # ── Summary table ──
    summary_data = [
        ["URL",          url],
        ["Domain",       data.get("domain", "—")],
        ["Threat Level", data.get("threat_level", "—")],
        ["Risk Score",   f"{data.get('risk', 0)}%"],
        ["Scanned",      data.get("scan_date", "—")],
    ]
    if data.get("ai_confidence") is not None:
        summary_data.append(["ML Confidence", f"{data['ai_confidence']}%"])
    if data.get("whois"):
        w = data["whois"]
        summary_data.append(["Domain Age", f"{w['age_days']} days (created {w['created']})"])
        summary_data.append(["Registrar",  w.get("registrar", "Unknown")])

    t = Table(summary_data, colWidths=[45*mm, 130*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#f5f3ff")),
        ("TEXTCOLOR",  (0,0), (0,-1), colors.HexColor("#7c5cfc")),
        ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, colors.HexColor("#fafafa")]),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
        ("PADDING",    (0,0), (-1,-1), 7),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("WORDWRAP",   (1,0), (1,-1), True),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # ── AI explanation ──
    if data.get("ai_explanation"):
        story.append(Paragraph("AI Analysis", h2_style))
        story.append(Paragraph(data["ai_explanation"], body_style))
        story.append(Spacer(1, 8))

    # ── Threat indicators ──
    story.append(Paragraph("Threat Indicators", h2_style))
    for r in data.get("reasons", []):
        text = r["text"] if isinstance(r, dict) else str(r)
        icon = r.get("icon", "•") if isinstance(r, dict) else "•"
        story.append(Paragraph(f"{icon}  {text}", body_style))
    story.append(Spacer(1, 8))

    # ── VT section ──
    vt = data.get("vt")
    if vt and not vt.get("scanning"):
        story.append(Paragraph("VirusTotal Report", h2_style))
        vt_data = [
            ["Malicious Vendors", str(vt.get("malicious", 0))],
            ["Suspicious Vendors",str(vt.get("suspicious",0))],
            ["Harmless Vendors",  str(vt.get("harmless",  0))],
            ["Total Vendors",     str(vt.get("total",     0))],
        ]
        if vt.get("flagged_by"):
            vt_data.append(["Flagged By", ", ".join(vt["flagged_by"])])
        if vt.get("categories"):
            vt_data.append(["Categories", ", ".join(vt["categories"])])
        vt_table = Table(vt_data, colWidths=[50*mm, 125*mm])
        vt_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#fff0f2")),
            ("TEXTCOLOR",  (0,0), (0,-1), colors.HexColor("#cc0000")),
            ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
            ("PADDING",    (0,0), (-1,-1), 7),
        ]))
        story.append(vt_table)
        story.append(Spacer(1, 8))

    # ── Typosquatting ──
    if data.get("typo_matches"):
        story.append(Paragraph("Typosquatting Analysis", h2_style))
        for m in data["typo_matches"]:
            story.append(Paragraph(
                f"• Resembles brand '{m['brand']}' with {m['score']}% similarity",
                body_style
            ))
        story.append(Spacer(1, 8))

    # ── Footer ──
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e0e0e0")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Generated by TrapNet Cyber Intelligence System · {datetime.utcnow().strftime('%d %b %Y %H:%M UTC')}",
        ParagraphStyle("footer", parent=styles["Normal"],
                       fontSize=8, textColor=colors.HexColor("#aaaaaa"),
                       alignment=TA_CENTER)
    ))

    doc.build(story)
    buf.seek(0)
    return buf


# ═══════════════════════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if request.is_json:
        url = (request.get_json() or {}).get("url", "").strip()
    else:
        url = request.form.get("url", "").strip()
    if not url:
        if request.is_json:
            return jsonify({"error": "No URL provided"}), 400
        return render_template("index.html", error="Please enter a URL")
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    data = check_url(url)
    if request.is_json:
        return jsonify({"url": url, **data})
    return render_template("index.html", data=data, url=url)


# ── FEATURE 6: Bulk URL scanner ───────────────────────────────────────
@app.route("/bulk-scan", methods=["POST"])
def bulk_scan():
    body = request.get_json() or {}
    urls = body.get("urls", [])
    if not urls:
        return jsonify({"error": "No URLs provided"}), 400
    urls = [u.strip() for u in urls if u.strip()][:20]  # max 20
    results = []
    for url in urls:
        if not url.startswith(("http://","https://")):
            url = "https://" + url
        try:
            r = check_url(url)
            results.append({"url": url, **r})
        except Exception as e:
            results.append({"url": url, "error": str(e), "status": "error"})
    return jsonify({"results": results, "total": len(results)})


# ── FEATURE 7: History API ────────────────────────────────────────────
@app.route("/history", methods=["GET"])
def get_history():
    return jsonify({
        "history": scan_history[:50],
        "total":   len(scan_history)
    })

@app.route("/history/clear", methods=["POST"])
def clear_history():
    scan_history.clear()
    return jsonify({"ok": True})


# ── PDF Export ────────────────────────────────────────────────────────
@app.route("/export-pdf", methods=["POST"])
def export_pdf():
    body = request.get_json() or {}
    url  = body.get("url", "").strip()
    data = body.get("data", {})
    if not url or not data:
        return jsonify({"error": "Missing data"}), 400
    if not pdf_enabled:
        return jsonify({"error": "reportlab not installed"}), 500
    try:
        buf      = generate_pdf_report(url, data)
        filename = f"trapnet_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        return send_file(buf, mimetype="application/pdf",
                         as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("🕸  TrapNet v2 → http://localhost:5000")
    app.run(debug=True, port=5000)