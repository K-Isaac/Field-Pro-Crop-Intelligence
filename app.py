"""FieldLens Pro AI — live, public plant-intelligence platform (v3).

Public app  : /            anyone with internet can scan a plant and get a diagnosis
Admin       : /admin       password-protected control tower (keys, limits, scans, logs)
"""
import os, io, csv, json, time, uuid, hmac, hashlib, secrets, sqlite3, base64, re
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory, session, Response, g
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageOps

try:
    import qrcode, qrcode.image.svg
except Exception:  # optional
    qrcode = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv("DATA_DIR") or os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
DB_PATH = os.path.join(DATA_DIR, "fieldlens.db")
PRODUCTION = os.getenv("FL_ENV", "development") == "production"
os.makedirs(UPLOAD_DIR, exist_ok=True)
Image.MAX_IMAGE_PIXELS = 40_000_000

LANGS = {"en": "English", "rw": "Kinyarwanda", "fr": "French", "sw": "Swahili"}


def load_secret():
    env = os.getenv("SECRET_KEY")
    if env:
        return env
    p = os.path.join(DATA_DIR, ".secret_key")
    if os.path.exists(p):
        with open(p) as f:
            return f.read().strip()
    k = secrets.token_hex(32)
    with open(p, "w") as f:
        f.write(k)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return k


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = load_secret()
app.config.update(
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=PRODUCTION,
    PERMANENT_SESSION_LIFETIME=8 * 3600,
)

# --------------------------------------------------------------------------- DB
SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, created_at INTEGER, ip_hash TEXT, client_id TEXT, device TEXT,
  lang TEXT, crop_hint TEXT, notes TEXT, image TEXT, latency_ms INTEGER, engine TEXT,
  status TEXT, danger INTEGER DEFAULT 0, health INTEGER, plant TEXT, analysis TEXT, error TEXT);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_ip ON scans(ip_hash, created_at);
CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, created_at INTEGER, helpful INTEGER, comment TEXT);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, level TEXT, source TEXT, message TEXT);
CREATE TABLE IF NOT EXISTS login_attempts (ip_hash TEXT, ts INTEGER);
"""


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    con.commit()
    con.close()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=15)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def log(level, source, message):
    try:
        con = sqlite3.connect(DB_PATH, timeout=15)
        con.execute("INSERT INTO logs(ts,level,source,message) VALUES(?,?,?,?)",
                    (int(time.time()), level, source, str(message)[:500]))
        con.execute("DELETE FROM logs WHERE id < (SELECT MAX(id) FROM logs) - 2000")
        con.commit()
        con.close()
    except Exception as e:  # never break a request because of logging
        print("log failure:", e)


# ---------------------------------------------------------------------- settings
DEFAULTS = {
    "ai_provider": "openai",
    "openai_model": "gpt-4.1",
    "gemini_model": "gemini-2.5-flash",
    "openai_api_key": "",
    "gemini_api_key": "",
    "admin_password_hash": "",
    "min_health_score": 55,
    "min_water_pct": 38,
    "min_nitrogen_pct": 40,
    "min_phosphorus_pct": 35,
    "min_potassium_pct": 35,
    "chlorophyll_sensitivity": 1.0,
    "scans_per_ip_per_hour": 12,
    "global_scans_per_day": 500,
    "max_upload_mb": 10,
    "maintenance_mode": False,
    "announcement": "",
    "public_name": "FieldLens Pro",
    "contact_email": "",
    "region_context": "Rwanda & East Africa",
}
# key -> (type, *bounds)
EDITABLE = {
    "ai_provider": ("choice", ["openai", "gemini"]),
    "openai_model": ("str", 60), "gemini_model": ("str", 60),
    "min_health_score": ("int", 5, 95), "min_water_pct": ("int", 5, 95),
    "min_nitrogen_pct": ("int", 5, 95), "min_phosphorus_pct": ("int", 5, 95),
    "min_potassium_pct": ("int", 5, 95),
    "chlorophyll_sensitivity": ("float", 0.5, 1.5),
    "scans_per_ip_per_hour": ("int", 1, 1000), "global_scans_per_day": ("int", 1, 1000000),
    "max_upload_mb": ("int", 1, 20),
    "maintenance_mode": ("bool",), "announcement": ("str", 300),
    "public_name": ("str", 60), "contact_email": ("str", 120), "region_context": ("str", 120),
}


def S():
    if "settings" not in g:
        s = dict(DEFAULTS)
        for r in get_db().execute("SELECT key,value FROM settings"):
            if r["key"] in DEFAULTS:
                try:
                    s[r["key"]] = json.loads(r["value"])
                except ValueError:
                    pass
        g.settings = s
    return g.settings


def set_setting(key, value):
    get_db().execute("INSERT INTO settings(key,value) VALUES(?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))
    get_db().commit()
    g.pop("settings", None)


def api_key(provider):
    k = (S().get(f"{provider}_api_key") or "").strip()
    return k or os.getenv(f"{provider.upper()}_API_KEY", "").strip()


def key_source(provider):
    if (S().get(f"{provider}_api_key") or "").strip():
        return "admin"
    return "env" if os.getenv(f"{provider.upper()}_API_KEY", "").strip() else None


def ai_ready():
    return bool(api_key(S()["ai_provider"]))


def scrub(msg):
    msg = str(msg)
    for p in ("openai", "gemini"):
        k = api_key(p)
        if k:
            msg = msg.replace(k, "***")
    return re.sub(r"(sk-[A-Za-z0-9_\-]{6,}|AIza[0-9A-Za-z_\-]{10,})", "***", msg)


# ------------------------------------------------------------------------ helpers
def client_ip_hash():
    ip = request.remote_addr or "0.0.0.0"
    return hashlib.sha256((app.secret_key + ip).encode()).hexdigest()[:16]


def now():
    return int(time.time())


def json_error(msg, code):
    return jsonify({"ok": False, "error": msg}), code


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; media-src 'self' blob:; "
        "manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'self'")
    if PRODUCTION:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.path.startswith("/admin") or request.path.startswith("/api/admin"):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    return resp


# --------------------------------------------------------------------- AI engine
def build_prompt(crop, notes, lang):
    s = S()
    return f"""
You are FieldLens Pro AI, an expert precision-agronomy and plant-diagnostics engine serving farmers in {s['region_context']}.
Look carefully at the image. Return ONLY valid JSON (no markdown fences) matching exactly this schema:
{{
  "is_plant": true,
  "confidence": 80,
  "retake_tip": "If the photo is blurry/dark/too far, one short tip to retake it, else empty string",
  "plant_name": "Common Name (Scientific Name)",
  "crop_stage": "Seedling | Vegetative | Flowering | Fruiting/Grain-Fill | Mature",
  "estimated_age_days": 42,
  "probable_maturity_window": "e.g. 38 - 45 days remaining (total cycle ~85 days)",
  "maturity_drivers": "Short physiological reason for this maturity timeline",
  "overall_status": "Optimal | Moderate Stress | High Risk - Immediate Action",
  "health_score": 78,
  "danger_alarm": false,
  "danger_reason": null,
  "endangered_zone": "none | roots | stem | lower_leaves | upper_canopy | fruit",
  "endangered_zone_detail": "Exact symptom location and likely physiological cause",
  "nutrients": {{"nitrogen_pct": 65, "phosphorus_pct": 70, "potassium_pct": 58, "magnesium_pct": 72, "iron_pct": 68, "status_summary": "Short summary"}},
  "water_composition": {{"hydration_pct": 54, "turgor_status": "Optimal Turgor | Mild Deficit | Severe Wilting | Waterlogged", "recommendation": "Practical irrigation adjustment"}},
  "fertilizer_and_manure": [{{"type": "e.g. composted manure, NPK 17-17-17, urea", "dosage": "Practical field rate", "timing": "When and how to apply"}}],
  "pests_and_insects": [{{"name": "Detected pest/disease or 'None detected'", "severity": "None | Low | Moderate | High", "insecticide_or_ipm": "Integrated pest management step first (cultural/biological/neem), then an approved active ingredient if needed"}}],
  "summary": "Two plain-language sentences for the farmer."
}}
Rules:
- If the image does not clearly show a plant or crop, set "is_plant": false and keep other fields minimal.
- Percentages are visual estimates from the image, not lab values; stay honest in "confidence".
- Recommend only widely available inputs; mention reading the product label and wearing protective gear for any chemical.
- Write every human-readable VALUE in {LANGS.get(lang, 'English')}; keep JSON keys and the enumerated status words (Optimal, Moderate Stress, High Risk - Immediate Action, severity words, zone names) in English.
Farmer crop hint: {crop or 'Auto-detect from the image'}
Farmer notes: {notes or 'None'}
Set danger_alarm=true if health_score < {s['min_health_score']} OR hydration_pct < {s['min_water_pct']} OR nitrogen_pct < {s['min_nitrogen_pct']} OR potassium_pct < {s['min_potassium_pct']} OR a severe pest/disease is visible.
"""


def _parse_json(raw):
    raw = (raw or "").strip()
    a, b = raw.find("{"), raw.rfind("}")
    if a < 0 or b < a:
        raise ValueError("AI returned no JSON")
    return json.loads(raw[a:b + 1])


def call_openai(img_bytes, prompt):
    from openai import OpenAI
    s = S()
    client = OpenAI(api_key=api_key("openai"), timeout=70, max_retries=1)
    b64 = base64.b64encode(img_bytes).decode()
    resp = client.responses.create(
        model=s["openai_model"],
        input=[{"role": "user", "content": [
            {"type": "input_text", "text": prompt},
            {"type": "input_image", "image_url": f"data:image/jpeg;base64,{b64}", "detail": "high"}]}])
    return _parse_json(resp.output_text), f"OpenAI Vision ({s['openai_model']})"


def call_gemini(img_bytes, prompt):
    from google import genai
    from google.genai import types
    s = S()
    client = genai.Client(api_key=api_key("gemini"))
    resp = client.models.generate_content(
        model=s["gemini_model"],
        contents=[types.Part.from_bytes(data=img_bytes, mime_type="image/jpeg"), prompt],
        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0.2))
    return _parse_json(resp.text), f"Gemini Vision ({s['gemini_model']})"


def run_ai(img_bytes, crop, notes, lang):
    prompt = build_prompt(crop, notes, lang)
    if S()["ai_provider"] == "gemini":
        return call_gemini(img_bytes, prompt)
    return call_openai(img_bytes, prompt)


def num(v, lo=0, hi=100, default=0):
    try:
        return int(max(lo, min(hi, round(float(v)))))
    except (TypeError, ValueError):
        return default


def txt(v, n=400, default=""):
    return default if v is None else str(v)[:n]


ZONES = {"none", "roots", "stem", "lower_leaves", "upper_canopy", "fruit"}


def normalize(d):
    """Coerce untrusted model output into a safe, predictable shape."""
    if not isinstance(d, dict):
        raise ValueError("AI output was not an object")
    n, w = d.get("nutrients") or {}, d.get("water_composition") or {}
    zone = txt(d.get("endangered_zone"), 20, "none").lower().replace(" ", "_")
    ferts = [{"type": txt(f.get("type"), 120), "dosage": txt(f.get("dosage"), 160), "timing": txt(f.get("timing"), 200)}
             for f in (d.get("fertilizer_and_manure") or [])[:4] if isinstance(f, dict)]
    pests = [{"name": txt(p.get("name"), 120), "severity": txt(p.get("severity"), 12, "None"),
              "insecticide_or_ipm": txt(p.get("insecticide_or_ipm"), 300)}
             for p in (d.get("pests_and_insects") or [])[:4] if isinstance(p, dict)]
    return {
        "is_plant": bool(d.get("is_plant", True)),
        "confidence": num(d.get("confidence"), default=60),
        "retake_tip": txt(d.get("retake_tip"), 200),
        "plant_name": txt(d.get("plant_name"), 120, "Unknown plant"),
        "crop_stage": txt(d.get("crop_stage"), 40),
        "estimated_age_days": num(d.get("estimated_age_days"), 0, 1500),
        "probable_maturity_window": txt(d.get("probable_maturity_window"), 160),
        "maturity_drivers": txt(d.get("maturity_drivers"), 400),
        "overall_status": txt(d.get("overall_status"), 60),
        "health_score": num(d.get("health_score"), default=60),
        "danger_alarm": bool(d.get("danger_alarm")),
        "danger_reason": txt(d.get("danger_reason"), 300) or None,
        "endangered_zone": zone if zone in ZONES else "none",
        "endangered_zone_detail": txt(d.get("endangered_zone_detail"), 400),
        "nutrients": {k: num(n.get(k)) for k in
                      ("nitrogen_pct", "phosphorus_pct", "potassium_pct", "magnesium_pct", "iron_pct")}
        | {"status_summary": txt(n.get("status_summary"), 300)},
        "water_composition": {"hydration_pct": num(w.get("hydration_pct")),
                              "turgor_status": txt(w.get("turgor_status"), 60),
                              "recommendation": txt(w.get("recommendation"), 300)},
        "fertilizer_and_manure": ferts,
        "pests_and_insects": pests,
        "summary": txt(d.get("summary"), 500),
    }


def enforce_thresholds(a):
    """Admin-set rules are applied deterministically after the model answers."""
    s = S()
    mult = float(s["chlorophyll_sensitivity"])
    nut = a["nutrients"]
    nut["nitrogen_pct"] = num(nut["nitrogen_pct"] * mult)
    reasons = []
    if a["health_score"] < s["min_health_score"]:
        reasons.append(f"Health score {a['health_score']}% is below the {s['min_health_score']}% limit")
    if a["water_composition"]["hydration_pct"] < s["min_water_pct"]:
        reasons.append(f"Hydration {a['water_composition']['hydration_pct']}% is below {s['min_water_pct']}%")
    if nut["nitrogen_pct"] < s["min_nitrogen_pct"]:
        reasons.append(f"Nitrogen {nut['nitrogen_pct']}% is critically low")
    if nut["potassium_pct"] < s["min_potassium_pct"]:
        reasons.append(f"Potassium {nut['potassium_pct']}% is critically low")
    if any(p["severity"].lower() == "high" for p in a["pests_and_insects"]):
        reasons.append("Severe pest or disease pressure")
    if reasons or a["danger_alarm"]:
        a["danger_alarm"] = True
        a["danger_reason"] = a["danger_reason"] or " • ".join(reasons)
        if a["endangered_zone"] == "none":
            a["endangered_zone"] = "lower_leaves"
    return a


# ---------------------------------------------------------------------- images
def process_image(raw):
    img = Image.open(io.BytesIO(raw))
    img.verify()
    img = Image.open(io.BytesIO(raw))
    img = ImageOps.exif_transpose(img).convert("RGB")  # also drops GPS/EXIF
    img.thumbnail((1280, 1280))
    out = io.BytesIO()
    img.save(out, "JPEG", quality=82, optimize=True)
    return out.getvalue()


def record_view(r, admin=False):
    rec = {
        "id": r["id"], "created_at": r["created_at"], "image_url": f"/uploads/{r['image']}",
        "crop_hint": r["crop_hint"], "notes": r["notes"], "latency_ms": r["latency_ms"],
        "status": r["status"], "analysis": json.loads(r["analysis"]) if r["analysis"] else None,
    }
    if rec["analysis"] is not None:
        rec["analysis"]["engine"] = r["engine"]
    if admin:
        rec.update({"client_id": r["client_id"], "ip_hash": r["ip_hash"], "device": r["device"],
                    "lang": r["lang"], "error": r["error"]})
    return rec


def delete_image(name):
    if name and re.fullmatch(r"[0-9a-f]{16}\.jpg", name):
        try:
            os.remove(os.path.join(UPLOAD_DIR, name))
        except OSError:
            pass


# ------------------------------------------------------------------ public routes
def page(name):
    resp = send_from_directory(os.path.join(BASE_DIR, "templates"), name)
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.route("/")
@app.route("/r/<rid>")
def index(rid=None):
    return page("index.html")


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /admin\nDisallow: /api/\nDisallow: /uploads/\n", mimetype="text/plain")


@app.route("/sw.js")
def service_worker():
    resp = send_from_directory(os.path.join(BASE_DIR, "static"), "sw.js")
    resp.headers["Service-Worker-Allowed"] = "/"
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.route("/manifest.webmanifest")
def manifest():
    return send_from_directory(os.path.join(BASE_DIR, "static"), "manifest.webmanifest",
                               mimetype="application/manifest+json")


@app.route("/uploads/<name>")
def uploads(name):
    if not re.fullmatch(r"[0-9a-f]{16}\.jpg", name):
        return "Not found", 404
    resp = send_from_directory(UPLOAD_DIR, name, mimetype="image/jpeg")
    resp.headers["Cache-Control"] = "public, max-age=604800, immutable"
    return resp


@app.route("/api/public-config")
def public_config():
    s = S()
    return jsonify({"name": s["public_name"], "announcement": s["announcement"],
                    "maintenance": s["maintenance_mode"], "ai_ready": ai_ready(),
                    "languages": LANGS, "max_mb": s["max_upload_mb"], "contact": s["contact_email"]})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    s = S()
    if s["maintenance_mode"]:
        return json_error("FieldLens is briefly under maintenance. Please try again soon.", 503)
    if not ai_ready():
        log("ERROR", "CONFIG", "Scan attempted but no AI API key is configured.")
        return json_error("The diagnosis engine is not available right now. Please try again later.", 503)

    db, ip_hash, t = get_db(), client_ip_hash(), now()
    used = db.execute("SELECT COUNT(*) FROM scans WHERE ip_hash=? AND created_at>? AND status IN ('ok','error','not_plant')",
                      (ip_hash, t - 3600)).fetchone()[0]
    if used >= s["scans_per_ip_per_hour"]:
        return json_error(f"Scan limit reached ({s['scans_per_ip_per_hour']} per hour). Please try again later.", 429)
    day = db.execute("SELECT COUNT(*) FROM scans WHERE created_at>? AND status IN ('ok','error','not_plant')",
                     (t - 86400,)).fetchone()[0]
    if day >= s["global_scans_per_day"]:
        log("WARN", "LIMIT", "Global daily scan cap reached.")
        return json_error("FieldLens has reached today's free capacity. Please come back tomorrow.", 429)

    f = request.files.get("photo")
    if not f:
        return json_error("No photo received.", 400)
    raw = f.read()
    if len(raw) > s["max_upload_mb"] * 1024 * 1024:
        return json_error(f"Photo is larger than {s['max_upload_mb']} MB.", 413)
    try:
        jpeg = process_image(raw)
    except Exception:
        return json_error("That file could not be read as a photo. Please use a JPG, PNG or WebP image.", 400)

    sid = uuid.uuid4().hex[:16]
    fname = f"{sid}.jpg"
    with open(os.path.join(UPLOAD_DIR, fname), "wb") as fh:
        fh.write(jpeg)

    crop = request.form.get("crop", "").strip()[:80]
    notes = request.form.get("notes", "").strip()[:400]
    lang = request.form.get("lang", "en")
    lang = lang if lang in LANGS else "en"
    client_id = re.sub(r"[^A-Za-z0-9\-]", "", request.form.get("client_id", ""))[:40]
    device = (request.user_agent.platform or "unknown")[:30]

    t0 = time.time()
    analysis, engine, status, err = None, "", "ok", None
    try:
        raw_data, engine = run_ai(jpeg, crop, notes, lang)
        analysis = enforce_thresholds(normalize(raw_data))
        if not analysis["is_plant"]:
            status = "not_plant"
    except Exception as e:
        status, err = "error", scrub(f"{type(e).__name__}: {e}")[:400]
        log("ERROR", "VISION", err)
    latency = int((time.time() - t0) * 1000)

    db.execute("INSERT INTO scans(id,created_at,ip_hash,client_id,device,lang,crop_hint,notes,image,latency_ms,engine,"
               "status,danger,health,plant,analysis,error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (sid, t, ip_hash, client_id, device, lang, crop, notes, fname, latency, engine, status,
                int(bool(analysis and analysis["danger_alarm"])), analysis["health_score"] if analysis else None,
                analysis["plant_name"] if analysis else None, json.dumps(analysis) if analysis else None, err))
    db.commit()

    if status == "error":
        return json_error("We could not analyze that photo right now. Please try again in a moment.", 502)
    if status == "not_plant":
        return json_error("We could not see a plant in that photo. " + (analysis["retake_tip"] or
                          "Move closer to a leaf or the whole plant in good daylight and try again."), 422)
    log("INFO", "VISION", f"{analysis['plant_name']} analysed in {latency}ms (alarm={analysis['danger_alarm']})")
    row = db.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    return jsonify({"ok": True, "record": record_view(row)})


@app.route("/api/scan/<sid>")
def api_scan_get(sid):
    if not re.fullmatch(r"[0-9a-f]{16}", sid):
        return json_error("Not found", 404)
    r = get_db().execute("SELECT * FROM scans WHERE id=? AND status='ok'", (sid,)).fetchone()
    return jsonify({"ok": True, "record": record_view(r)}) if r else json_error("Not found", 404)


@app.route("/api/scans")
def api_scans():
    ids = [i for i in request.args.get("ids", "").split(",") if re.fullmatch(r"[0-9a-f]{16}", i)][:40]
    if not ids:
        return jsonify([])
    q = ",".join("?" * len(ids))
    rows = get_db().execute(f"SELECT * FROM scans WHERE status='ok' AND id IN ({q}) ORDER BY created_at DESC", ids)
    return jsonify([record_view(r) for r in rows])


@app.route("/api/feedback", methods=["POST"])
def api_feedback():
    d = request.get_json(silent=True) or {}
    sid = str(d.get("scan_id", ""))
    if not re.fullmatch(r"[0-9a-f]{16}", sid) or not get_db().execute("SELECT 1 FROM scans WHERE id=?", (sid,)).fetchone():
        return json_error("Unknown scan", 404)
    get_db().execute("INSERT INTO feedback(scan_id,created_at,helpful,comment) VALUES(?,?,?,?)",
                     (sid, now(), 1 if d.get("helpful") else 0, txt(d.get("comment"), 500)))
    get_db().commit()
    return jsonify({"ok": True})


# ------------------------------------------------------------------- admin auth
def admin_password_ok(pw):
    h = S()["admin_password_hash"]
    if h:
        return check_password_hash(h, pw)
    env = os.getenv("ADMIN_PASSWORD", "")
    return bool(env) and hmac.compare_digest(env.encode(), pw.encode())


def admin_configured():
    return bool(S()["admin_password_hash"] or os.getenv("ADMIN_PASSWORD"))


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("admin"):
            return json_error("Please sign in.", 401)
        if request.method != "GET" and request.headers.get("X-FL-Admin") != "1":
            return json_error("Bad request.", 400)  # CSRF guard: custom header forces a CORS preflight
        return fn(*a, **kw)
    return wrapper


@app.route("/admin")
def admin_page():
    return page("admin.html")


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    if not admin_configured():
        return json_error("Admin is disabled: set the ADMIN_PASSWORD environment variable on the server.", 503)
    db, ip_hash = get_db(), client_ip_hash()
    db.execute("DELETE FROM login_attempts WHERE ts<?", (now() - 900,))
    fails = db.execute("SELECT COUNT(*) FROM login_attempts WHERE ip_hash=?", (ip_hash,)).fetchone()[0]
    if fails >= 5:
        return json_error("Too many attempts. Try again in 15 minutes.", 429)
    pw = str((request.get_json(silent=True) or {}).get("password", ""))
    if admin_password_ok(pw):
        db.execute("DELETE FROM login_attempts WHERE ip_hash=?", (ip_hash,))
        db.commit()
        session.clear()
        session.permanent = True
        session["admin"] = True
        log("INFO", "ADMIN", "Admin signed in.")
        return jsonify({"ok": True})
    db.execute("INSERT INTO login_attempts(ip_hash,ts) VALUES(?,?)", (ip_hash, now()))
    db.commit()
    log("WARN", "ADMIN", "Failed admin login attempt.")
    return json_error("Incorrect password.", 401)


@app.route("/api/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/admin/session")
def admin_session():
    return jsonify({"signed_in": bool(session.get("admin")), "configured": admin_configured()})


@app.route("/api/admin/password", methods=["POST"])
@admin_required
def admin_password():
    d = request.get_json(silent=True) or {}
    if not admin_password_ok(str(d.get("current", ""))):
        return json_error("Current password is incorrect.", 403)
    new = str(d.get("new", ""))
    if len(new) < 10:
        return json_error("New password must be at least 10 characters.", 400)
    set_setting("admin_password_hash", generate_password_hash(new))
    log("INFO", "ADMIN", "Admin password changed.")
    return jsonify({"ok": True})


# ------------------------------------------------------------------ admin data
@app.route("/api/admin/overview")
@admin_required
def admin_overview():
    db, t, s = get_db(), now(), S()
    q = lambda sql, *p: db.execute(sql, p).fetchone()[0]
    ok = "status IN ('ok','not_plant')"
    total = q("SELECT COUNT(*) FROM scans")
    daily = db.execute("SELECT strftime('%Y-%m-%d', created_at,'unixepoch') d, COUNT(*) c FROM scans "
                       "WHERE created_at>? GROUP BY d ORDER BY d", (t - 14 * 86400,)).fetchall()
    top = db.execute("SELECT plant, COUNT(*) c, ROUND(AVG(health)) h FROM scans WHERE plant IS NOT NULL "
                     "GROUP BY plant ORDER BY c DESC LIMIT 8").fetchall()
    fb = db.execute("SELECT COUNT(*), COALESCE(SUM(helpful),0) FROM feedback").fetchone()
    return jsonify({
        "ai_ready": ai_ready(), "provider": s["ai_provider"],
        "model": s["openai_model"] if s["ai_provider"] == "openai" else s["gemini_model"],
        "maintenance": s["maintenance_mode"],
        "total": total, "last_24h": q("SELECT COUNT(*) FROM scans WHERE created_at>?", t - 86400),
        "last_7d": q("SELECT COUNT(*) FROM scans WHERE created_at>?", t - 7 * 86400),
        "devices": q("SELECT COUNT(DISTINCT client_id) FROM scans WHERE client_id!=''"),
        "danger": q("SELECT COUNT(*) FROM scans WHERE danger=1"),
        "errors": q("SELECT COUNT(*) FROM scans WHERE status='error'"),
        "not_plant": q("SELECT COUNT(*) FROM scans WHERE status='not_plant'"),
        "avg_latency_ms": int(q(f"SELECT COALESCE(AVG(latency_ms),0) FROM scans WHERE status='ok'")),
        "avg_health": int(q("SELECT COALESCE(AVG(health),0) FROM scans WHERE status='ok'")),
        "daily_cap": s["global_scans_per_day"],
        "daily": [{"day": r["d"], "count": r["c"]} for r in daily],
        "top_crops": [{"plant": r["plant"], "count": r["c"], "avg_health": r["h"]} for r in top],
        "feedback": {"total": fb[0], "helpful": fb[1]},
        "disk_mb": round(sum(os.path.getsize(os.path.join(UPLOAD_DIR, f)) for f in os.listdir(UPLOAD_DIR)) / 1e6, 1),
    })


@app.route("/api/admin/scans")
@admin_required
def admin_scans():
    where, p = ["1=1"], []
    st = request.args.get("status", "")
    if st in ("ok", "error", "not_plant"):
        where.append("status=?"); p.append(st)
    if request.args.get("danger") == "1":
        where.append("danger=1")
    qs = request.args.get("q", "").strip()[:60]
    if qs:
        where.append("(plant LIKE ? OR crop_hint LIKE ? OR notes LIKE ?)"); p += [f"%{qs}%"] * 3
    limit = min(int(request.args.get("limit", 25) or 25), 100)
    offset = max(int(request.args.get("offset", 0) or 0), 0)
    w = " AND ".join(where)
    total = get_db().execute(f"SELECT COUNT(*) FROM scans WHERE {w}", p).fetchone()[0]
    rows = get_db().execute(f"SELECT * FROM scans WHERE {w} ORDER BY created_at DESC LIMIT ? OFFSET ?", p + [limit, offset])
    return jsonify({"total": total, "scans": [record_view(r, admin=True) for r in rows]})


@app.route("/api/admin/scans/<sid>", methods=["DELETE"])
@admin_required
def admin_scan_delete(sid):
    r = get_db().execute("SELECT image FROM scans WHERE id=?", (sid,)).fetchone()
    if not r:
        return json_error("Not found", 404)
    delete_image(r["image"])
    get_db().execute("DELETE FROM scans WHERE id=?", (sid,))
    get_db().execute("DELETE FROM feedback WHERE scan_id=?", (sid,))
    get_db().commit()
    log("INFO", "ADMIN", f"Deleted scan {sid}")
    return jsonify({"ok": True})


def csv_safe(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


@app.route("/api/admin/export.csv")
@admin_required
def admin_export():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "time_utc", "status", "plant", "health", "danger", "latency_ms", "engine", "lang", "crop_hint", "notes", "device"])
    for r in get_db().execute("SELECT * FROM scans ORDER BY created_at DESC"):
        w.writerow([r["id"], datetime.fromtimestamp(r["created_at"], timezone.utc).isoformat(), r["status"],
                    csv_safe(r["plant"]), r["health"], r["danger"], r["latency_ms"], r["engine"], r["lang"],
                    csv_safe(r["crop_hint"]), csv_safe(r["notes"]), csv_safe(r["device"])])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=fieldlens_scans.csv"})


@app.route("/api/admin/feedback")
@admin_required
def admin_feedback():
    rows = get_db().execute("SELECT f.*, s.plant, s.image FROM feedback f LEFT JOIN scans s ON s.id=f.scan_id "
                            "ORDER BY f.created_at DESC LIMIT 200")
    return jsonify([{"scan_id": r["scan_id"], "created_at": r["created_at"], "helpful": bool(r["helpful"]),
                     "comment": r["comment"], "plant": r["plant"], "image_url": f"/uploads/{r['image']}" if r["image"] else None}
                    for r in rows])


@app.route("/api/admin/logs")
@admin_required
def admin_logs():
    rows = get_db().execute("SELECT ts,level,source,message FROM logs ORDER BY id DESC LIMIT 200")
    return jsonify([dict(r) for r in rows])


# --------------------------------------------------------------- admin settings
def mask(provider):
    k = api_key(provider)
    return {"set": bool(k), "source": key_source(provider), "tail": k[-4:] if len(k) > 8 else ""}


@app.route("/api/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "GET":
        s = S()
        out = {k: s[k] for k in EDITABLE}
        out["keys"] = {"openai": mask("openai"), "gemini": mask("gemini")}
        return jsonify(out)

    d = request.get_json(silent=True) or {}
    changed = []
    for k, rule in EDITABLE.items():
        if k not in d:
            continue
        v, kind = d[k], rule[0]
        try:
            if kind == "int":
                v = int(v); assert rule[1] <= v <= rule[2]
            elif kind == "float":
                v = float(v); assert rule[1] <= v <= rule[2]
            elif kind == "bool":
                v = bool(v)
            elif kind == "choice":
                assert v in rule[1]
            else:
                v = str(v).strip()[:rule[1]]
        except (ValueError, TypeError, AssertionError):
            return json_error(f"Invalid value for {k}.", 400)
        set_setting(k, v); changed.append(k)
    for p in ("openai", "gemini"):
        newk = str(d.get(f"{p}_api_key", "")).strip()
        if newk:
            set_setting(f"{p}_api_key", newk); changed.append(f"{p}_api_key")
        if d.get(f"clear_{p}_key"):
            set_setting(f"{p}_api_key", ""); changed.append(f"{p}_api_key(cleared)")
    log("INFO", "ADMIN", "Settings updated: " + ", ".join(changed or ["(none)"]))
    return jsonify({"ok": True, "changed": changed})


@app.route("/api/admin/test-ai", methods=["POST"])
@admin_required
def admin_test_ai():
    prov = S()["ai_provider"]
    if not api_key(prov):
        return json_error(f"No {prov} API key is set.", 400)
    t0 = time.time()
    try:
        if prov == "openai":
            from openai import OpenAI
            r = OpenAI(api_key=api_key("openai"), timeout=30, max_retries=0).responses.create(
                model=S()["openai_model"], input="Reply with the single word: OK")
            reply = r.output_text
        else:
            from google import genai
            reply = genai.Client(api_key=api_key("gemini")).models.generate_content(
                model=S()["gemini_model"], contents="Reply with the single word: OK").text
        ms = int((time.time() - t0) * 1000)
        log("INFO", "ADMIN", f"AI connection test passed ({prov}, {ms}ms)")
        return jsonify({"ok": True, "latency_ms": ms, "reply": txt(reply, 40)})
    except Exception as e:
        msg = scrub(f"{type(e).__name__}: {e}")[:300]
        log("ERROR", "ADMIN", "AI connection test failed: " + msg)
        return json_error(msg, 502)


@app.route("/api/admin/maintenance", methods=["POST"])
@admin_required
def admin_maintenance():
    d = request.get_json(silent=True) or {}
    act, db = d.get("action"), get_db()
    if act == "purge_older_than":
        days = max(1, int(d.get("days", 90)))
        rows = db.execute("SELECT id,image FROM scans WHERE created_at<?", (now() - days * 86400,)).fetchall()
        for r in rows:
            delete_image(r["image"])
        db.execute("DELETE FROM scans WHERE created_at<?", (now() - days * 86400,))
        db.execute("DELETE FROM feedback WHERE scan_id NOT IN (SELECT id FROM scans)")
        db.commit()
        log("WARN", "ADMIN", f"Purged {len(rows)} scans older than {days} days")
        return jsonify({"ok": True, "deleted": len(rows)})
    if act == "delete_all_scans":
        for r in db.execute("SELECT image FROM scans"):
            delete_image(r["image"])
        db.execute("DELETE FROM scans"); db.execute("DELETE FROM feedback"); db.commit()
        log("WARN", "ADMIN", "Deleted ALL scans")
        return jsonify({"ok": True})
    if act == "clear_logs":
        db.execute("DELETE FROM logs"); db.commit()
        return jsonify({"ok": True})
    return json_error("Unknown action", 400)


@app.route("/api/admin/qr.svg")
@admin_required
def admin_qr():
    url = request.args.get("url") or request.host_url
    if qrcode is None:
        return Response("<svg xmlns='http://www.w3.org/2000/svg'/>", mimetype="image/svg+xml")
    img = qrcode.make(url[:300], image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return Response(buf.getvalue(), mimetype="image/svg+xml")


init_db()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    print(f"FieldLens Pro running on http://localhost:{port}  (admin: /admin)")
    if not os.getenv("ADMIN_PASSWORD"):
        print("WARNING: ADMIN_PASSWORD is not set — /admin login is disabled.")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
