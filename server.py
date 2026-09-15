#!/usr/bin/env python3
"""
WhatsApp Market - Backend API
Supports SQLite (local) and PostgreSQL (production).
Includes simple seller authentication (JWT).
"""

import os
import sqlite3
import requests
import secrets as pysecrets
import hashlib
import secrets
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from flask_cors import CORS

# ---------- Configuration ----------
from pathlib import Path

class Config:
    """Base configuration"""
    BASE_DIR = Path(__file__).parent.absolute()
    UPLOAD_FOLDER = BASE_DIR / "uploads"
    
    # Core settings
    PORT = int(os.environ.get("PORT", 5000))
    JWT_EXPIRE_HOURS = 72
    
    # Database
    DATABASE_URL = os.environ.get("DATABASE_URL")
    SQLITE_PATH = BASE_DIR / "marketplace.db"
    USE_POSTGRES = bool(DATABASE_URL)
    REQUIRE_POSTGRES = os.environ.get("REQUIRE_POSTGRES", "0") == "1"
    if REQUIRE_POSTGRES and not USE_POSTGRES:
        raise SystemExit(
            "REQUIRE_POSTGRES=1 but DATABASE_URL is not set. "
            "Attach Railway PostgreSQL and set DATABASE_URL, or remove REQUIRE_POSTGRES."
        )
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "mp4", "webm", "mov", "ogg", "pdf"}

# Load configuration
config = Config()

# Database configuration (for compatibility)
BASE_DIR = str(config.BASE_DIR)
PORT = config.PORT
JWT_EXPIRE_HOURS = config.JWT_EXPIRE_HOURS
DATABASE_URL = config.DATABASE_URL
SQLITE_PATH = str(config.SQLITE_PATH)
USE_POSTGRES = config.USE_POSTGRES
REQUIRE_POSTGRES = config.REQUIRE_POSTGRES
UPLOAD_FOLDER = str(config.UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = config.ALLOWED_EXTENSIONS

# Secrets (MUST come from environment variables—no defaults)
JWT_SECRET = os.environ.get("JWT_SECRET")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET")
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_MAILTO = os.environ.get("VAPID_MAILTO", "mailto:admin@sungarland.com")

# Validate production environment
if os.environ.get("FLASK_ENV") == "production":
    required_env_vars = ["JWT_SECRET", "ADMIN_SECRET"]
    missing = [var for var in required_env_vars if not os.environ.get(var)]
    if missing:
        raise SystemExit(f"Production mode: Missing required environment variables: {', '.join(missing)}")

# Initialize upload folder
config.UPLOAD_FOLDER.mkdir(exist_ok=True)
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB max (for videos)
CORS(app, supports_credentials=True)
# ---------- Database helpers ----------
def get_db():
    if "db" not in g:
        if USE_POSTGRES:
            import psycopg2
            import psycopg2.extras
            url = DATABASE_URL
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql://", 1)
            g.db = psycopg2.connect(url)
            g.db.autocommit = False
        else:
            g.db = sqlite3.connect(SQLITE_PATH)
            g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def execute(query, params=None, fetchone=False, fetchall=False, commit=False):
    """Simple cross-db helper."""
    db = get_db()
    params = params or ()

    if USE_POSTGRES:
        import psycopg2.extras
        cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        pg_query = query.replace("?", "%s")
        cur.execute(pg_query, params)
        if commit:
            db.commit()
        if fetchone:
            row = cur.fetchone()
            return dict(row) if row else None
        if fetchall:
            return [dict(r) for r in cur.fetchall()]
        return cur
    else:
        cur = db.execute(query, params)
        if commit:
            db.commit()
        if fetchone:
            row = cur.fetchone()
            return dict(row) if row else None
        if fetchall:
            return [dict(r) for r in cur.fetchall()]
        return cur


def init_db():
    """Create tables and seed sample data if empty."""
    if USE_POSTGRES:
        execute("""
            CREATE TABLE IF NOT EXISTS sellers (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                shop_name TEXT NOT NULL,
                whatsapp TEXT NOT NULL,
                is_blocked INTEGER DEFAULT 0,
                full_name TEXT,
                id_number TEXT,
                address TEXT,
                id_document_url TEXT,
                selfie_url TEXT,
                kyc_status TEXT DEFAULT 'none',
                kyc_submitted_at TEXT,
                subscription_expires_at TEXT,
                created_at TEXT NOT NULL
            )
        """, commit=True)
        execute("""
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                seller TEXT NOT NULL,
                whatsapp TEXT NOT NULL,
                image TEXT,
                video_url TEXT,
                seller_id INTEGER REFERENCES sellers(id),
                created_at TEXT NOT NULL
            )
        """, commit=True)
    else:
        execute("""
            CREATE TABLE IF NOT EXISTS sellers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                shop_name TEXT NOT NULL,
                whatsapp TEXT NOT NULL,
                is_blocked INTEGER DEFAULT 0,
                full_name TEXT,
                id_number TEXT,
                address TEXT,
                id_document_url TEXT,
                selfie_url TEXT,
                kyc_status TEXT DEFAULT 'none',
                kyc_submitted_at TEXT,
                subscription_expires_at TEXT,
                created_at TEXT NOT NULL
            )
        """, commit=True)
        execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                seller TEXT NOT NULL,
                whatsapp TEXT NOT NULL,
                image TEXT,
                video_url TEXT,
                seller_id INTEGER,
                created_at TEXT NOT NULL,
                FOREIGN KEY (seller_id) REFERENCES sellers(id)
            )
        """, commit=True)

        execute("""
            CREATE TABLE IF NOT EXISTS buyers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                selfie_url TEXT,
                kyc_status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL
            )
        """, commit=True)


    
    # Ensure is_blocked column exists (for existing databases)
    try:
        if USE_POSTGRES:
            execute("ALTER TABLE sellers ADD COLUMN IF NOT EXISTS is_blocked INTEGER DEFAULT 0", commit=True)
        else:
            # SQLite doesn't support IF NOT EXISTS for columns easily
            cols = execute("PRAGMA table_info(sellers)", fetchall=True)
            col_names = [c["name"] for c in (cols or [])]
            if "is_blocked" not in col_names:
                execute("ALTER TABLE sellers ADD COLUMN is_blocked INTEGER DEFAULT 0", commit=True)
    except Exception as e:
        print(f"Note: column check - {e}")

    
    # Ratings and Comments tables
    try:
        if USE_POSTGRES:
            execute("""
                CREATE TABLE IF NOT EXISTS ratings (
                    id SERIAL PRIMARY KEY,
                    product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
                    author_name TEXT NOT NULL,
                    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
                    created_at TEXT NOT NULL
                )
            """, commit=True)
            execute("""
                CREATE TABLE IF NOT EXISTS comments (
                    id SERIAL PRIMARY KEY,
                    product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
                    author_name TEXT NOT NULL,
                    comment TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """, commit=True)
        else:
            execute("""
                CREATE TABLE IF NOT EXISTS ratings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    author_name TEXT NOT NULL,
                    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (product_id) REFERENCES products(id)
                )
            """, commit=True)
            execute("""
                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    author_name TEXT NOT NULL,
                    comment TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (product_id) REFERENCES products(id)
                )
            """, commit=True)
    except Exception as e:
        print(f"Ratings/Comments table note: {e}")

    # Ensure video_url column exists
    try:
        if USE_POSTGRES:
            execute("ALTER TABLE products ADD COLUMN IF NOT EXISTS video_url TEXT", commit=True)
        else:
            cols = execute("PRAGMA table_info(products)", fetchall=True)
            col_names = [c["name"] for c in (cols or [])]
            if "video_url" not in col_names:
                execute("ALTER TABLE products ADD COLUMN video_url TEXT", commit=True)
    except Exception as e:
        print(f"video_url column note: {e}")

    
    # Inquiries (Buy clicks) table
    try:
        if USE_POSTGRES:
            execute("""
                CREATE TABLE IF NOT EXISTS inquiries (
                    id SERIAL PRIMARY KEY,
                    product_id INTEGER,
                    product_name TEXT,
                    seller_name TEXT,
                    buyer_name TEXT,
                    created_at TEXT NOT NULL
                )
            """, commit=True)
        else:
            execute("""
                CREATE TABLE IF NOT EXISTS inquiries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER,
                    product_name TEXT,
                    seller_name TEXT,
                    buyer_name TEXT,
                    created_at TEXT NOT NULL
                )
            """, commit=True)
    except Exception as e:
        print(f"Inquiries table note: {e}")

    
    # App settings (subscription prices etc.)
    try:
        if USE_POSTGRES:
            execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """, commit=True)
        else:
            execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """, commit=True)

        # Default prices in Ghana Cedis (GHS)
        existing = execute("SELECT key FROM settings WHERE key = 'price_first'", fetchone=True)
        if not existing:
            execute("INSERT INTO settings (key, value) VALUES ('price_first', '50')", commit=True)
            execute("INSERT INTO settings (key, value) VALUES ('price_renewal', '100')", commit=True)
            execute("INSERT INTO settings (key, value) VALUES ('currency', 'GHS')", commit=True)
    except Exception as e:
        print(f"Settings table note: {e}")

    
    # Orders table (for online payments)
    try:
        if USE_POSTGRES:
            execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    id SERIAL PRIMARY KEY,
                    product_id INTEGER,
                    product_name TEXT,
                    product_price REAL,
                    seller_name TEXT,
                    seller_whatsapp TEXT,
                    buyer_name TEXT,
                    buyer_email TEXT,
                    buyer_phone TEXT,
                    amount REAL,
                    currency TEXT DEFAULT 'GHS',
                    payment_reference TEXT UNIQUE,
                    payment_status TEXT DEFAULT 'pending',
                    created_at TEXT NOT NULL
                )
            """, commit=True)
        else:
            execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER,
                    product_name TEXT,
                    product_price REAL,
                    seller_name TEXT,
                    seller_whatsapp TEXT,
                    buyer_name TEXT,
                    buyer_email TEXT,
                    buyer_phone TEXT,
                    amount REAL,
                    currency TEXT DEFAULT 'GHS',
                    payment_reference TEXT UNIQUE,
                    payment_status TEXT DEFAULT 'pending',
                    created_at TEXT NOT NULL
                )
            """, commit=True)
    except Exception as e:
        print(f"Orders table note: {e}")

    # Default Paystack settings
    try:
        if not execute("SELECT key FROM settings WHERE key = 'paystack_public_key'", fetchone=True):
            execute("INSERT INTO settings (key, value) VALUES ('paystack_public_key', '')", commit=True)
            execute("INSERT INTO settings (key, value) VALUES ('paystack_secret_key', '')", commit=True)
            execute("INSERT INTO settings (key, value) VALUES ('paystack_enabled', '0')", commit=True)
    except Exception as e:
        print(f"Paystack settings note: {e}")

    
    # Houses & Hostels (no online payment)
    try:
        if USE_POSTGRES:
            execute("""
                CREATE TABLE IF NOT EXISTS properties (
                    id SERIAL PRIMARY KEY,
                    title TEXT NOT NULL,
                    property_type TEXT NOT NULL,
                    location TEXT NOT NULL,
                    price TEXT,
                    description TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    agent_whatsapp TEXT NOT NULL,
                    agent_id INTEGER,
                    image TEXT,
                    video_url TEXT,
                    is_available INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL
                )
            """, commit=True)
        else:
            execute("""
                CREATE TABLE IF NOT EXISTS properties (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    property_type TEXT NOT NULL,
                    location TEXT NOT NULL,
                    price TEXT,
                    description TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    agent_whatsapp TEXT NOT NULL,
                    agent_id INTEGER,
                    image TEXT,
                    video_url TEXT,
                    is_available INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL
                )
            """, commit=True)
    except Exception as e:
        print(f"Properties table note: {e}")

    
    # Auth enhancement columns
    try:
        auth_cols = [
            ("email_verified", "INTEGER DEFAULT 0"),
            ("verification_token", "TEXT"),
            ("reset_token", "TEXT"),
            ("reset_token_expires", "TEXT"),
            ("failed_login_attempts", "INTEGER DEFAULT 0"),
            ("locked_until", "TEXT"),
            ("full_name_profile", "TEXT"),
            ("bio", "TEXT"),
            ("profile_image", "TEXT"),
            ("terms_accepted_at", "TEXT"),
        ]
        if USE_POSTGRES:
            for col, typedef in auth_cols:
                execute(f"ALTER TABLE sellers ADD COLUMN IF NOT EXISTS {col} {typedef}", commit=True)
        else:
            cols = execute("PRAGMA table_info(sellers)", fetchall=True)
            col_names = [c["name"] for c in (cols or [])]
            for col, typedef in auth_cols:
                if col not in col_names:
                    execute(f"ALTER TABLE sellers ADD COLUMN {col} {typedef}", commit=True)
    except Exception as e:
        print(f"Auth columns note: {e}")

    # Agent (Houses & Hostels) verification columns
    try:
        agent_cols = [
            ("agent_doc_url", "TEXT"),
            ("agent_license_number", "TEXT"),
            ("agent_status", "TEXT DEFAULT 'none'"),
            ("agent_submitted_at", "TEXT"),
        ]
        if USE_POSTGRES:
            for col, typedef in agent_cols:
                execute(f"ALTER TABLE sellers ADD COLUMN IF NOT EXISTS {col} {typedef}", commit=True)
        else:
            cols = execute("PRAGMA table_info(sellers)", fetchall=True)
            col_names = [c["name"] for c in (cols or [])]
            for col, typedef in agent_cols:
                if col not in col_names:
                    execute(f"ALTER TABLE sellers ADD COLUMN {col} {typedef}", commit=True)
    except Exception as e:
        print(f"Agent verification columns note: {e}")


    
    # Chat, notifications, page views
    try:
        if USE_POSTGRES:
            execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id SERIAL PRIMARY KEY,
                    product_id INTEGER,
                    property_id INTEGER,
                    buyer_name TEXT NOT NULL,
                    buyer_email TEXT,
                    seller_id INTEGER,
                    subject TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """, commit=True)
            execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id SERIAL PRIMARY KEY,
                    conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
                    sender_type TEXT NOT NULL,
                    sender_name TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """, commit=True)
            execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id SERIAL PRIMARY KEY,
                    seller_id INTEGER,
                    title TEXT NOT NULL,
                    body TEXT,
                    link TEXT,
                    is_read INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            """, commit=True)
            execute("""
                CREATE TABLE IF NOT EXISTS page_views (
                    id SERIAL PRIMARY KEY,
                    path TEXT,
                    product_id INTEGER,
                    property_id INTEGER,
                    created_at TEXT NOT NULL
                )
            """, commit=True)
        else:
            execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER,
                    property_id INTEGER,
                    buyer_name TEXT NOT NULL,
                    buyer_email TEXT,
                    seller_id INTEGER,
                    subject TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """, commit=True)
            execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id INTEGER NOT NULL,
                    sender_type TEXT NOT NULL,
                    sender_name TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (conversation_id) REFERENCES conversations(id)
                )
            """, commit=True)
            execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    seller_id INTEGER,
                    title TEXT NOT NULL,
                    body TEXT,
                    link TEXT,
                    is_read INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            """, commit=True)
            execute("""
                CREATE TABLE IF NOT EXISTS page_views (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT,
                    product_id INTEGER,
                    property_id INTEGER,
                    created_at TEXT NOT NULL
                )
            """, commit=True)
    except Exception as e:
        print(f"Chat/notifications tables note: {e}")

    
    # Web Push subscriptions
    try:
        if USE_POSTGRES:
            execute("""
                CREATE TABLE IF NOT EXISTS push_subscriptions (
                    id SERIAL PRIMARY KEY,
                    seller_id INTEGER,
                    endpoint TEXT UNIQUE NOT NULL,
                    p256dh TEXT,
                    auth TEXT,
                    created_at TEXT NOT NULL
                )
            """, commit=True)
        else:
            execute("""
                CREATE TABLE IF NOT EXISTS push_subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    seller_id INTEGER,
                    endpoint TEXT UNIQUE NOT NULL,
                    p256dh TEXT,
                    auth TEXT,
                    created_at TEXT NOT NULL
                )
            """, commit=True)
    except Exception as e:
        print(f"Push subscriptions table note: {e}")

    
    # Reports / disputes
    try:
        if USE_POSTGRES:
            execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id SERIAL PRIMARY KEY,
                    reporter_name TEXT,
                    reporter_email TEXT,
                    target_type TEXT NOT NULL,
                    target_id INTEGER,
                    target_name TEXT,
                    reason TEXT NOT NULL,
                    details TEXT,
                    status TEXT DEFAULT 'open',
                    created_at TEXT NOT NULL
                )
            """, commit=True)
        else:
            execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporter_name TEXT,
                    reporter_email TEXT,
                    target_type TEXT NOT NULL,
                    target_id INTEGER,
                    target_name TEXT,
                    reason TEXT NOT NULL,
                    details TEXT,
                    status TEXT DEFAULT 'open',
                    created_at TEXT NOT NULL
                )
            """, commit=True)
    except Exception as e:
        print(f"Reports table note: {e}")

    count_row = execute("SELECT COUNT(*) as cnt FROM products", fetchone=True)
    count = count_row["cnt"] if count_row else 0

    if count == 0:
        samples = [
            ("Handmade Leather Journal", 34.99, "Handmade",
             "Beautiful A5 leather-bound journal with 200 blank pages of high-quality paper. Perfect for writing, sketching, or as a gift. Hand-stitched binding.",
             "Craft & Co", "15551234567",
             "https://images.unsplash.com/photo-1544947950-fa07a98d237f?w=500&h=400&fit=crop"),
            ("Vintage Bookbinding Kit", 49.00, "Books",
             "Complete starter kit for bookbinding: bone folder, awl, needles, linen thread, and instructional booklet. Ideal for beginners.",
             "BindCraft Studio", "15551234567",
             "https://images.unsplash.com/photo-1512820790803-83ca734da794?w=500&h=400&fit=crop"),
            ("Watercolor Illustration Print", 22.50, "Art",
             "Limited edition A3 fine-art print of an original botanical watercolor illustration. Printed on archival paper.",
             "Luna Art Prints", "15559876543",
             "https://images.unsplash.com/photo-1579783902614-a3fb3927b6a5?w=500&h=400&fit=crop"),
            ("Classic Hardcover Notebook", 18.99, "Books",
             "Elegant hardcover notebook with dotted pages, ribbon marker, and elastic band. 192 pages, cream paper.",
             "Paper House", "15551234567",
             "https://images.unsplash.com/photo-1531346878377-a5be20888e57?w=500&h=400&fit=crop"),
            ("Minimalist Desk Organizer", 39.00, "Home",
             "Solid wood desk organizer with compartments for pens, cards, and small accessories. Natural finish.",
             "Nordic Woodworks", "15557654321",
             "https://images.unsplash.com/photo-1595428774223-ef52624120d2?w=500&h=400&fit=crop"),
            ("Hand-Printed Tote Bag", 27.00, "Fashion",
             "100% cotton tote bag with original linocut print. Strong handles and spacious interior. Eco-friendly.",
             "Print & Carry", "15559876543",
             "https://images.unsplash.com/photo-1590874103328-eac38a674cb2?w=500&h=400&fit=crop"),
        ]
        now = datetime.now(timezone.utc).isoformat()
        for s in samples:
            execute(
                """INSERT INTO products
                   (name, price, category, description, seller, whatsapp, image, seller_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)""",
                (*s, now),
                commit=True,
            )
        print("Database seeded with sample products.")


# ---------- Auth helpers ----------

def send_email(to_email: str, subject: str, body: str) -> bool:
    """Send email via SMTP if configured; otherwise log the message."""
    host = os.environ.get("SMTP_HOST", "")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASS", "")
    mail_from = os.environ.get("MAIL_FROM", user or "noreply@sungarland.com")

    if not host or not user:
        print(f"[EMAIL-DEV] To: {to_email}\nSubject: {subject}\n{body}\n")
        return False

    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = mail_from
        msg["To"] = to_email
        with smtplib.SMTP(host, port, timeout=20) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(mail_from, [to_email], msg.as_string())
        return True
    except Exception as e:
        print(f"[EMAIL-ERROR] {e}")
        print(f"[EMAIL-FALLBACK] To: {to_email}\nSubject: {subject}\n{body}\n")
        return False




def send_web_push_to_seller(seller_id, title, body="", url="/"):
    """Send Web Push to all of a seller's subscribed devices."""
    if not VAPID_PRIVATE_KEY or not VAPID_PUBLIC_KEY:
        return
    try:
        from pywebpush import webpush, WebPushException
        import json as _json
        rows = execute(
            "SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE seller_id = ?",
            (seller_id,), fetchall=True
        ) or []
        payload = _json.dumps({"title": title, "body": body or "", "url": url})
        for row in rows:
            try:
                webpush(
                    subscription_info={
                        "endpoint": row["endpoint"],
                        "keys": {"p256dh": row["p256dh"], "auth": row["auth"]},
                    },
                    data=payload,
                    vapid_private_key=VAPID_PRIVATE_KEY,
                    vapid_claims={"sub": VAPID_MAILTO},
                )
            except Exception as e:
                print(f"Web push to device failed: {e}")
                # Remove gone subscriptions
                if "410" in str(e) or "404" in str(e):
                    try:
                        execute("DELETE FROM push_subscriptions WHERE endpoint = ?", (row["endpoint"],), commit=True)
                    except Exception:
                        pass
    except Exception as e:
        print(f"Web push unavailable: {e}")


def create_notification(seller_id, title, body="", link=""):
    if not seller_id:
        return
    now = datetime.now(timezone.utc).isoformat()
    try:
        execute(
            "INSERT INTO notifications (seller_id, title, body, link, is_read, created_at) VALUES (?, ?, ?, ?, 0, ?)",
            (seller_id, title, body, link, now), commit=True
        )
        send_web_push_to_seller(seller_id, title, body, link or "/")
    except Exception as e:
        print(f"notify error: {e}")



def upload_to_cloudinary(filepath, filename):
    """Upload file to Cloudinary if configured. Returns secure URL or None."""
    cloud_name = os.environ.get("CLOUDINARY_CLOUD_NAME") or get_setting("cloudinary_cloud_name", "")
    api_key = os.environ.get("CLOUDINARY_API_KEY") or get_setting("cloudinary_api_key", "")
    api_secret = os.environ.get("CLOUDINARY_API_SECRET") or get_setting("cloudinary_api_secret", "")
    if not (cloud_name and api_key and api_secret):
        return None
    try:
        import cloudinary
        import cloudinary.uploader
        cloudinary.config(cloud_name=cloud_name, api_key=api_key, api_secret=api_secret, secure=True)
        result = cloudinary.uploader.upload(
            filepath,
            folder="sungarland",
            public_id=filename.rsplit(".", 1)[0],
            resource_type="auto",
        )
        return result.get("secure_url")
    except Exception as e:
        print(f"Cloudinary upload error: {e}")
        return None


def frontend_base_url():
    return os.environ.get("FRONTEND_URL", "http://localhost:5500").rstrip("/")


def hash_password(password: str) -> str:
    """Use Werkzeug PBKDF2 (secure). Also accepts legacy salt$hash format."""
    return generate_password_hash(password)


def verify_password(password: str, stored: str) -> bool:
    if not stored:
        return False
    # Legacy SHA-256 salt$hash format from older versions
    if "$" in stored and not stored.startswith(("pbkdf2:", "scrypt:", "argon2:")):
        try:
            salt, pw_hash = stored.split("$", 1)
            return hashlib.sha256((salt + password).encode()).hexdigest() == pw_hash
        except Exception:
            return False
    try:
        return check_password_hash(stored, password)
    except Exception:
        return False


def create_token(seller_id: int, username: str) -> str:
    payload = {
        "seller_id": seller_id,
        "username": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None





def ensure_vapid_keys():
    global VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY
    if VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY:
        return
    # Try load from settings DB after init - called from init_db end
    try:
        pub = get_setting("vapid_public_key", "")
        priv = get_setting("vapid_private_key", "")
        if pub and priv:
            VAPID_PUBLIC_KEY = pub
            VAPID_PRIVATE_KEY = priv
            return
        from py_vapid import Vapid01
        from cryptography.hazmat.primitives import serialization
        import base64
        v = Vapid01()
        v.generate_keys()
        priv = v.private_pem()
        if isinstance(priv, bytes):
            priv = priv.decode()
        raw = v.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        pub = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        set_setting("vapid_public_key", pub)
        set_setting("vapid_private_key", priv)
        VAPID_PUBLIC_KEY = pub
        VAPID_PRIVATE_KEY = priv
        print("[PUSH] Generated and stored VAPID keys in settings")
    except Exception as e:
        print(f"[PUSH] Could not ensure VAPID keys: {e}")


def get_setting(key, default=None):
    row = execute("SELECT value FROM settings WHERE key = ?", (key,), fetchone=True)
    return row["value"] if row else default

def set_setting(key, value):
    existing = execute("SELECT key FROM settings WHERE key = ?", (key,), fetchone=True)
    if existing:
        execute("UPDATE settings SET value = ? WHERE key = ?", (str(value), key), commit=True)
    else:
        execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, str(value)), commit=True)


def is_subscription_active(seller_row):
    """Return True if seller has an active (non-expired) subscription."""
    if not seller_row:
        return False
    exp = seller_row.get("subscription_expires_at")
    if not exp:
        return False
    try:
        exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        return exp_dt > datetime.now(timezone.utc)
    except Exception:
        return False


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Authentication required"}), 401
        token = auth[7:]
        data = decode_token(token)
        if not data:
            return jsonify({"error": "Invalid or expired token"}), 401
        g.seller_id = data["seller_id"]
        g.username = data["username"]
        return f(*args, **kwargs)
    return decorated


# ---------- Auth Routes ----------

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    required = ["username", "email", "password", "shop_name", "whatsapp"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    if not data.get("terms_accepted"):
        return jsonify({"error": "You must accept the Terms of Service and Privacy Policy"}), 400

    username = data["username"].strip().lower()
    email = data["email"].strip().lower()
    password = data["password"]
    shop_name = data["shop_name"].strip()
    whatsapp = "".join(c for c in str(data["whatsapp"]) if c.isdigit())

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if len(whatsapp) < 8:
        return jsonify({"error": "WhatsApp number looks invalid"}), 400
    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "Invalid email address"}), 400

    existing = execute(
        "SELECT id FROM sellers WHERE username = ? OR email = ?",
        (username, email),
        fetchone=True,
    )
    if existing:
        return jsonify({"error": "Username or email already taken"}), 409

    now = datetime.now(timezone.utc).isoformat()
    pw_hash = hash_password(password)
    verify_token = secrets.token_urlsafe(32)
    trial_end = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()

    if USE_POSTGRES:
        execute(
            """INSERT INTO sellers (username, email, password_hash, shop_name, whatsapp, created_at,
               email_verified, verification_token, subscription_expires_at, terms_accepted_at, failed_login_attempts)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 0)""",
            (username, email, pw_hash, shop_name, whatsapp, now, verify_token, trial_end, now),
            commit=True,
        )
        row = execute("SELECT id FROM sellers WHERE username = ?", (username,), fetchone=True)
        seller_id = row["id"]
    else:
        cur = execute(
            """INSERT INTO sellers (username, email, password_hash, shop_name, whatsapp, created_at,
               email_verified, verification_token, subscription_expires_at, terms_accepted_at, failed_login_attempts)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 0)""",
            (username, email, pw_hash, shop_name, whatsapp, now, verify_token, trial_end, now),
            commit=True,
        )
        seller_id = cur.lastrowid

    verify_url = f"{frontend_base_url()}/?verify_email={verify_token}"
    send_email(
        email,
        "Verify your SunGarland account",
        f"Welcome to SunGarland!\n\nPlease verify your email by opening this link:\n{verify_url}\n\nIf you did not register, ignore this email.",
    )

    token = create_token(seller_id, username)
    resp = {
        "token": token,
        "seller": {
            "id": seller_id,
            "username": username,
            "email": email,
            "shop_name": shop_name,
            "whatsapp": whatsapp,
            "subscription_expires_at": trial_end,
            "email_verified": False,
        },
        "message": "Account created. Please verify your email.",
    }
    # In dev (no SMTP), include link so you can still test
    if not os.environ.get("SMTP_HOST"):
        resp["dev_verify_url"] = verify_url
    return jsonify(resp), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    seller = execute(
        "SELECT * FROM sellers WHERE username = ? OR email = ?",
        (username, username),
        fetchone=True,
    )

    # Brute-force protection
    if seller:
        locked_until = seller.get("locked_until")
        if locked_until:
            try:
                until = datetime.fromisoformat(locked_until.replace("Z", "+00:00"))
                if until.tzinfo is None:
                    until = until.replace(tzinfo=timezone.utc)
                if until > datetime.now(timezone.utc):
                    mins = int((until - datetime.now(timezone.utc)).total_seconds() // 60) + 1
                    return jsonify({"error": f"Account temporarily locked. Try again in {mins} minute(s)."}), 429
            except Exception:
                pass

    if not seller or not verify_password(password, seller["password_hash"]):
        if seller:
            attempts = int(seller.get("failed_login_attempts") or 0) + 1
            locked_until = None
            if attempts >= 5:
                locked_until = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
                attempts = 0
            if locked_until:
                execute(
                    "UPDATE sellers SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
                    (attempts, locked_until, seller["id"]), commit=True
                )
                return jsonify({"error": "Too many failed attempts. Account locked for 15 minutes."}), 429
            execute(
                "UPDATE sellers SET failed_login_attempts = ? WHERE id = ?",
                (attempts, seller["id"]), commit=True
            )
        return jsonify({"error": "Invalid credentials"}), 401

    if seller.get("is_blocked"):
        return jsonify({"error": "Your account has been blocked. Please contact support."}), 403

    # Reset failed attempts on success
    execute(
        "UPDATE sellers SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
        (seller["id"],), commit=True
    )

    token = create_token(seller["id"], seller["username"])
    return jsonify({
        "token": token,
        "seller": {
            "id": seller["id"],
            "username": seller["username"],
            "email": seller["email"],
            "shop_name": seller["shop_name"],
            "whatsapp": seller["whatsapp"],
            "email_verified": bool(seller.get("email_verified")),
            "full_name_profile": seller.get("full_name_profile"),
            "bio": seller.get("bio"),
            "profile_image": seller.get("profile_image"),
        }
    })


@app.route("/api/auth/me", methods=["GET"])
@login_required
def me():
    seller = execute(
        """SELECT id, username, email, shop_name, whatsapp, subscription_expires_at, kyc_status,
                  email_verified, full_name_profile, bio, profile_image, created_at
           FROM sellers WHERE id = ?""",
        (g.seller_id,),
        fetchone=True,
    )
    if not seller:
        return jsonify({"error": "Seller not found"}), 404
    result = dict(seller)
    result["email_verified"] = bool(result.get("email_verified"))
    return jsonify(result)


@app.route("/api/auth/verify-email", methods=["POST"])
def verify_email():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or request.args.get("token") or "").strip()
    if not token:
        return jsonify({"error": "Verification token required"}), 400

    seller = execute(
        "SELECT id, email_verified FROM sellers WHERE verification_token = ?",
        (token,), fetchone=True
    )
    if not seller:
        return jsonify({"error": "Invalid or expired verification link"}), 400
    if seller.get("email_verified"):
        return jsonify({"message": "Email already verified"})

    execute(
        "UPDATE sellers SET email_verified = 1, verification_token = NULL WHERE id = ?",
        (seller["id"],), commit=True
    )
    return jsonify({"message": "Email verified successfully"})


@app.route("/api/auth/resend-verification", methods=["POST"])
@login_required
def resend_verification():
    seller = execute(
        "SELECT id, email, email_verified FROM sellers WHERE id = ?",
        (g.seller_id,), fetchone=True
    )
    if not seller:
        return jsonify({"error": "Not found"}), 404
    if seller.get("email_verified"):
        return jsonify({"message": "Email already verified"})

    verify_token = secrets.token_urlsafe(32)
    execute(
        "UPDATE sellers SET verification_token = ? WHERE id = ?",
        (verify_token, seller["id"]), commit=True
    )
    verify_url = f"{frontend_base_url()}/?verify_email={verify_token}"
    send_email(
        seller["email"],
        "Verify your SunGarland account",
        f"Please verify your email:\n{verify_url}\n",
    )
    resp = {"message": "Verification email sent"}
    if not os.environ.get("SMTP_HOST"):
        resp["dev_verify_url"] = verify_url
    return jsonify(resp)


@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "Email required"}), 400

    # Always return same message to avoid email enumeration
    generic = {"message": "If that email exists, a reset link has been sent."}

    seller = execute("SELECT id, email FROM sellers WHERE email = ?", (email,), fetchone=True)
    if not seller:
        return jsonify(generic)

    reset_token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    execute(
        "UPDATE sellers SET reset_token = ?, reset_token_expires = ? WHERE id = ?",
        (reset_token, expires, seller["id"]), commit=True
    )
    reset_url = f"{frontend_base_url()}/?reset_token={reset_token}"
    send_email(
        email,
        "Reset your SunGarland password",
        f"Click this link to reset your password (valid 1 hour):\n{reset_url}\n\nIf you did not request this, ignore this email.",
    )
    resp = dict(generic)
    if not os.environ.get("SMTP_HOST"):
        resp["dev_reset_url"] = reset_url
    return jsonify(resp)


@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    new_password = data.get("password") or ""

    if not token or not new_password:
        return jsonify({"error": "Token and new password required"}), 400
    if len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    seller = execute(
        "SELECT id, reset_token_expires FROM sellers WHERE reset_token = ?",
        (token,), fetchone=True
    )
    if not seller:
        return jsonify({"error": "Invalid or expired reset link"}), 400

    exp = seller.get("reset_token_expires")
    if exp:
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt < datetime.now(timezone.utc):
                return jsonify({"error": "Reset link has expired"}), 400
        except Exception:
            return jsonify({"error": "Invalid reset link"}), 400

    pw_hash = hash_password(new_password)
    execute(
        """UPDATE sellers SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL,
           failed_login_attempts = 0, locked_until = NULL WHERE id = ?""",
        (pw_hash, seller["id"]), commit=True
    )
    return jsonify({"message": "Password reset successful. You can now log in."})


@app.route("/api/auth/change-password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json(silent=True) or {}
    current_pw = data.get("current_password") or ""
    new_password = data.get("new_password") or ""

    if not current_pw or not new_password:
        return jsonify({"error": "Current and new password required"}), 400
    if len(new_password) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400

    seller = execute("SELECT password_hash FROM sellers WHERE id = ?", (g.seller_id,), fetchone=True)
    if not seller or not verify_password(current_pw, seller["password_hash"]):
        return jsonify({"error": "Current password is incorrect"}), 401

    pw_hash = hash_password(new_password)
    execute("UPDATE sellers SET password_hash = ? WHERE id = ?", (pw_hash, g.seller_id), commit=True)
    return jsonify({"message": "Password updated successfully"})


@app.route("/api/auth/profile", methods=["PUT"])
@login_required
def update_profile():
    data = request.get_json(silent=True) or {}
    fields = []
    params = []

    if "shop_name" in data and data["shop_name"]:
        fields.append("shop_name = ?")
        params.append(str(data["shop_name"]).strip())
    if "whatsapp" in data and data["whatsapp"]:
        wa = "".join(c for c in str(data["whatsapp"]) if c.isdigit())
        if len(wa) < 8:
            return jsonify({"error": "Invalid WhatsApp number"}), 400
        fields.append("whatsapp = ?")
        params.append(wa)
    if "full_name_profile" in data:
        fields.append("full_name_profile = ?")
        params.append((data.get("full_name_profile") or "").strip() or None)
    if "bio" in data:
        fields.append("bio = ?")
        params.append((data.get("bio") or "").strip()[:500] or None)
    if "profile_image" in data:
        fields.append("profile_image = ?")
        params.append(data.get("profile_image") or None)

    if not fields:
        return jsonify({"error": "No fields to update"}), 400

    params.append(g.seller_id)
    execute(f"UPDATE sellers SET {', '.join(fields)} WHERE id = ?", tuple(params), commit=True)

    seller = execute(
        """SELECT id, username, email, shop_name, whatsapp, email_verified,
                  full_name_profile, bio, profile_image, kyc_status, subscription_expires_at
           FROM sellers WHERE id = ?""",
        (g.seller_id,), fetchone=True
    )
    result = dict(seller)
    result["email_verified"] = bool(result.get("email_verified"))
    return jsonify({"message": "Profile updated", "seller": result})


@app.route("/api/auth/delete-account", methods=["POST"])
@login_required
def delete_account():
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    if not password:
        return jsonify({"error": "Password required to delete account"}), 400

    seller = execute("SELECT password_hash FROM sellers WHERE id = ?", (g.seller_id,), fetchone=True)
    if not seller or not verify_password(password, seller["password_hash"]):
        return jsonify({"error": "Incorrect password"}), 401

    sid = g.seller_id
    # Remove seller content
    execute("DELETE FROM products WHERE seller_id = ?", (sid,), commit=True)
    execute("DELETE FROM properties WHERE seller_id = ?", (sid,), commit=True)
    execute("DELETE FROM sellers WHERE id = ?", (sid,), commit=True)
    return jsonify({"message": "Account and associated listings permanently deleted"})



@app.route("/api/health", methods=["GET"])
def health():
    db_ok = False
    db_error = None
    try:
        row = execute("SELECT 1 as ok", fetchone=True)
        db_ok = bool(row)
    except Exception as e:
        db_error = str(e)

    return jsonify({
        "status": "ok" if db_ok else "degraded",
        "database": "postgresql" if USE_POSTGRES else "sqlite",
        "database_connected": db_ok,
        "database_error": db_error,
        "persistent": USE_POSTGRES,
        "warning": None if USE_POSTGRES else "Using SQLite — data may be lost on Railway restart. Set DATABASE_URL to Postgres.",
        "message": "SunGarland API",
    })



@app.route("/api/products", methods=["GET"])
def get_products():
    category = request.args.get("category")
    search = request.args.get("search", "").strip()
    min_price = request.args.get("min_price")
    max_price = request.args.get("max_price")
    sort = request.args.get("sort", "newest")  # newest, price_asc, price_desc, name

    # Only show products from sellers with active subscription (or no seller_id for seeded demos)
    now_iso = datetime.now(timezone.utc).isoformat()
    query = """SELECT p.* FROM products p
               LEFT JOIN sellers s ON p.seller_id = s.id
               WHERE (p.seller_id IS NULL OR (s.subscription_expires_at IS NOT NULL AND s.subscription_expires_at > ?))"""
    params = [now_iso]

    if category and category.lower() != "all":
        query += " AND category = ?"
        params.append(category)

    if search:
        query += " AND (name LIKE ? OR description LIKE ? OR seller LIKE ? OR category LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like, like, like])

    if min_price:
        try:
            query += " AND price >= ?"
            params.append(float(min_price))
        except ValueError:
            pass
    if max_price:
        try:
            query += " AND price <= ?"
            params.append(float(max_price))
        except ValueError:
            pass

    if sort == "price_asc":
        query += " ORDER BY price ASC"
    elif sort == "price_desc":
        query += " ORDER BY price DESC"
    elif sort == "name":
        query += " ORDER BY name ASC"
    else:
        query += " ORDER BY created_at DESC"

    products = execute(query, params, fetchall=True)
    return jsonify(products or [])


@app.route("/api/products/<int:product_id>", methods=["GET"])
def get_product(product_id):
    product = execute("SELECT * FROM products WHERE id = ?", (product_id,), fetchone=True)
    if not product:
        return jsonify({"error": "Product not found"}), 404
    return jsonify(product)


@app.route("/api/products", methods=["POST"])
@login_required
def create_product():
    """Only logged-in sellers can create products."""
    # Check if seller is blocked, KYC not approved, or subscription expired
    seller_check = execute(
        "SELECT is_blocked, kyc_status, subscription_expires_at FROM sellers WHERE id = ?",
        (g.seller_id,), fetchone=True
    )
    if seller_check and seller_check.get("is_blocked"):
        return jsonify({"error": "Your account has been blocked. You cannot list products."}), 403
    if not seller_check or seller_check.get("kyc_status") != "approved":
        return jsonify({"error": "You must complete and get KYC approval before listing products."}), 403
    if not is_subscription_active(seller_check):
        return jsonify({"error": "Your monthly subscription has expired. Please renew to list products."}), 403

    data = request.get_json(silent=True) or {}

    required = ["name", "price", "category", "description"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    try:
        price = float(data["price"])
        if price < 0:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"error": "Price must be a positive number"}), 400

    seller = execute(
        "SELECT shop_name, whatsapp FROM sellers WHERE id = ?",
        (g.seller_id,),
        fetchone=True,
    )
    if not seller:
        return jsonify({"error": "Seller not found"}), 404

    image = data.get("image") or None
    video_url = data.get("video_url") or None
    now = datetime.now(timezone.utc).isoformat()

    if USE_POSTGRES:
        execute(
            """INSERT INTO products
               (name, price, category, description, seller, whatsapp, image, video_url, seller_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                data["name"].strip(), price, data["category"].strip(),
                data["description"].strip(), seller["shop_name"], seller["whatsapp"],
                image, g.seller_id, now,
            ),
            commit=True,
        )
        row = execute(
            "SELECT * FROM products WHERE seller_id = ? ORDER BY id DESC LIMIT 1",
            (g.seller_id,), fetchone=True,
        )
    else:
        cur = execute(
            """INSERT INTO products
               (name, price, category, description, seller, whatsapp, image, video_url, seller_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                data["name"].strip(), price, data["category"].strip(),
                data["description"].strip(), seller["shop_name"], seller["whatsapp"],
                image, g.seller_id, now,
            ),
            commit=True,
        )
        row = execute("SELECT * FROM products WHERE id = ?", (cur.lastrowid,), fetchone=True)

    return jsonify(row), 201


@app.route("/api/products/<int:product_id>", methods=["DELETE"])
@login_required
def delete_product(product_id):
    product = execute("SELECT * FROM products WHERE id = ?", (product_id,), fetchone=True)
    if not product:
        return jsonify({"error": "Product not found"}), 404
    if product.get("seller_id") != g.seller_id:
        return jsonify({"error": "You can only delete your own products"}), 403

    execute("DELETE FROM products WHERE id = ?", (product_id,), commit=True)
    return jsonify({"message": "Product deleted"}), 200


@app.route("/api/categories", methods=["GET"])
def get_categories():
    rows = execute("SELECT DISTINCT category FROM products ORDER BY category", fetchall=True)
    return jsonify([r["category"] for r in (rows or [])])



# ---------- Admin Routes ----------
@app.route("/api/admin/sellers", methods=["GET"])
def admin_list_sellers():
    """List all registered sellers. Protected by admin secret."""
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    sellers = execute(
        "SELECT id, username, email, shop_name, whatsapp, is_blocked, kyc_status, full_name, subscription_expires_at, created_at FROM sellers ORDER BY created_at DESC",
        fetchall=True
    )
    return jsonify(sellers or [])


@app.route("/api/admin/stats", methods=["GET"])
def admin_stats():
    """Simple stats for admin."""
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    sellers_count = execute("SELECT COUNT(*) as cnt FROM sellers", fetchone=True)
    products_count = execute("SELECT COUNT(*) as cnt FROM products", fetchone=True)

    return jsonify({
        "total_sellers": sellers_count["cnt"] if sellers_count else 0,
        "total_products": products_count["cnt"] if products_count else 0,
    })

@app.route("/api/admin/sellers/<int:seller_id>/block", methods=["POST"])
def admin_block_seller(seller_id):
    """Block a seller."""
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    seller = execute("SELECT id FROM sellers WHERE id = ?", (seller_id,), fetchone=True)
    if not seller:
        return jsonify({"error": "Seller not found"}), 404

    execute("UPDATE sellers SET is_blocked = 1 WHERE id = ?", (seller_id,), commit=True)
    return jsonify({"message": "Seller blocked successfully", "id": seller_id})


@app.route("/api/admin/sellers/<int:seller_id>/unblock", methods=["POST"])
def admin_unblock_seller(seller_id):
    """Unblock a seller."""
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    seller = execute("SELECT id FROM sellers WHERE id = ?", (seller_id,), fetchone=True)
    if not seller:
        return jsonify({"error": "Seller not found"}), 404

    execute("UPDATE sellers SET is_blocked = 0 WHERE id = ?", (seller_id,), commit=True)
    return jsonify({"message": "Seller unblocked successfully", "id": seller_id})




# ---------- Seller KYC ----------
@app.route("/api/kyc/submit", methods=["POST"])
@login_required
def submit_kyc():
    """Seller submits KYC information + documents."""
    data = request.get_json(silent=True) or {}

    required = ["full_name", "id_number", "address"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    full_name = data["full_name"].strip()
    id_number = data["id_number"].strip()
    address = data["address"].strip()
    id_document_url = data.get("id_document_url") or None
    selfie_url = data.get("selfie_url") or None

    now = datetime.now(timezone.utc).isoformat()

    face_score = data.get("face_match_score")
    face_label = data.get("face_match_label") or None
    try:
        face_score = float(face_score) if face_score is not None else None
    except (TypeError, ValueError):
        face_score = None

    execute(
        """UPDATE sellers SET
            full_name = ?, id_number = ?, address = ?,
            id_document_url = ?, selfie_url = ?,
            kyc_status = 'pending', kyc_submitted_at = ?,
            face_match_score = ?, face_match_label = ?
           WHERE id = ?""",
        (full_name, id_number, address, id_document_url, selfie_url, now, face_score, face_label, g.seller_id),
        commit=True,
    )

    return jsonify({
        "message": "KYC submitted successfully. Waiting for admin approval.",
        "kyc_status": "pending"
    })


@app.route("/api/kyc/status", methods=["GET"])
@login_required
def kyc_status():
    """Get current seller KYC status."""
    seller = execute(
        "SELECT kyc_status, full_name, id_number, address, id_document_url, selfie_url, kyc_submitted_at FROM sellers WHERE id = ?",
        (g.seller_id,),
        fetchone=True,
    )
    if not seller:
        return jsonify({"error": "Seller not found"}), 404
    return jsonify(seller)


# ---------- Buyer KYC (simple) ----------
@app.route("/api/buyer/verify", methods=["POST"])
def buyer_verify():
    """Buyer submits basic verification before purchasing."""
    data = request.get_json(silent=True) or {}

    full_name = (data.get("full_name") or "").strip()
    if not full_name:
        return jsonify({"error": "Full name is required"}), 400

    selfie_url = data.get("selfie_url") or None
    email = data.get("email") or None
    phone = data.get("phone") or None
    now = datetime.now(timezone.utc).isoformat()

    # For demo we auto-approve buyers (can be changed to pending)
    if USE_POSTGRES:
        execute(
            """INSERT INTO buyers (full_name, email, phone, selfie_url, kyc_status, created_at)
               VALUES (?, ?, ?, ?, 'approved', ?)""",
            (full_name, email, phone, selfie_url, now),
            commit=True,
        )
        row = execute("SELECT id FROM buyers ORDER BY id DESC LIMIT 1", fetchone=True)
        buyer_id = row["id"]
    else:
        cur = execute(
            """INSERT INTO buyers (full_name, email, phone, selfie_url, kyc_status, created_at)
               VALUES (?, ?, ?, ?, 'approved', ?)""",
            (full_name, email, phone, selfie_url, now),
            commit=True,
        )
        buyer_id = cur.lastrowid

    # Create a simple token for the buyer
    token = create_token(buyer_id, full_name)  # reuse JWT helper
    return jsonify({
        "message": "Verification successful",
        "buyer_token": token,
        "buyer_id": buyer_id,
        "full_name": full_name
    })


# ---------- Admin KYC management ----------
@app.route("/api/admin/kyc/pending", methods=["GET"])
def admin_pending_kyc():
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    sellers = execute(
        """SELECT id, username, email, shop_name, whatsapp, full_name, id_number, address,
                  id_document_url, selfie_url, kyc_status, kyc_submitted_at, created_at,
                  face_match_score, face_match_label
           FROM sellers WHERE kyc_status = 'pending' ORDER BY kyc_submitted_at DESC""",
        fetchall=True,
    )
    return jsonify(sellers or [])


@app.route("/api/admin/kyc/<int:seller_id>/approve", methods=["POST"])
def admin_approve_kyc(seller_id):
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    execute("UPDATE sellers SET kyc_status = 'approved' WHERE id = ?", (seller_id,), commit=True)
    return jsonify({"message": "KYC approved", "id": seller_id})


@app.route("/api/admin/kyc/<int:seller_id>/reject", methods=["POST"])
def admin_reject_kyc(seller_id):
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    execute("UPDATE sellers SET kyc_status = 'rejected' WHERE id = ?", (seller_id,), commit=True)
    return jsonify({"message": "KYC rejected", "id": seller_id})


@app.route("/api/admin/products", methods=["GET"])
def admin_list_products():
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    products = execute("SELECT * FROM products ORDER BY created_at DESC", fetchall=True)
    return jsonify(products or [])


@app.route("/api/admin/products/<int:product_id>", methods=["DELETE"])
def admin_delete_product(product_id):
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    execute("DELETE FROM products WHERE id = ?", (product_id,), commit=True)
    return jsonify({"message": "Product deleted", "id": product_id})



# ---------- Image Upload ----------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/api/upload", methods=["POST"])
def upload_image():
    """Upload an image file and return its URL."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed. Use images (PNG, JPG, WEBP) or videos (MP4, WEBM, MOV)"}), 400

    # Create unique filename
    ext = file.filename.rsplit(".", 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # Prefer Cloudinary for permanent storage
    cloud_url = upload_to_cloudinary(filepath, filename)
    if cloud_url:
        try:
            os.remove(filepath)
        except Exception:
            pass
        return jsonify({"url": cloud_url, "filename": filename, "storage": "cloudinary"})

    # Fallback: local server storage
    host = request.host_url.rstrip("/")
    url = f"{host}/uploads/{filename}"
    return jsonify({"url": url, "filename": filename, "storage": "local"})


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    """Serve uploaded images."""
    return send_from_directory(UPLOAD_FOLDER, filename)



# ---------- Ratings & Comments ----------
@app.route("/api/products/<int:product_id>/ratings", methods=["GET"])
def get_ratings(product_id):
    ratings = execute(
        "SELECT * FROM ratings WHERE product_id = ? ORDER BY created_at DESC",
        (product_id,), fetchall=True
    )
    avg_row = execute(
        "SELECT AVG(rating) as avg_rating, COUNT(*) as count FROM ratings WHERE product_id = ?",
        (product_id,), fetchone=True
    )
    avg = round(float(avg_row["avg_rating"] or 0), 1)
    count = avg_row["count"] or 0
    return jsonify({"ratings": ratings or [], "average": avg, "count": count})


@app.route("/api/products/<int:product_id>/ratings", methods=["POST"])
def add_rating(product_id):
    data = request.get_json(silent=True) or {}
    author = (data.get("author_name") or "Anonymous").strip()[:50]
    try:
        rating = int(data.get("rating", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Rating must be a number"}), 400
    if rating < 1 or rating > 5:
        return jsonify({"error": "Rating must be between 1 and 5"}), 400

    # Check product exists
    product = execute("SELECT id FROM products WHERE id = ?", (product_id,), fetchone=True)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    now = datetime.now(timezone.utc).isoformat()
    execute(
        "INSERT INTO ratings (product_id, author_name, rating, created_at) VALUES (?, ?, ?, ?)",
        (product_id, author, rating, now), commit=True
    )
    return jsonify({"message": "Rating added"}), 201


@app.route("/api/products/<int:product_id>/comments", methods=["GET"])
def get_comments(product_id):
    comments = execute(
        "SELECT * FROM comments WHERE product_id = ? ORDER BY created_at DESC",
        (product_id,), fetchall=True
    )
    return jsonify(comments or [])


@app.route("/api/products/<int:product_id>/comments", methods=["POST"])
def add_comment(product_id):
    data = request.get_json(silent=True) or {}
    author = (data.get("author_name") or "Anonymous").strip()[:50]
    comment = (data.get("comment") or "").strip()
    if not comment:
        return jsonify({"error": "Comment cannot be empty"}), 400
    if len(comment) > 1000:
        return jsonify({"error": "Comment too long (max 1000 characters)"}), 400

    product = execute("SELECT id FROM products WHERE id = ?", (product_id,), fetchone=True)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    now = datetime.now(timezone.utc).isoformat()
    execute(
        "INSERT INTO comments (product_id, author_name, comment, created_at) VALUES (?, ?, ?, ?)",
        (product_id, author, comment, now), commit=True
    )
    return jsonify({"message": "Comment added"}), 201


@app.route("/api/products/<int:product_id>/details", methods=["GET"])
def product_details(product_id):
    """Full product details including ratings and comments."""
    product = execute("SELECT * FROM products WHERE id = ?", (product_id,), fetchone=True)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    ratings_data = execute(
        "SELECT AVG(rating) as avg_rating, COUNT(*) as count FROM ratings WHERE product_id = ?",
        (product_id,), fetchone=True
    )
    ratings = execute(
        "SELECT * FROM ratings WHERE product_id = ? ORDER BY created_at DESC LIMIT 20",
        (product_id,), fetchall=True
    )
    comments = execute(
        "SELECT * FROM comments WHERE product_id = ? ORDER BY created_at DESC LIMIT 50",
        (product_id,), fetchall=True
    )

    result = dict(product)
    result["average_rating"] = round(float(ratings_data["avg_rating"] or 0), 1)
    result["rating_count"] = ratings_data["count"] or 0
    result["ratings"] = ratings or []
    result["comments"] = comments or []
    return jsonify(result)



# ---------- Seller Profile ----------
@app.route("/api/sellers/<int:seller_id>", methods=["GET"])
def seller_profile(seller_id):
    seller = execute(
        "SELECT id, username, shop_name, whatsapp, kyc_status, created_at FROM sellers WHERE id = ?",
        (seller_id,), fetchone=True
    )
    if not seller:
        return jsonify({"error": "Seller not found"}), 404

    products = execute(
        "SELECT * FROM products WHERE seller_id = ? ORDER BY created_at DESC",
        (seller_id,), fetchall=True
    ) or []

    # Average rating across all their products
    avg_row = execute(
        """SELECT AVG(r.rating) as avg_rating, COUNT(r.id) as rating_count
           FROM ratings r
           JOIN products p ON p.id = r.product_id
           WHERE p.seller_id = ?""",
        (seller_id,), fetchone=True
    )

    result = dict(seller)
    result["products"] = products
    result["product_count"] = len(products)
    result["average_rating"] = round(float(avg_row["avg_rating"] or 0), 1) if avg_row else 0
    result["rating_count"] = avg_row["rating_count"] if avg_row else 0
    return jsonify(result)


@app.route("/api/sellers/by-name/<path:shop_name>", methods=["GET"])
def seller_by_name(shop_name):
    seller = execute(
        "SELECT id FROM sellers WHERE shop_name = ? OR username = ?",
        (shop_name, shop_name), fetchone=True
    )
    if not seller:
        return jsonify({"error": "Seller not found"}), 404
    return seller_profile(seller["id"])


# ---------- Seller Dashboard (my products) ----------
@app.route("/api/my/products", methods=["GET"])
@login_required
def my_products():
    products = execute(
        "SELECT * FROM products WHERE seller_id = ? ORDER BY created_at DESC",
        (g.seller_id,), fetchall=True
    )
    return jsonify(products or [])


@app.route("/api/my/products/<int:product_id>", methods=["DELETE"])
@login_required
def delete_my_product(product_id):
    product = execute("SELECT * FROM products WHERE id = ?", (product_id,), fetchone=True)
    if not product:
        return jsonify({"error": "Product not found"}), 404
    if product.get("seller_id") != g.seller_id:
        return jsonify({"error": "Not your product"}), 403
    execute("DELETE FROM products WHERE id = ?", (product_id,), commit=True)
    return jsonify({"message": "Product deleted"})


# ---------- Inquiries (Buy tracking) ----------
@app.route("/api/inquiries", methods=["POST"])
def log_inquiry():
    data = request.get_json(silent=True) or {}
    product_id = data.get("product_id")
    product_name = data.get("product_name", "")
    seller_name = data.get("seller_name", "")
    buyer_name = data.get("buyer_name", "Anonymous")
    now = datetime.now(timezone.utc).isoformat()

    execute(
        "INSERT INTO inquiries (product_id, product_name, seller_name, buyer_name, created_at) VALUES (?, ?, ?, ?, ?)",
        (product_id, product_name, seller_name, buyer_name, now), commit=True
    )
    return jsonify({"message": "Inquiry logged"}), 201


@app.route("/api/admin/inquiries", methods=["GET"])
def admin_inquiries():
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    rows = execute("SELECT * FROM inquiries ORDER BY created_at DESC LIMIT 100", fetchall=True)
    return jsonify(rows or [])


# Enhanced product listing is already partially supported via query params.
# Add sort support:


# ---------- Subscription ----------
@app.route("/api/subscription/status", methods=["GET"])
@login_required
def subscription_status():
    seller = execute(
        "SELECT subscription_expires_at, shop_name, has_paid_before FROM sellers WHERE id = ?",
        (g.seller_id,), fetchone=True
    )
    if not seller:
        return jsonify({"error": "Seller not found"}), 404

    active = is_subscription_active(seller)
    exp = seller.get("subscription_expires_at")
    days_left = None
    if exp:
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            delta = exp_dt - datetime.now(timezone.utc)
            days_left = max(0, delta.days)
        except Exception:
            pass

    has_paid = bool(seller.get("has_paid_before"))
    price_first = float(get_setting("price_first", "50"))
    price_renewal = float(get_setting("price_renewal", "100"))
    currency = get_setting("currency", "GHS")
    current_price = price_renewal if has_paid else price_first

    return jsonify({
        "active": active,
        "expires_at": exp,
        "days_left": days_left,
        "shop_name": seller.get("shop_name"),
        "has_paid_before": has_paid,
        "price": current_price,
        "price_first": price_first,
        "price_renewal": price_renewal,
        "currency": currency,
        "is_first_time": not has_paid
    })



@app.route("/api/subscription/pay/initialize", methods=["POST"])
@login_required
def subscription_pay_initialize():
    """Start Paystack payment for seller subscription (first or renewal)."""
    if get_setting("paystack_enabled", "0") != "1":
        return jsonify({"error": "Online payments are not enabled. Contact admin."}), 400
    secret = get_setting("paystack_secret_key", "")
    if not secret:
        return jsonify({"error": "Payment gateway not configured"}), 400

    seller = execute(
        "SELECT id, email, shop_name, has_paid_before, subscription_expires_at FROM sellers WHERE id = ?",
        (g.seller_id,), fetchone=True
    )
    if not seller:
        return jsonify({"error": "Seller not found"}), 404

    has_paid = bool(seller.get("has_paid_before"))
    price_first = float(get_setting("price_first", "50"))
    price_renewal = float(get_setting("price_renewal", "100"))
    currency = get_setting("currency", "GHS")
    amount = price_renewal if has_paid else price_first
    amount_kobo = int(round(amount * 100))
    reference = f"SUB-{g.seller_id}-{pysecrets.token_hex(8)}"
    callback_url = (request.get_json(silent=True) or {}).get("callback_url") or (frontend_base_url() + "/")

    try:
        resp = requests.post(
            "https://api.paystack.co/transaction/initialize",
            headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/json"},
            json={
                "email": seller["email"],
                "amount": amount_kobo,
                "currency": currency,
                "reference": reference,
                "callback_url": callback_url,
                "metadata": {
                    "type": "subscription",
                    "seller_id": g.seller_id,
                    "shop_name": seller.get("shop_name"),
                    "plan": "renewal" if has_paid else "first",
                },
            },
            timeout=30,
        )
        result = resp.json()
        if not result.get("status"):
            return jsonify({"error": result.get("message", "Paystack init failed")}), 400

        # Store pending reference on seller via reset_token field? Use notifications table or settings
        # Use a simple approach: put reference in a temporary notification body or new column
        # We'll verify purely via Paystack metadata + reference prefix SUB-{seller_id}-
        return jsonify({
            "authorization_url": result["data"]["authorization_url"],
            "reference": reference,
            "amount": amount,
            "currency": currency,
            "plan": "renewal" if has_paid else "first",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/subscription/pay/verify/<reference>", methods=["GET"])
@login_required
def subscription_pay_verify(reference):
    """Verify subscription payment and extend plan by 30 days."""
    secret = get_setting("paystack_secret_key", "")
    if not secret:
        return jsonify({"error": "Payment gateway not configured"}), 400

    if not reference.startswith(f"SUB-{g.seller_id}-"):
        return jsonify({"error": "Invalid subscription reference"}), 400

    try:
        resp = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers={"Authorization": f"Bearer {secret}"},
            timeout=30,
        )
        result = resp.json()
        if not result.get("status"):
            return jsonify({"error": result.get("message", "Verification failed")}), 400

        data = result["data"]
        if data.get("status") != "success":
            return jsonify({"status": data.get("status"), "message": "Payment not successful"}), 400

        seller = execute(
            "SELECT subscription_expires_at FROM sellers WHERE id = ?",
            (g.seller_id,), fetchone=True
        )
        now = datetime.now(timezone.utc)
        base = now
        current_exp = seller.get("subscription_expires_at") if seller else None
        if current_exp:
            try:
                exp_dt = datetime.fromisoformat(current_exp.replace("Z", "+00:00"))
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if exp_dt > now:
                    base = exp_dt
            except Exception:
                pass

        new_exp = (base + timedelta(days=30)).isoformat()
        execute(
            "UPDATE sellers SET subscription_expires_at = ?, has_paid_before = 1 WHERE id = ?",
            (new_exp, g.seller_id), commit=True
        )
        create_notification(g.seller_id, "Subscription activated", f"Your plan is active until {new_exp[:10]}", "dashboard")

        return jsonify({
            "status": "success",
            "message": "Subscription activated for 30 days",
            "expires_at": new_exp,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/subscription/renew", methods=["POST"])
@login_required
def renew_subscription():
    """
    Renew / extend subscription by 30 days.
    In production, connect this to a payment gateway (Stripe, Paystack, etc.)
    and only call this after successful payment.
    """
    seller = execute(
        "SELECT subscription_expires_at FROM sellers WHERE id = ?",
        (g.seller_id,), fetchone=True
    )
    if not seller:
        return jsonify({"error": "Seller not found"}), 404

    now = datetime.now(timezone.utc)
    current_exp = seller.get("subscription_expires_at")
    base = now
    if current_exp:
        try:
            exp_dt = datetime.fromisoformat(current_exp.replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt > now:
                base = exp_dt  # extend from current expiry
        except Exception:
            pass

    new_exp = (base + timedelta(days=30)).isoformat()
    execute(
        "UPDATE sellers SET subscription_expires_at = ?, has_paid_before = 1 WHERE id = ?",
        (new_exp, g.seller_id), commit=True
    )

    price_first = float(get_setting("price_first", "50"))
    price_renewal = float(get_setting("price_renewal", "100"))
    currency = get_setting("currency", "GHS")
    # After first payment, future renewals use renewal price
    seller_before = execute("SELECT has_paid_before FROM sellers WHERE id = ?", (g.seller_id,), fetchone=True)

    return jsonify({
        "message": "Subscription renewed for 30 days",
        "expires_at": new_exp,
        "active": True,
        "currency": currency
    })


@app.route("/api/admin/sellers/<int:seller_id>/extend", methods=["POST"])
def admin_extend_subscription(seller_id):
    """Admin can manually extend a seller subscription by 30 days."""
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    seller = execute("SELECT subscription_expires_at FROM sellers WHERE id = ?", (seller_id,), fetchone=True)
    if not seller:
        return jsonify({"error": "Seller not found"}), 404

    now = datetime.now(timezone.utc)
    current_exp = seller.get("subscription_expires_at")
    base = now
    if current_exp:
        try:
            exp_dt = datetime.fromisoformat(current_exp.replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt > now:
                base = exp_dt
        except Exception:
            pass

    new_exp = (base + timedelta(days=30)).isoformat()
    execute("UPDATE sellers SET subscription_expires_at = ? WHERE id = ?", (new_exp, seller_id), commit=True)
    return jsonify({"message": "Subscription extended by 30 days", "expires_at": new_exp})



@app.route("/api/admin/settings", methods=["GET"])
def admin_get_settings():
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "price_first": float(get_setting("price_first", "50")),
        "price_renewal": float(get_setting("price_renewal", "100")),
        "currency": get_setting("currency", "GHS"),
        "paystack_public_key": get_setting("paystack_public_key", ""),
        "paystack_secret_key": get_setting("paystack_secret_key", ""),
        "paystack_enabled": get_setting("paystack_enabled", "0") == "1",
        "cloudinary_cloud_name": get_setting("cloudinary_cloud_name", ""),
        "cloudinary_api_key": get_setting("cloudinary_api_key", ""),
        "cloudinary_api_secret": get_setting("cloudinary_api_secret", ""),
        "smtp_configured": bool(os.environ.get("SMTP_HOST")),
        "frontend_url": frontend_base_url(),
    })


@app.route("/api/admin/settings", methods=["POST"])
def admin_update_settings():
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    if "price_first" in data:
        try:
            val = float(data["price_first"])
            if val < 0:
                raise ValueError()
            set_setting("price_first", val)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid price_first"}), 400
    if "price_renewal" in data:
        try:
            val = float(data["price_renewal"])
            if val < 0:
                raise ValueError()
            set_setting("price_renewal", val)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid price_renewal"}), 400
    if "currency" in data and data["currency"]:
        set_setting("currency", str(data["currency"]).strip().upper()[:5])
    if "paystack_public_key" in data:
        set_setting("paystack_public_key", str(data["paystack_public_key"]).strip())
    if "paystack_secret_key" in data:
        set_setting("paystack_secret_key", str(data["paystack_secret_key"]).strip())
    if "paystack_enabled" in data:
        set_setting("paystack_enabled", "1" if data["paystack_enabled"] else "0")
    if "cloudinary_cloud_name" in data:
        set_setting("cloudinary_cloud_name", str(data["cloudinary_cloud_name"]).strip())
    if "cloudinary_api_key" in data:
        set_setting("cloudinary_api_key", str(data["cloudinary_api_key"]).strip())
    if "cloudinary_api_secret" in data:
        set_setting("cloudinary_api_secret", str(data["cloudinary_api_secret"]).strip())

    return jsonify({
        "message": "Settings updated",
        "price_first": float(get_setting("price_first", "50")),
        "price_renewal": float(get_setting("price_renewal", "100")),
        "currency": get_setting("currency", "GHS"),
        "paystack_enabled": get_setting("paystack_enabled", "0") == "1",
    })


@app.route("/api/subscription/prices", methods=["GET"])
def public_prices():
    """Public endpoint so frontend can show prices without login."""
    return jsonify({
        "price_first": float(get_setting("price_first", "50")),
        "price_renewal": float(get_setting("price_renewal", "100")),
        "currency": get_setting("currency", "GHS")
    })



# ---------- Paystack Payments ----------
@app.route("/api/payment/config", methods=["GET"])
def payment_config():
    """Public config for frontend (only public key + enabled flag)."""
    enabled = get_setting("paystack_enabled", "0") == "1"
    public_key = get_setting("paystack_public_key", "")
    currency = get_setting("currency", "GHS")
    return jsonify({
        "enabled": enabled and bool(public_key),
        "public_key": public_key if enabled else "",
        "currency": currency
    })


@app.route("/api/payment/initialize", methods=["POST"])
def payment_initialize():
    """Create an order and initialize a Paystack transaction."""
    if get_setting("paystack_enabled", "0") != "1":
        return jsonify({"error": "Online payments are not enabled"}), 400

    secret = get_setting("paystack_secret_key", "")
    if not secret:
        return jsonify({"error": "Payment gateway not configured"}), 400

    data = request.get_json(silent=True) or {}
    product_id = data.get("product_id")
    buyer_name = (data.get("buyer_name") or "").strip()
    buyer_email = (data.get("buyer_email") or "").strip()
    buyer_phone = (data.get("buyer_phone") or "").strip()

    if not product_id:
        return jsonify({"error": "product_id required"}), 400
    if not buyer_name:
        return jsonify({"error": "Buyer name required"}), 400
    if not buyer_email:
        return jsonify({"error": "Buyer email required for payment"}), 400

    product = execute("SELECT * FROM products WHERE id = ?", (product_id,), fetchone=True)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    amount = float(product["price"])
    currency = get_setting("currency", "GHS")
    # Paystack expects amount in the smallest currency unit (pesewas for GHS)
    amount_kobo = int(round(amount * 100))

    reference = f"SG-{product_id}-{pysecrets.token_hex(8)}"
    now = datetime.now(timezone.utc).isoformat()

    execute(
        """INSERT INTO orders
           (product_id, product_name, product_price, seller_name, seller_whatsapp,
            buyer_name, buyer_email, buyer_phone, amount, currency, payment_reference, payment_status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
        (
            product["id"], product["name"], amount, product["seller"], product["whatsapp"],
            buyer_name, buyer_email, buyer_phone, amount, currency, reference, now
        ),
        commit=True,
    )

    # Callback URL - frontend will handle the return
    callback_url = data.get("callback_url") or request.host_url.rstrip("/") + "/"

    try:
        resp = requests.post(
            "https://api.paystack.co/transaction/initialize",
            headers={
                "Authorization": f"Bearer {secret}",
                "Content-Type": "application/json",
            },
            json={
                "email": buyer_email,
                "amount": amount_kobo,
                "currency": currency,
                "reference": reference,
                "callback_url": callback_url,
                "metadata": {
                    "product_id": product_id,
                    "product_name": product["name"],
                    "buyer_name": buyer_name,
                    "seller_name": product["seller"],
                },
            },
            timeout=30,
        )
        result = resp.json()
        if not result.get("status"):
            return jsonify({"error": result.get("message", "Paystack initialization failed")}), 400

        return jsonify({
            "authorization_url": result["data"]["authorization_url"],
            "access_code": result["data"]["access_code"],
            "reference": reference,
            "amount": amount,
            "currency": currency,
        })
    except Exception as e:
        return jsonify({"error": f"Payment service error: {str(e)}"}), 500


@app.route("/api/payment/verify/<reference>", methods=["GET"])
def payment_verify(reference):
    """Verify a Paystack payment and update order status."""
    secret = get_setting("paystack_secret_key", "")
    if not secret:
        return jsonify({"error": "Payment gateway not configured"}), 400

    try:
        resp = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers={"Authorization": f"Bearer {secret}"},
            timeout=30,
        )
        result = resp.json()
        if not result.get("status"):
            return jsonify({"error": result.get("message", "Verification failed")}), 400

        data = result["data"]
        status = data.get("status")  # success, failed, abandoned

        order = execute(
            "SELECT * FROM orders WHERE payment_reference = ?",
            (reference,), fetchone=True
        )
        if not order:
            return jsonify({"error": "Order not found"}), 404

        if status == "success":
            execute(
                "UPDATE orders SET payment_status = 'paid' WHERE payment_reference = ?",
                (reference,), commit=True
            )
            try:
                prod = execute("SELECT seller_id FROM products WHERE id = ?", (order["product_id"],), fetchone=True)
                if prod and prod.get("seller_id"):
                    create_notification(
                        prod["seller_id"],
                        "New paid order",
                        f"{order.get('buyer_name')} paid for {order.get('product_name')}",
                        "dashboard"
                    )
            except Exception:
                pass
            # Also log as inquiry
            try:
                now = datetime.now(timezone.utc).isoformat()
                execute(
                    "INSERT INTO inquiries (product_id, product_name, seller_name, buyer_name, created_at) VALUES (?, ?, ?, ?, ?)",
                    (order["product_id"], order["product_name"], order["seller_name"],
                     f"{order['buyer_name']} (Paid online)", now),
                    commit=True,
                )
            except Exception:
                pass

            return jsonify({
                "status": "success",
                "message": "Payment successful",
                "order": {
                    "reference": reference,
                    "product_name": order["product_name"],
                    "amount": order["amount"],
                    "currency": order["currency"],
                    "seller_name": order["seller_name"],
                    "seller_whatsapp": order["seller_whatsapp"],
                    "buyer_name": order["buyer_name"],
                }
            })
        else:
            execute(
                "UPDATE orders SET payment_status = ? WHERE payment_reference = ?",
                (status, reference), commit=True
            )
            return jsonify({"status": status, "message": f"Payment status: {status}"})
    except Exception as e:
        return jsonify({"error": f"Verification error: {str(e)}"}), 500


@app.route("/api/admin/orders", methods=["GET"])
def admin_orders():
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    rows = execute("SELECT * FROM orders ORDER BY created_at DESC LIMIT 100", fetchall=True)
    return jsonify(rows or [])



# ---------- Houses & Hostels (NO online payment) ----------
PROPERTY_DISCLAIMER = (
    "IMPORTANT: SunGarland does not process any payments for houses or hostels. "
    "Do not pay any agent or third party until you have visited the property in person "
    "and confirmed that the person you are dealing with is the legitimate agent in charge. "
    "Meet in a safe public place when possible. SunGarland is only a listing platform."
)

@app.route("/api/properties", methods=["GET"])
def list_properties():
    ptype = request.args.get("type")
    search = request.args.get("search", "").strip()
    query = "SELECT * FROM properties WHERE is_available = 1"
    params = []
    if ptype and ptype.lower() != "all":
        query += " AND property_type = ?"
        params.append(ptype)
    if search:
        query += " AND (title LIKE ? OR location LIKE ? OR description LIKE ? OR agent_name LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like, like, like])
    query += " ORDER BY created_at DESC"
    rows = execute(query, params, fetchall=True)
    return jsonify({"properties": rows or [], "disclaimer": PROPERTY_DISCLAIMER})


@app.route("/api/properties/<int:prop_id>", methods=["GET"])
def get_property(prop_id):
    row = execute("SELECT * FROM properties WHERE id = ?", (prop_id,), fetchone=True)
    if not row:
        return jsonify({"error": "Property not found"}), 404
    result = dict(row)
    result["disclaimer"] = PROPERTY_DISCLAIMER
    return jsonify(result)


@app.route("/api/properties", methods=["POST"])
@login_required
def create_property():
    """Agents (logged-in sellers) can list houses/hostels. No payment involved."""
    seller_check = execute(
        "SELECT is_blocked, kyc_status, shop_name, whatsapp FROM sellers WHERE id = ?",
        (g.seller_id,), fetchone=True
    )
    if seller_check and seller_check.get("is_blocked"):
        return jsonify({"error": "Your account has been blocked."}), 403
    if not seller_check or seller_check.get("kyc_status") != "approved":
        return jsonify({"error": "Complete KYC approval before listing properties."}), 403

    data = request.get_json(silent=True) or {}
    required = ["title", "property_type", "location", "description"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing: {', '.join(missing)}"}), 400

    now = datetime.now(timezone.utc).isoformat()
    execute(
        """INSERT INTO properties
           (title, property_type, location, price, description, agent_name, agent_whatsapp,
            agent_id, image, video_url, is_available, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
        (
            data["title"].strip(),
            data["property_type"].strip(),
            data["location"].strip(),
            (data.get("price") or "").strip() or None,
            data["description"].strip(),
            seller_check["shop_name"],
            seller_check["whatsapp"],
            g.seller_id,
            data.get("image") or None,
            data.get("video_url") or None,
            now,
        ),
        commit=True,
    )
    row = execute(
        "SELECT * FROM properties WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
        (g.seller_id,), fetchone=True
    )
    return jsonify(row), 201


@app.route("/api/my/properties", methods=["GET"])
@login_required
def my_properties():
    rows = execute(
        "SELECT * FROM properties WHERE agent_id = ? ORDER BY created_at DESC",
        (g.seller_id,), fetchall=True
    )
    return jsonify(rows or [])


@app.route("/api/my/properties/<int:prop_id>", methods=["DELETE"])
@login_required
def delete_my_property(prop_id):
    prop = execute("SELECT * FROM properties WHERE id = ?", (prop_id,), fetchone=True)
    if not prop:
        return jsonify({"error": "Not found"}), 404
    if prop.get("agent_id") != g.seller_id:
        return jsonify({"error": "Not your listing"}), 403
    execute("DELETE FROM properties WHERE id = ?", (prop_id,), commit=True)
    return jsonify({"message": "Deleted"})


@app.route("/api/admin/properties", methods=["GET"])
def admin_properties():
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    rows = execute("SELECT * FROM properties ORDER BY created_at DESC", fetchall=True)
    return jsonify(rows or [])


@app.route("/api/admin/properties/<int:prop_id>", methods=["DELETE"])
def admin_delete_property(prop_id):
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    execute("DELETE FROM properties WHERE id = ?", (prop_id,), commit=True)
    return jsonify({"message": "Deleted"})



# ---------- Houses & Hostels ----------
@app.route("/api/properties", methods=["GET"])
def get_properties():
    prop_type = request.args.get("type")  # house, hostel, or all
    search = request.args.get("search", "").strip()
    location = request.args.get("location", "").strip()

    query = "SELECT * FROM properties WHERE 1=1"
    params = []

    if prop_type and prop_type.lower() not in ("all", ""):
        query += " AND property_type = ?"
        params.append(prop_type.lower())

    if search:
        like = f"%{search}%"
        query += " AND (title LIKE ? OR description LIKE ? OR location LIKE ? OR agent_name LIKE ?)"
        params.extend([like, like, like, like])

    if location:
        query += " AND location LIKE ?"
        params.append(f"%{location}%")

    query += " ORDER BY created_at DESC"
    rows = execute(query, params, fetchall=True)
    return jsonify(rows or [])


@app.route("/api/properties/<int:prop_id>", methods=["GET"])
def get_property(prop_id):
    row = execute("SELECT * FROM properties WHERE id = ?", (prop_id,), fetchone=True)
    if not row:
        return jsonify({"error": "Property not found"}), 404
    return jsonify(row)


@app.route("/api/properties", methods=["POST"])
@login_required
def create_property():
    """Agents (logged-in sellers) can list houses/hostels. No payment required for listing properties."""
    seller_check = execute(
        "SELECT is_blocked, shop_name, whatsapp, agent_status FROM sellers WHERE id = ?",
        (g.seller_id,), fetchone=True
    )
    if seller_check and seller_check.get("is_blocked"):
        return jsonify({"error": "Your account has been blocked."}), 403
    if not seller_check or seller_check.get("agent_status") != "approved":
        return jsonify({
            "error": "You must submit a government-registered agent document and get admin approval before listing houses or hostels."
        }), 403

    data = request.get_json(silent=True) or {}
    required = ["title", "property_type", "location", "price", "description"]
    missing = [f for f in required if not data.get(f) and data.get(f) != 0]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    try:
        price = float(data["price"])
        if price < 0:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid price"}), 400

    prop_type = str(data["property_type"]).strip().lower()
    if prop_type not in ("house", "hostel", "apartment", "room"):
        prop_type = "house"

    agent_name = data.get("agent_name") or (seller_check["shop_name"] if seller_check else "Agent")
    whatsapp = data.get("whatsapp") or (seller_check["whatsapp"] if seller_check else "")
    if not whatsapp:
        return jsonify({"error": "WhatsApp number is required"}), 400

    now = datetime.now(timezone.utc).isoformat()
    image = data.get("image") or None
    price_period = data.get("price_period") or "month"

    if USE_POSTGRES:
        execute(
            """INSERT INTO properties
               (title, property_type, location, price, price_period, description, image, agent_name, whatsapp, seller_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (data["title"].strip(), prop_type, data["location"].strip(), price, price_period,
             data["description"].strip(), image, agent_name, str(whatsapp).strip(), g.seller_id, now),
            commit=True,
        )
        row = execute("SELECT * FROM properties ORDER BY id DESC LIMIT 1", fetchone=True)
    else:
        cur = execute(
            """INSERT INTO properties
               (title, property_type, location, price, price_period, description, image, agent_name, whatsapp, seller_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (data["title"].strip(), prop_type, data["location"].strip(), price, price_period,
             data["description"].strip(), image, agent_name, str(whatsapp).strip(), g.seller_id, now),
            commit=True,
        )
        row = execute("SELECT * FROM properties WHERE id = ?", (cur.lastrowid,), fetchone=True)

    return jsonify(row), 201


@app.route("/api/my/properties", methods=["GET"])
@login_required
def my_properties():
    rows = execute(
        "SELECT * FROM properties WHERE seller_id = ? ORDER BY created_at DESC",
        (g.seller_id,), fetchall=True
    )
    return jsonify(rows or [])


@app.route("/api/my/properties/<int:prop_id>", methods=["DELETE"])
@login_required
def delete_my_property(prop_id):
    prop = execute("SELECT * FROM properties WHERE id = ?", (prop_id,), fetchone=True)
    if not prop:
        return jsonify({"error": "Not found"}), 404
    if prop.get("seller_id") != g.seller_id:
        return jsonify({"error": "Not your listing"}), 403
    execute("DELETE FROM properties WHERE id = ?", (prop_id,), commit=True)
    return jsonify({"message": "Deleted"})


@app.route("/api/admin/properties", methods=["GET"])
def admin_properties():
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    rows = execute("SELECT * FROM properties ORDER BY created_at DESC", fetchall=True)
    return jsonify(rows or [])


@app.route("/api/admin/properties/<int:prop_id>", methods=["DELETE"])
def admin_delete_property(prop_id):
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    execute("DELETE FROM properties WHERE id = ?", (prop_id,), commit=True)
    return jsonify({"message": "Deleted"})



# ---------- Agent verification (Houses & Hostels) ----------
@app.route("/api/agent/submit", methods=["POST"])
@login_required
def submit_agent_docs():
    data = request.get_json(silent=True) or {}
    license_number = (data.get("agent_license_number") or "").strip()
    doc_url = (data.get("agent_doc_url") or "").strip()
    if not license_number:
        return jsonify({"error": "Government registration / license number is required"}), 400
    if not doc_url:
        return jsonify({"error": "Please upload your government agent registration document"}), 400
    now = datetime.now(timezone.utc).isoformat()
    execute(
        """UPDATE sellers SET agent_license_number = ?, agent_doc_url = ?,
           agent_status = 'pending', agent_submitted_at = ? WHERE id = ?""",
        (license_number, doc_url, now, g.seller_id), commit=True)
    return jsonify({"message": "Agent documents submitted. Waiting for admin approval.", "agent_status": "pending"})


@app.route("/api/agent/status", methods=["GET"])
@login_required
def agent_status():
    seller = execute(
        """SELECT agent_status, agent_license_number, agent_doc_url, agent_submitted_at, shop_name
           FROM sellers WHERE id = ?""", (g.seller_id,), fetchone=True)
    if not seller:
        return jsonify({"error": "Not found"}), 404
    return jsonify(seller)


@app.route("/api/admin/agents/pending", methods=["GET"])
def admin_pending_agents():
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    rows = execute(
        """SELECT id, username, email, shop_name, whatsapp, agent_license_number,
                  agent_doc_url, agent_status, agent_submitted_at, created_at
           FROM sellers WHERE agent_status = 'pending' ORDER BY agent_submitted_at DESC""",
        fetchall=True)
    return jsonify(rows or [])


@app.route("/api/admin/agents/<int:seller_id>/approve", methods=["POST"])
def admin_approve_agent(seller_id):
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    execute("UPDATE sellers SET agent_status = 'approved' WHERE id = ?", (seller_id,), commit=True)
    create_notification(seller_id, "Agent Approved", "You can now list houses and hostels.", "agentVerify")
    return jsonify({"message": "Agent approved", "id": seller_id})


@app.route("/api/admin/agents/<int:seller_id>/reject", methods=["POST"])
def admin_reject_agent(seller_id):
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    execute("UPDATE sellers SET agent_status = 'rejected' WHERE id = ?", (seller_id,), commit=True)
    return jsonify({"message": "Agent rejected", "id": seller_id})



# ---------- In-app Chat ----------
@app.route("/api/chat/start", methods=["POST"])
def chat_start():
    data = request.get_json(silent=True) or {}
    buyer_name = (data.get("buyer_name") or "Guest").strip()[:80]
    buyer_email = (data.get("buyer_email") or "").strip() or None
    body = (data.get("message") or "").strip()
    if not body:
        return jsonify({"error": "Message required"}), 400

    product_id = data.get("product_id")
    property_id = data.get("property_id")
    seller_id = None
    subject = "Inquiry"

    if product_id:
        p = execute("SELECT id, name, seller_id, seller FROM products WHERE id = ?", (product_id,), fetchone=True)
        if not p:
            return jsonify({"error": "Product not found"}), 404
        seller_id = p.get("seller_id")
        subject = f"Product: {p['name']}"
    elif property_id:
        p = execute("SELECT id, title, seller_id, agent_name FROM properties WHERE id = ?", (property_id,), fetchone=True)
        if not p:
            return jsonify({"error": "Property not found"}), 404
        seller_id = p.get("seller_id")
        subject = f"Property: {p['title']}"
    else:
        return jsonify({"error": "product_id or property_id required"}), 400

    now = datetime.now(timezone.utc).isoformat()
    if USE_POSTGRES:
        execute(
            """INSERT INTO conversations (product_id, property_id, buyer_name, buyer_email, seller_id, subject, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (product_id, property_id, buyer_name, buyer_email, seller_id, subject, now, now), commit=True)
        conv = execute("SELECT id FROM conversations ORDER BY id DESC LIMIT 1", fetchone=True)
        conv_id = conv["id"]
    else:
        cur = execute(
            """INSERT INTO conversations (product_id, property_id, buyer_name, buyer_email, seller_id, subject, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (product_id, property_id, buyer_name, buyer_email, seller_id, subject, now, now), commit=True)
        conv_id = cur.lastrowid

    execute(
        "INSERT INTO messages (conversation_id, sender_type, sender_name, body, created_at) VALUES (?, 'buyer', ?, ?, ?)",
        (conv_id, buyer_name, body, now), commit=True)

    if seller_id:
        create_notification(seller_id, "New message", f"{buyer_name}: {body[:80]}", f"?chat={conv_id}")

    return jsonify({"conversation_id": conv_id, "message": "Conversation started"}), 201


@app.route("/api/chat/<int:conv_id>/messages", methods=["GET"])
def chat_messages(conv_id):
    conv = execute("SELECT * FROM conversations WHERE id = ?", (conv_id,), fetchone=True)
    if not conv:
        return jsonify({"error": "Not found"}), 404
    msgs = execute(
        "SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC",
        (conv_id,), fetchall=True)
    return jsonify({"conversation": conv, "messages": msgs or []})


@app.route("/api/chat/<int:conv_id>/messages", methods=["POST"])
def chat_send(conv_id):
    data = request.get_json(silent=True) or {}
    body = (data.get("message") or "").strip()
    if not body:
        return jsonify({"error": "Message required"}), 400

    conv = execute("SELECT * FROM conversations WHERE id = ?", (conv_id,), fetchone=True)
    if not conv:
        return jsonify({"error": "Not found"}), 404

    # Seller reply requires login matching seller_id
    sender_type = data.get("sender_type") or "buyer"
    sender_name = (data.get("sender_name") or "Guest").strip()[:80]

    if sender_type == "seller":
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Login required to reply as seller"}), 401
        payload = decode_token(auth[7:])
        if not payload or payload.get("seller_id") != conv.get("seller_id"):
            return jsonify({"error": "Not your conversation"}), 403
        seller = execute("SELECT shop_name FROM sellers WHERE id = ?", (conv["seller_id"],), fetchone=True)
        sender_name = seller["shop_name"] if seller else "Seller"

    now = datetime.now(timezone.utc).isoformat()
    execute(
        "INSERT INTO messages (conversation_id, sender_type, sender_name, body, created_at) VALUES (?, ?, ?, ?, ?)",
        (conv_id, sender_type, sender_name, body, now), commit=True)
    execute("UPDATE conversations SET updated_at = ? WHERE id = ?", (now, conv_id), commit=True)

    if sender_type == "buyer" and conv.get("seller_id"):
        create_notification(conv["seller_id"], "New message", f"{sender_name}: {body[:80]}", f"?chat={conv_id}")

    return jsonify({"message": "Sent"}), 201


@app.route("/api/chat/my", methods=["GET"])
@login_required
def chat_my():
    rows = execute(
        """SELECT c.*, 
           (SELECT body FROM messages WHERE conversation_id = c.id ORDER BY id DESC LIMIT 1) as last_message
           FROM conversations c WHERE c.seller_id = ? ORDER BY c.updated_at DESC""",
        (g.seller_id,), fetchall=True)
    return jsonify(rows or [])


# ---------- Notifications ----------
@app.route("/api/notifications", methods=["GET"])
@login_required
def list_notifications():
    rows = execute(
        "SELECT * FROM notifications WHERE seller_id = ? ORDER BY created_at DESC LIMIT 50",
        (g.seller_id,), fetchall=True)
    unread = execute(
        "SELECT COUNT(*) as cnt FROM notifications WHERE seller_id = ? AND is_read = 0",
        (g.seller_id,), fetchone=True)
    return jsonify({"notifications": rows or [], "unread": unread["cnt"] if unread else 0})


@app.route("/api/notifications/read", methods=["POST"])
@login_required
def read_notifications():
    data = request.get_json(silent=True) or {}
    nid = data.get("id")
    if nid:
        execute("UPDATE notifications SET is_read = 1 WHERE id = ? AND seller_id = ?", (nid, g.seller_id), commit=True)
    else:
        execute("UPDATE notifications SET is_read = 1 WHERE seller_id = ?", (g.seller_id,), commit=True)
    return jsonify({"message": "ok"})


# ---------- Analytics ----------
@app.route("/api/analytics/view", methods=["POST"])
def track_view():
    data = request.get_json(silent=True) or {}
    now = datetime.now(timezone.utc).isoformat()
    execute(
        "INSERT INTO page_views (path, product_id, property_id, created_at) VALUES (?, ?, ?, ?)",
        (data.get("path"), data.get("product_id"), data.get("property_id"), now), commit=True)
    return jsonify({"ok": True})


@app.route("/api/admin/analytics", methods=["GET"])
def admin_analytics():
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    sellers = execute("SELECT COUNT(*) as c FROM sellers", fetchone=True)
    products = execute("SELECT COUNT(*) as c FROM products", fetchone=True)
    properties = execute("SELECT COUNT(*) as c FROM properties", fetchone=True)
    orders = execute("SELECT COUNT(*) as c FROM orders", fetchone=True)
    paid = execute("SELECT COUNT(*) as c, COALESCE(SUM(amount),0) as revenue FROM orders WHERE payment_status = 'paid'", fetchone=True)
    inquiries = execute("SELECT COUNT(*) as c FROM inquiries", fetchone=True)
    views = execute("SELECT COUNT(*) as c FROM page_views", fetchone=True)
    pending_kyc = execute("SELECT COUNT(*) as c FROM sellers WHERE kyc_status = 'pending'", fetchone=True)
    pending_agents = execute("SELECT COUNT(*) as c FROM sellers WHERE agent_status = 'pending'", fetchone=True)
    msgs = execute("SELECT COUNT(*) as c FROM messages", fetchone=True)

    return jsonify({
        "sellers": sellers["c"] if sellers else 0,
        "products": products["c"] if products else 0,
        "properties": properties["c"] if properties else 0,
        "orders_total": orders["c"] if orders else 0,
        "orders_paid": paid["c"] if paid else 0,
        "revenue": float(paid["revenue"] or 0) if paid else 0,
        "inquiries": inquiries["c"] if inquiries else 0,
        "page_views": views["c"] if views else 0,
        "pending_kyc": pending_kyc["c"] if pending_kyc else 0,
        "pending_agents": pending_agents["c"] if pending_agents else 0,
        "messages": msgs["c"] if msgs else 0,
        "currency": get_setting("currency", "GHS"),
    })


# ---------- Face check helper (optional automated assist) ----------
@app.route("/api/kyc/face-check", methods=["POST"])
@login_required
def kyc_face_check():
    """
    Lightweight automated assist for KYC.
    Real biometric matching needs a provider (AWS Rekognition, etc.).
    This endpoint validates that selfie + ID URLs exist and marks assist status.
    """
    data = request.get_json(silent=True) or {}
    selfie = (data.get("selfie_url") or "").strip()
    id_doc = (data.get("id_document_url") or "").strip()
    if not selfie or not id_doc:
        return jsonify({"error": "selfie_url and id_document_url required"}), 400

    # Heuristic: both must be image URLs from our upload host or http
    ok = selfie.startswith("http") and id_doc.startswith("http")
    result = {
        "automated_check": "passed_basic" if ok else "failed_basic",
        "message": "Basic document presence check passed. Admin will still review identity."
                   if ok else "Invalid image URLs",
        "note": "Full face matching requires an external AI provider API key."
    }
    return jsonify(result)




@app.route("/api/kyc/face-match", methods=["POST"])
@login_required
def kyc_face_match_result():
    data = request.get_json(silent=True) or {}
    score = data.get("face_match_score")
    label = data.get("face_match_label")
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None
    execute(
        "UPDATE sellers SET face_match_score = ?, face_match_label = ? WHERE id = ?",
        (score, label, g.seller_id), commit=True
    )
    return jsonify({"message": "Face match stored", "face_match_score": score, "face_match_label": label})


# ---------- Web Push ----------
@app.route("/api/push/vapid-public-key", methods=["GET"])
def push_vapid_public():
    return jsonify({
        "publicKey": VAPID_PUBLIC_KEY,
        "enabled": bool(VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY),
    })


@app.route("/api/push/subscribe", methods=["POST"])
@login_required
def push_subscribe():
    data = request.get_json(silent=True) or {}
    endpoint = data.get("endpoint")
    keys = data.get("keys") or {}
    if not endpoint or not keys.get("p256dh") or not keys.get("auth"):
        return jsonify({"error": "Invalid subscription"}), 400
    now = datetime.now(timezone.utc).isoformat()
    existing = execute("SELECT id FROM push_subscriptions WHERE endpoint = ?", (endpoint,), fetchone=True)
    if existing:
        execute(
            "UPDATE push_subscriptions SET seller_id = ?, p256dh = ?, auth = ? WHERE endpoint = ?",
            (g.seller_id, keys["p256dh"], keys["auth"], endpoint), commit=True
        )
    else:
        execute(
            "INSERT INTO push_subscriptions (seller_id, endpoint, p256dh, auth, created_at) VALUES (?, ?, ?, ?, ?)",
            (g.seller_id, endpoint, keys["p256dh"], keys["auth"], now), commit=True
        )
    return jsonify({"message": "Subscribed to push notifications"})


@app.route("/api/push/unsubscribe", methods=["POST"])
@login_required
def push_unsubscribe():
    data = request.get_json(silent=True) or {}
    endpoint = data.get("endpoint")
    if endpoint:
        execute("DELETE FROM push_subscriptions WHERE endpoint = ? AND seller_id = ?", (endpoint, g.seller_id), commit=True)
    return jsonify({"message": "Unsubscribed"})


@app.route("/api/kyc/face-match-result", methods=["POST"])
@login_required
def kyc_face_match_result():
    """Store client-side face-api.js match score with the seller KYC record."""
    data = request.get_json(silent=True) or {}
    score = data.get("match_score")  # 0-1
    label = data.get("label") or "unknown"
    try:
        score_f = float(score) if score is not None else None
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid score"}), 400

    # Store in bio field prefix or agent field - use a dedicated note via notification + seller bio append
    # Better: store in verification via updating a JSON-ish note on seller - use full_name_profile? 
    # Use agent_license temporary no - add column via try alter
    try:
        if USE_POSTGRES:
            execute("ALTER TABLE sellers ADD COLUMN IF NOT EXISTS face_match_score REAL", commit=True)
            execute("ALTER TABLE sellers ADD COLUMN IF NOT EXISTS face_match_label TEXT", commit=True)
        else:
            cols = execute("PRAGMA table_info(sellers)", fetchall=True)
            names = [c["name"] for c in (cols or [])]
            if "face_match_score" not in names:
                execute("ALTER TABLE sellers ADD COLUMN face_match_score REAL", commit=True)
            if "face_match_label" not in names:
                execute("ALTER TABLE sellers ADD COLUMN face_match_label TEXT", commit=True)
    except Exception as e:
        print(f"face_match cols: {e}")

    execute(
        "UPDATE sellers SET face_match_score = ?, face_match_label = ? WHERE id = ?",
        (score_f, label, g.seller_id), commit=True
    )
    return jsonify({"message": "Face match result saved", "match_score": score_f, "label": label})



# ---------- Reports / Disputes ----------
@app.route("/api/reports", methods=["POST"])
def create_report():
    data = request.get_json(silent=True) or {}
    reason = (data.get("reason") or "").strip()
    if not reason:
        return jsonify({"error": "Reason is required"}), 400
    target_type = (data.get("target_type") or "product").strip().lower()
    if target_type not in ("product", "property", "seller", "other"):
        target_type = "other"
    now = datetime.now(timezone.utc).isoformat()
    execute(
        """INSERT INTO reports (reporter_name, reporter_email, target_type, target_id, target_name, reason, details, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?)""",
        (
            (data.get("reporter_name") or "Anonymous").strip()[:80],
            (data.get("reporter_email") or "").strip() or None,
            target_type,
            data.get("target_id"),
            (data.get("target_name") or "").strip() or None,
            reason[:200],
            (data.get("details") or "").strip()[:2000] or None,
            now,
        ),
        commit=True,
    )
    return jsonify({"message": "Report submitted. Our team will review it."}), 201


@app.route("/api/admin/reports", methods=["GET"])
def admin_reports():
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    status = request.args.get("status")  # open, resolved, dismissed
    if status:
        rows = execute("SELECT * FROM reports WHERE status = ? ORDER BY created_at DESC LIMIT 100", (status,), fetchall=True)
    else:
        rows = execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT 100", fetchall=True)
    return jsonify(rows or [])


@app.route("/api/admin/reports/<int:report_id>", methods=["POST"])
def admin_update_report(report_id):
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    status = (data.get("status") or "").strip().lower()
    if status not in ("open", "resolved", "dismissed"):
        return jsonify({"error": "status must be open, resolved, or dismissed"}), 400
    execute("UPDATE reports SET status = ? WHERE id = ?", (status, report_id), commit=True)
    return jsonify({"message": "Report updated", "id": report_id, "status": status})



# ---------- Backup / Export ----------
def _table_rows(table_name):
    try:
        return execute(f"SELECT * FROM {table_name}", fetchall=True) or []
    except Exception:
        return []


@app.route("/api/admin/backup", methods=["GET"])
def admin_full_backup():
    """Full JSON backup of critical tables for disaster recovery."""
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "database_engine": "postgresql" if USE_POSTGRES else "sqlite",
        "persistent": USE_POSTGRES,
        "tables": {
            "sellers": _table_rows("sellers"),
            "products": _table_rows("products"),
            "properties": _table_rows("properties"),
            "orders": _table_rows("orders"),
            "inquiries": _table_rows("inquiries"),
            "ratings": _table_rows("ratings"),
            "comments": _table_rows("comments"),
            "reports": _table_rows("reports"),
            "conversations": _table_rows("conversations"),
            "messages": _table_rows("messages"),
            "notifications": _table_rows("notifications"),
            "settings": _table_rows("settings"),
            "buyers": _table_rows("buyers"),
        },
    }

    from flask import Response
    import json as _json
    body = _json.dumps(payload, default=str, indent=2)
    filename = f"sungarland-backup-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json"
    return Response(
        body,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/admin/export/<table_name>", methods=["GET"])
def admin_export_table(table_name):
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    allowed = {
        "sellers", "products", "properties", "orders", "inquiries",
        "ratings", "comments", "reports", "conversations", "messages",
        "notifications", "settings", "buyers",
    }
    if table_name not in allowed:
        return jsonify({"error": "Unknown table"}), 404

    rows = _table_rows(table_name)
    fmt = (request.args.get("format") or "json").lower()

    if fmt == "csv":
        import csv
        import io
        from flask import Response
        if not rows:
            return Response("No data\n", mimetype="text/csv")
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()), extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k) for k in rows[0].keys()})
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{table_name}.csv"'},
        )

    return jsonify({
        "table": table_name,
        "count": len(rows),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "rows": rows,
    })


@app.route("/api/admin/db-status", methods=["GET"])
def admin_db_status():
    admin_key = request.headers.get("X-Admin-Key") or request.args.get("key")
    if not admin_key or admin_key != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    counts = {}
    for t in ("sellers", "products", "properties", "orders", "reports", "messages"):
        try:
            row = execute(f"SELECT COUNT(*) as c FROM {t}", fetchone=True)
            counts[t] = row["c"] if row else 0
        except Exception:
            counts[t] = None

    return jsonify({
        "engine": "postgresql" if USE_POSTGRES else "sqlite",
        "persistent": USE_POSTGRES,
        "database_url_set": bool(DATABASE_URL),
        "require_postgres": REQUIRE_POSTGRES,
        "sqlite_path": SQLITE_PATH if not USE_POSTGRES else None,
        "table_counts": counts,
        "recommendation": (
            "Postgres is active — good for production."
            if USE_POSTGRES
            else "Attach Railway Postgres and set DATABASE_URL, then set REQUIRE_POSTGRES=1."
        ),
    })


# ---------- Main ----------
if __name__ == "__main__":
    with app.app_context():
        init_db()
    print(f"Starting WhatsApp Market API on http://0.0.0.0:{PORT}")
    print(f"Database: {'PostgreSQL' if USE_POSTGRES else 'SQLite'}")
    print("Auth endpoints: /api/auth/register  /api/auth/login  /api/auth/me")
    print("Admin endpoints: /api/admin/sellers  /api/admin/stats")
    app.run(host="0.0.0.0", port=PORT, debug=not USE_POSTGRES)
