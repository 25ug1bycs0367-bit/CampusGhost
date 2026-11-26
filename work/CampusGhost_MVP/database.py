"""Encrypted, pseudonymous data storage for the CampusGhost MVP.

Sensitive platform fields are AES-GCM encrypted before being written to SQLite.
The application decrypts the minimum required fields into backend memory for
validation and investigation; the AI/UI receive pseudonymous identifiers only.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone, date
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_PATH = Path(__file__).resolve().parent / "data" / "campusghost.db"
KEY_PATH = Path(__file__).resolve().parent / "data" / "campusghost.key"

PLATFORM_ALIASES = {
    "lms": ("contineo_portal", "Contineo Portal (LMS)"),
    "contineo": ("contineo_portal", "Contineo Portal (LMS)"),
    "contineo portal": ("contineo_portal", "Contineo Portal (LMS)"),
    "contineo portal (lms)": ("contineo_portal", "Contineo Portal (LMS)"),
    "moodle": ("moodle_lms", "Moodle LMS"),
    "moodle lms": ("moodle_lms", "Moodle LMS"),
    "department drive": ("department_drive", "Department Drive"),
    "github-like": ("project_repository", "Project Repository"),
    "project repository": ("project_repository", "Project Repository"),
    "research portal": ("research_portal", "Research Portal"),
}


def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def canonical_platform(platform_name):
    key = str(platform_name or "").strip().lower()
    if key in PLATFORM_ALIASES:
        return PLATFORM_ALIASES[key]
    slug = re.sub(r"[^a-z0-9]+", "_", key).strip("_") or "unknown_platform"
    return slug, str(platform_name or "Unknown platform").strip()


def _encryption_key():
    """Load a 256-bit key from env or create a local, git-ignored dev key."""
    configured = os.getenv("CAMPUSGHOST_ENCRYPTION_KEY", "").strip()
    if configured:
        try:
            key = base64.urlsafe_b64decode(configured + "=" * (-len(configured) % 4))
        except Exception as exc:
            raise RuntimeError("CAMPUSGHOST_ENCRYPTION_KEY must be URL-safe base64.") from exc
        if len(key) != 32:
            raise RuntimeError("CAMPUSGHOST_ENCRYPTION_KEY must decode to exactly 32 bytes.")
        return key

    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if KEY_PATH.exists():
        key = base64.urlsafe_b64decode(KEY_PATH.read_text(encoding="ascii").strip())
        if len(key) != 32:
            raise RuntimeError("The local CampusGhost encryption key is invalid.")
        return key

    key = secrets.token_bytes(32)
    encoded = base64.urlsafe_b64encode(key).decode("ascii")
    fd = os.open(str(KEY_PATH), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(encoded)
    return key


def encrypt_json(value):
    """Return nonce+ciphertext using AES-256-GCM authenticated encryption."""
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    encrypted = AESGCM(_encryption_key()).encrypt(nonce, plaintext, None)
    return nonce + encrypted


def decrypt_json(blob, default=None):
    if blob is None:
        return default
    raw = bytes(blob)
    if len(raw) < 29:
        raise ValueError("Encrypted CampusGhost record is truncated.")
    plaintext = AESGCM(_encryption_key()).decrypt(raw[:12], raw[12:], None)
    return json.loads(plaintext.decode("utf-8"))


def _pseudonym_key():
    # Derive a separate key for stable HMAC tokens; do not reuse the AES key directly.
    return hmac.new(_encryption_key(), b"CampusGhost:pseudonymization-key:v1", hashlib.sha256).digest()


def pseudonym(kind, source_ref):
    """Create a stable keyed pseudonym without storing the source identifier."""
    value = str(source_ref or "").strip().casefold()
    if not value:
        raise ValueError("A pseudonymous source reference is required.")
    digest = hmac.new(_pseudonym_key(), f"{kind}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()[:16].upper()
    prefix = {"person": "CG-P", "account": "CG-A", "permission": "CG-G"}.get(kind, "CG-X")
    return f"{prefix}-{digest}"


@contextmanager
def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def _ensure_column(con, table, column, definition):
    columns = {row[1] for row in con.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _create_schema(con):
    con.executescript("""
    CREATE TABLE IF NOT EXISTS persons (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        campus_status TEXT NOT NULL,
        department TEXT NOT NULL,
        email TEXT NOT NULL,
        person_token TEXT,
        campus_status_enc BLOB,
        department_enc BLOB,
        identity_enc BLOB,
        institutional_role_enc BLOB
    );
    CREATE TABLE IF NOT EXISTS platform_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        person_id INTEGER NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
        platform_key TEXT NOT NULL,
        platform_name TEXT NOT NULL,
        external_account_id TEXT NOT NULL,
        external_username TEXT,
        external_email TEXT,
        account_status TEXT NOT NULL DEFAULT 'PROTECTED',
        source_type TEXT NOT NULL DEFAULT 'simulated',
        last_synced_at TEXT NOT NULL,
        account_token TEXT,
        external_account_id_enc BLOB,
        external_username_enc BLOB,
        external_email_enc BLOB,
        account_status_enc BLOB,
        UNIQUE(platform_key, external_account_id)
    );
    CREATE INDEX IF NOT EXISTS idx_platform_accounts_person ON platform_accounts(person_id);
    CREATE TABLE IF NOT EXISTS permissions (
        id INTEGER PRIMARY KEY,
        person_id INTEGER NOT NULL REFERENCES persons(id),
        platform TEXT NOT NULL,
        resource TEXT NOT NULL,
        role TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT,
        platform_account_id INTEGER REFERENCES platform_accounts(id),
        permission_token TEXT,
        payload_enc BLOB
    );
    CREATE TABLE IF NOT EXISTS lifecycle_events (
        id INTEGER PRIMARY KEY,
        person_id INTEGER NOT NULL REFERENCES persons(id),
        event_type TEXT NOT NULL,
        event_date TEXT NOT NULL,
        details TEXT NOT NULL,
        payload_enc BLOB
    );
    CREATE TABLE IF NOT EXISTS investigations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        person_id INTEGER NOT NULL,
        status TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        reason TEXT NOT NULL,
        evidence TEXT NOT NULL,
        created_at TEXT NOT NULL,
        decision TEXT,
        completed_at TEXT,
        person_token TEXT,
        result_enc BLOB
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER,
        person_id INTEGER,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        created_at TEXT NOT NULL,
        person_token TEXT,
        details_enc BLOB
    );
    """)

    # Add protection fields to earlier MVP databases without changing their IDs.
    additions = {
        "persons": [("person_token", "TEXT"), ("campus_status_enc", "BLOB"), ("department_enc", "BLOB"),
                     ("institutional_role_enc", "BLOB")],
        "platform_accounts": [("account_token", "TEXT"), ("external_account_id_enc", "BLOB"),
                               ("external_username_enc", "BLOB"), ("external_email_enc", "BLOB"),
                               ("account_status_enc", "BLOB")],
        "permissions": [("platform_account_id", "INTEGER"), ("permission_token", "TEXT"), ("payload_enc", "BLOB")],
        "lifecycle_events": [("payload_enc", "BLOB")],
        "investigations": [("person_token", "TEXT"), ("result_enc", "BLOB")],
        "audit_logs": [("person_token", "TEXT"), ("details_enc", "BLOB")],
    }
    for table, columns in additions.items():
        for column, definition in columns:
            _ensure_column(con, table, column, definition)
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_token ON permissions(permission_token)")


DEMO_PEOPLE = [
    {
        "person_ref": "campus-person-001", "campus_status": "Current student",
        "department": "Computer Science", "institutional_role": "Student",
        "full_name": "Aarav Mehta", "email": "aarav.demo@campus.test",
    },
    {
        "person_ref": "campus-person-002", "campus_status": "Former project member",
        "department": "Information Technology", "institutional_role": "Project Member",
        "full_name": "Mira Nair", "email": "mira.demo@campus.test",
    },
    {
        "person_ref": "campus-person-003", "campus_status": "Graduate - research assistant",
        "department": "Electronics", "institutional_role": "Research Assistant",
        "full_name": "Kabir Rao", "email": "kabir.demo@campus.test",
    },
    {
        "person_ref": "campus-person-004", "campus_status": "Internship completed",
        "department": "Computer Science", "institutional_role": "Intern",
        "full_name": "Isha Menon", "email": "isha.demo@campus.test",
    },
    {
        "person_ref": "campus-faculty-005", "campus_status": "Current faculty",
        "department": "Computer Science", "institutional_role": "Faculty - Assistant Professor",
        "full_name": "Dr. Ananya Rao", "email": "ananya.rao.demo@campus.test",
    },
    {
        "person_ref": "campus-faculty-006", "campus_status": "Current faculty",
        "department": "Physics", "institutional_role": "Faculty - Professor",
        "full_name": "Dr. Vikram Shah", "email": "vikram.shah.demo@campus.test",
    },
    {
        "person_ref": "campus-faculty-007", "campus_status": "Former faculty - employment ended",
        "department": "Information Technology", "institutional_role": "Former Faculty - Associate Professor",
        "full_name": "Dr. Rohan Iyer", "email": "rohan.iyer.demo@campus.test",
    },
    {
        "person_ref": "campus-faculty-008", "campus_status": "Former faculty - resigned",
        "department": "Mathematics", "institutional_role": "Former Faculty - Lecturer",
        "full_name": "Dr. Kavya Menon", "email": "kavya.menon.demo@campus.test",
    },
]

DEMO_EVENTS = [
    ("campus-person-002", "Project exit", "2026-11-20", "Former project member was removed from the Campus Security project."),
    ("campus-person-003", "Graduation", "2026-06-15", "Graduation recorded; an active research-assistant relationship remains."),
    ("campus-person-004", "Internship completed", "2026-11-18", "Internship period has ended."),
    ("campus-faculty-007", "Employment ended", "2026-08-31", "Faculty employment ended; the Contineo Portal account was not disabled."),
    ("campus-faculty-008", "Employment ended", "2026-09-30", "Faculty member resigned; the Contineo Portal account remains active."),
]


def _insert_person(con, person):
    """Insert a fictional person with identity and institutional role encrypted."""
    person_token = pseudonym("person", person["person_ref"])
    existing = con.execute("SELECT id FROM persons WHERE person_token=?", (person_token,)).fetchone()
    if existing:
        return existing[0]
    con.execute("""
        INSERT INTO persons
        (name,campus_status,department,email,person_token,campus_status_enc,department_enc,identity_enc,institutional_role_enc)
        VALUES(?, 'PROTECTED','PROTECTED','',?,?,?,?,?)
    """, (person_token, person_token, encrypt_json(person["campus_status"]),
          encrypt_json(person["department"]), encrypt_json({
              "full_name": person["full_name"],
              "email": person["email"],
              "campus_person_ref": person["person_ref"],
              "institutional_role": person["institutional_role"],
          }), encrypt_json(person.get("institutional_role", "Unknown role"))))
    return con.execute("SELECT last_insert_rowid()").fetchone()[0]


def seed(con):
    """Idempotently ensure the fictional campus and faculty demo records exist."""
    person_ids = {}
    for person in DEMO_PEOPLE:
        person_ids[person["person_ref"]] = _insert_person(con, person)

    for person_ref, event_type, event_date, details in DEMO_EVENTS:
        person_id = person_ids[person_ref]
        already_exists = False
        for row in con.execute("SELECT payload_enc FROM lifecycle_events WHERE person_id=?", (person_id,)).fetchall():
            payload = decrypt_json(row["payload_enc"], {})
            if payload.get("event_type") == event_type:
                already_exists = True
                break
        if not already_exists:
            con.execute("""
                INSERT INTO lifecycle_events (person_id,event_type,event_date,details,payload_enc)
                VALUES(?, 'PROTECTED','PROTECTED','ENCRYPTED',?)
            """, (person_id, encrypt_json({
                "event_type": event_type, "event_date": event_date, "details": details
            })))


def _protect_legacy_rows(con):
    """Encrypt any plaintext fields found in older local demo databases, then clear them."""
    for row in con.execute("SELECT * FROM persons").fetchall():
        if not row["person_token"]:
            legacy_refs = {
                "aarav.demo@campus.test": "campus-person-001",
                "mira.demo@campus.test": "campus-person-002",
                "kabir.demo@campus.test": "campus-person-003",
                "isha.demo@campus.test": "campus-person-004",
            }
            source = legacy_refs.get(str(row["email"] or "").lower(), row["email"] or f"legacy-person-{row['id']}")
            token = pseudonym("person", source)
            status_enc = row["campus_status_enc"] or encrypt_json(row["campus_status"])
            dept_enc = row["department_enc"] or encrypt_json(row["department"])
            legacy_identity = decrypt_json(row["identity_enc"], {}) if row["identity_enc"] else {}
            role_enc = row["institutional_role_enc"] or encrypt_json(legacy_identity.get("institutional_role", "Unknown role"))
            con.execute("""
                UPDATE persons SET person_token=?, name=?, email='', campus_status='PROTECTED',
                    department='PROTECTED', campus_status_enc=?, department_enc=?, identity_enc=?,
                    institutional_role_enc=? WHERE id=?
            """, (token, token, status_enc, dept_enc, encrypt_json({
                "full_name": row["name"], "email": row["email"], "campus_person_ref": source
            }), role_enc, row["id"]))
        else:
            token = row["person_token"]
            # Never leave a real-looking name/email in the clear columns.
            con.execute("UPDATE persons SET name=?, email='', campus_status='PROTECTED', department='PROTECTED' WHERE id=?",
                        (token, row["id"]))
            if not row["campus_status_enc"]:
                con.execute("UPDATE persons SET campus_status_enc=? WHERE id=?",
                            (encrypt_json("Unknown"), row["id"]))
            if not row["department_enc"]:
                con.execute("UPDATE persons SET department_enc=? WHERE id=?",
                            (encrypt_json("Unknown"), row["id"]))
            if not row["institutional_role_enc"]:
                # Migration-only read of the protected identity envelope. Agent tools never read identity_enc.
                legacy_identity = decrypt_json(row["identity_enc"], {}) if row["identity_enc"] else {}
                con.execute("UPDATE persons SET institutional_role_enc=? WHERE id=?",
                            (encrypt_json(legacy_identity.get("institutional_role", "Unknown role")), row["id"]))
            if not row["identity_enc"]:
                con.execute("UPDATE persons SET identity_enc=? WHERE id=?",
                            (encrypt_json({"full_name": "Unmapped legacy identity", "email": ""}), row["id"]))
            if not row["identity_enc"]:
                con.execute("UPDATE persons SET identity_enc=? WHERE id=?",
                            (encrypt_json({"full_name": "Unmapped legacy identity", "email": ""}), row["id"]))

    for row in con.execute("SELECT * FROM platform_accounts").fetchall():
        if not row["external_account_id_enc"]:
            raw_id = row["external_account_id"] or f"legacy-account-{row['id']}"
            account_token = pseudonym("account", f"{row['platform_key']}:{raw_id}")
            con.execute("""
                UPDATE platform_accounts SET account_token=?, external_account_id=?,
                    external_account_id_enc=?, external_username_enc=?, external_email_enc=?,
                    account_status_enc=?, external_username=NULL, external_email=NULL,
                    account_status='PROTECTED' WHERE id=?
            """, (account_token, account_token, encrypt_json(raw_id),
                  encrypt_json(row["external_username"]), encrypt_json(row["external_email"]),
                  encrypt_json(row["account_status"]), row["id"]))
        else:
            token = row["account_token"] or pseudonym("account", f"{row['platform_key']}:{row['external_account_id']}")
            con.execute("UPDATE platform_accounts SET account_token=?, external_account_id=?, external_username=NULL, external_email=NULL, account_status='PROTECTED' WHERE id=?",
                        (token, token, row["id"]))

    for row in con.execute("SELECT * FROM permissions").fetchall():
        if not row["payload_enc"]:
            payload = {"platform": row["platform"], "resource": row["resource"],
                       "role": row["role"], "active": bool(row["active"]),
                       "expires_at": row["expires_at"]}
            account_token = str(row["person_id"])
            if row["platform_account_id"]:
                linked = con.execute("SELECT account_token FROM platform_accounts WHERE id=?",
                                     (row["platform_account_id"],)).fetchone()
                if linked and linked[0]:
                    account_token = linked[0]
            grant_token = pseudonym("permission", f"{account_token}:{row['resource']}")
            con.execute("""
                UPDATE permissions SET permission_token=?, payload_enc=?, platform='PROTECTED',
                    resource='PROTECTED', role='PROTECTED', active=0, expires_at=NULL WHERE id=?
            """, (grant_token, encrypt_json(payload), row["id"]))

    for row in con.execute("SELECT * FROM lifecycle_events").fetchall():
        if not row["payload_enc"]:
            payload = {"event_type": row["event_type"], "event_date": row["event_date"],
                       "details": row["details"]}
            con.execute("""
                UPDATE lifecycle_events SET payload_enc=?, event_type='PROTECTED',
                    event_date='PROTECTED', details='ENCRYPTED' WHERE id=?
            """, (encrypt_json(payload), row["id"]))

    for row in con.execute("SELECT * FROM investigations").fetchall():
        if not row["result_enc"]:
            person = con.execute("SELECT person_token FROM persons WHERE id=?", (row["person_id"],)).fetchone()
            con.execute("""
                UPDATE investigations SET person_token=?, result_enc=?, reason='ENCRYPTED',
                    evidence='ENCRYPTED', status='Report issued' WHERE id=?
            """, (person[0] if person else "UNKNOWN", encrypt_json({
                "recommendation": row["recommendation"],
                "reason": row["reason"], "evidence": row["evidence"]
            }), row["id"]))
            con.execute("UPDATE investigations SET recommendation='ENCRYPTED' WHERE id=?", (row["id"],))

    for row in con.execute("SELECT * FROM audit_logs").fetchall():
        person_token = None
        if row["person_id"] is not None:
            person = con.execute("SELECT person_token FROM persons WHERE id=?", (row["person_id"],)).fetchone()
            person_token = person[0] if person else "UNKNOWN"
        if not row["details_enc"]:
            con.execute("""
                UPDATE audit_logs SET person_token=?, details_enc=?, details='ENCRYPTED' WHERE id=?
            """, (person_token, encrypt_json(row["details"]), row["id"]))
        elif not row["person_token"]:
            con.execute("UPDATE audit_logs SET person_token=? WHERE id=?", (person_token, row["id"]))


def _remove_legacy_moodle_demo_accounts(con):
    """Remove only old simulated Moodle fixture rows replaced by the Contineo demo."""
    rows = con.execute(
        "SELECT id FROM platform_accounts WHERE platform_key='moodle_lms' AND source_type='simulated'"
    ).fetchall()
    for row in rows:
        account_id = row[0]
        con.execute("DELETE FROM permissions WHERE platform_account_id=?", (account_id,))
        con.execute("DELETE FROM platform_accounts WHERE id=?", (account_id,))


def init_db():
    # Initialise/validate the key before creating any encrypted records.
    _encryption_key()
    with connect() as con:
        _create_schema(con)
        _remove_legacy_moodle_demo_accounts(con)
        seed(con)
        _protect_legacy_rows(con)


def _decrypt_permission(row):
    payload = decrypt_json(row["payload_enc"], {})
    return {
        "id": row["id"], "permission_token": row["permission_token"],
        "platform": payload.get("platform", "Unknown platform"),
        "resource": payload.get("resource", "Unknown resource"),
        "role": payload.get("role", "Unknown role"),
        "active": bool(payload.get("active", False)),
        "expires_at": payload.get("expires_at"),
        "platform_account_id": row["platform_account_id"],
    }


def upsert_platform_snapshot(platform_key, platform_name, source_type, snapshot):
    """Validate pseudonymous source records and encrypt sensitive fields before storage."""
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("accounts"), list):
        raise ValueError("Connector response must contain an accounts list.")
    synced_accounts = 0
    synced_permissions = 0
    skipped_accounts = []
    synced_at = now()

    with connect() as con:
        for account_data in snapshot["accounts"]:
            if not isinstance(account_data, dict):
                skipped_accounts.append("Invalid account record")
                continue
            forbidden_identity_fields = {
                "person_email", "person_name", "full_name", "display_name",
                "external_username", "external_email", "email", "name",
            }
            if forbidden_identity_fields.intersection(account_data):
                skipped_accounts.append("Account contains direct identity fields; provide a pseudonymous person_ref instead")
                continue
            allowed_account_fields = {"person_ref", "external_account_id", "account_status", "permissions"}
            if set(account_data) - allowed_account_fields:
                skipped_accounts.append("Account contains unsupported fields; only pseudonymous connector fields are accepted")
                continue
            person_ref = str(account_data.get("person_ref", "")).strip()
            external_id = str(account_data.get("external_account_id", "")).strip()
            if not person_ref or not external_id:
                skipped_accounts.append("Account missing person_ref or external_account_id")
                continue

            # The same opaque person_ref must be supplied by each platform for safe correlation.
            person_token = pseudonym("person", person_ref)
            person = con.execute("SELECT id FROM persons WHERE person_token=?", (person_token,)).fetchone()
            if not person:
                con.execute("""
                    INSERT INTO persons (name,campus_status,department,email,person_token,campus_status_enc,department_enc,identity_enc,institutional_role_enc)
                    VALUES(?, 'PROTECTED','PROTECTED','',?,?,?,?,?)
                """, (person_token, person_token, encrypt_json("Unknown"), encrypt_json("Unknown"),
                      encrypt_json({"full_name": "Unmapped identity", "email": ""}), encrypt_json("Unknown role")))
                person_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
            else:
                person_id = person[0]

            account_status = str(account_data.get("account_status", "active")).lower()
            if account_status not in {"active", "disabled", "suspended"}:
                skipped_accounts.append(f"Invalid account status for {pseudonym('account', platform_key + ':' + external_id)}")
                continue
            account_token = pseudonym("account", f"{platform_key}:{external_id}")
            account = con.execute("""
                SELECT id FROM platform_accounts WHERE platform_key=? AND account_token=?
            """, (platform_key, account_token)).fetchone()
            encrypted_account_fields = (
                encrypt_json(external_id),
                encrypt_json(None),
                encrypt_json(None),
                encrypt_json(account_status),
            )
            if account:
                account_id = account[0]
                con.execute("""
                    UPDATE platform_accounts SET person_id=?, platform_name=?, external_account_id=?,
                        external_username=NULL, external_email=NULL, account_status='PROTECTED',
                        source_type=?, last_synced_at=?, account_token=?, external_account_id_enc=?,
                        external_username_enc=?, external_email_enc=?, account_status_enc=? WHERE id=?
                """, (person_id, platform_name, account_token, source_type, synced_at,
                      account_token, *encrypted_account_fields, account_id))
            else:
                con.execute("""
                    INSERT INTO platform_accounts
                    (person_id,platform_key,platform_name,external_account_id,external_username,
                     external_email,account_status,source_type,last_synced_at,account_token,
                     external_account_id_enc,external_username_enc,external_email_enc,account_status_enc)
                    VALUES(?,?,?, ?,NULL,NULL,'PROTECTED',?,?,?,?,?,?,?)
                """, (person_id, platform_key, platform_name, account_token, source_type, synced_at,
                      account_token, *encrypted_account_fields))
                account_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
            synced_accounts += 1

            grants = account_data.get("permissions", [])
            if not isinstance(grants, list):
                skipped_accounts.append(f"Permissions are not a list for {account_token}")
                continue
            seen_tokens = set()
            for grant in grants:
                if not isinstance(grant, dict):
                    skipped_accounts.append(f"Invalid permission record for {account_token}")
                    continue
                if set(grant) - {"resource", "role", "active", "expires_at"}:
                    skipped_accounts.append(f"Permission record contains unsupported fields for {account_token}")
                    continue
                resource = str(grant.get("resource", "")).strip()
                role = str(grant.get("role", "")).strip()
                active_value = grant.get("active", True)
                if not resource or not role or not isinstance(active_value, bool):
                    skipped_accounts.append(f"Invalid permission record for {account_token}")
                    continue
                expires_at = grant.get("expires_at")
                if expires_at:
                    try:
                        date.fromisoformat(str(expires_at))
                    except ValueError:
                        skipped_accounts.append(f"Invalid expiry date for {account_token}")
                        continue
                permission_token = pseudonym("permission", f"{account_token}:{resource}")
                seen_tokens.add(permission_token)
                payload = {"platform": platform_name, "resource": resource, "role": role,
                           "active": active_value, "expires_at": expires_at}
                encoded = encrypt_json(payload)
                existing = con.execute("SELECT id FROM permissions WHERE permission_token=?",
                                        (permission_token,)).fetchone()
                if existing:
                    con.execute("""
                        UPDATE permissions SET person_id=?, platform='PROTECTED', resource='PROTECTED',
                            role='PROTECTED', active=0, expires_at=NULL, platform_account_id=?, payload_enc=?
                        WHERE id=?
                    """, (person_id, account_id, encoded, existing[0]))
                else:
                    con.execute("""
                        INSERT INTO permissions
                        (person_id,platform,resource,role,active,expires_at,platform_account_id,permission_token,payload_enc)
                        VALUES(?,'PROTECTED','PROTECTED','PROTECTED',0,NULL,?,?,?)
                    """, (person_id, account_id, permission_token, encoded))
                synced_permissions += 1
            # Do not delete permissions omitted from a source snapshot: omission is not proof of revocation.

    return {"platform_key": platform_key, "platform_name": platform_name,
            "source_type": source_type, "accounts_synced": synced_accounts,
            "permissions_synced": synced_permissions, "warnings": skipped_accounts}


def get_dashboard_data():
    with connect() as con:
        stats = {
            "people_monitored": con.execute("SELECT COUNT(*) FROM persons").fetchone()[0],
            "linked_accounts": con.execute("SELECT COUNT(*) FROM platform_accounts").fetchone()[0],
            "active_permissions": sum(1 for row in con.execute("SELECT payload_enc FROM permissions")
                                       if decrypt_json(row[0], {}).get("active", False)),
            "investigations": con.execute("SELECT COUNT(*) FROM investigations").fetchone()[0],
            "audit_entries": con.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0],
        }
        platforms = []
        rows = con.execute("""
            SELECT pa.platform_key, pa.platform_name, pa.source_type,
                   pa.id AS account_id, pa.last_synced_at
            FROM platform_accounts pa ORDER BY pa.platform_name, pa.id
        """).fetchall()
        grouped = {}
        for row in rows:
            item = grouped.setdefault(row["platform_key"], {
                "platform_key": row["platform_key"], "platform_name": row["platform_name"],
                "source_type": row["source_type"], "linked_accounts": 0,
                "active_permissions": 0, "last_synced_at": row["last_synced_at"]
            })
            item["linked_accounts"] += 1
            item["last_synced_at"] = max(item["last_synced_at"], row["last_synced_at"])
            for permission in con.execute("SELECT payload_enc FROM permissions WHERE platform_account_id=?",
                                           (row["account_id"],)):
                if decrypt_json(permission[0], {}).get("active", False):
                    item["active_permissions"] += 1
        platforms = sorted(grouped.values(), key=lambda p: p["platform_name"].casefold())
        return {"stats": stats, "platforms": platforms}


def get_all_person_ids():
    with connect() as con:
        return [row[0] for row in con.execute("SELECT id FROM persons ORDER BY id")]


def get_agent_person_evidence(person_token):
    """Return only model-safe lifecycle attributes; never read identity_enc."""
    with connect() as con:
        row = con.execute(
            "SELECT person_token, campus_status_enc, institutional_role_enc FROM persons WHERE person_token=?",
            (person_token,),
        ).fetchone()
        if not row:
            raise ValueError("Pseudonymous person record not found.")
        status = decrypt_json(row["campus_status_enc"], "Unknown")
        role = decrypt_json(row["institutional_role_enc"], "Unknown role")
        events = []
        for event in con.execute(
            "SELECT payload_enc FROM lifecycle_events WHERE person_id=(SELECT id FROM persons WHERE person_token=?) ORDER BY id DESC",
            (person_token,),
        ).fetchall():
            payload = decrypt_json(event["payload_enc"], {})
            events.append({"event_type": payload.get("event_type", "Unknown"),
                           "event_date": payload.get("event_date", "")})
        return {"person_token": row["person_token"], "campus_status": status,
                "institutional_role": role, "events": events}


def get_agent_permission_evidence(person_token):
    """Return operational permission fields only; never read identity/account mapping columns."""
    with connect() as con:
        rows = con.execute("""
            SELECT g.permission_token, g.payload_enc, pa.platform_key
            FROM permissions g
            JOIN persons p ON p.id=g.person_id
            LEFT JOIN platform_accounts pa ON pa.id=g.platform_account_id
            WHERE p.person_token=? ORDER BY g.id
        """, (person_token,)).fetchall()
        results = []
        for row in rows:
            payload = decrypt_json(row["payload_enc"], {})
            if not payload.get("active", False):
                continue
            results.append({
                "permission_token": row["permission_token"],
                "platform_key": row["platform_key"] or "unknown",
                "platform": payload.get("platform", "Unknown platform"),
                "resource": payload.get("resource", "Unknown resource"),
                "role": payload.get("role", "Unknown role"),
                "expires_at": payload.get("expires_at"),
                "active": True,
            })
        return results


def get_agent_permission_evidence_by_token(person_token, permission_token):
    """Return one operational permission; no identity or external account fields."""
    with connect() as con:
        row = con.execute("""
            SELECT g.permission_token, g.payload_enc, pa.platform_key
            FROM permissions g
            JOIN persons p ON p.id=g.person_id
            LEFT JOIN platform_accounts pa ON pa.id=g.platform_account_id
            WHERE p.person_token=? AND g.permission_token=?
        """, (person_token, permission_token)).fetchone()
        if not row:
            raise ValueError("Permission reference does not belong to this pseudonymous person.")
        payload = decrypt_json(row["payload_enc"], {})
        return {"permission_token": row["permission_token"],
                "platform_key": row["platform_key"] or "unknown",
                "platform": payload.get("platform", "Unknown platform"),
                "resource": payload.get("resource", "Unknown resource"),
                "role": payload.get("role", "Unknown role"),
                "expires_at": payload.get("expires_at"),
                "active": bool(payload.get("active", False))}


def get_person_context(person_id):
    with connect() as con:
        # Explicit projection: normal investigations do not even load the
        # encrypted identity mapping into Python memory.
        row = con.execute(
            "SELECT id, person_token, campus_status_enc, institutional_role_enc FROM persons WHERE id=?",
            (person_id,),
        ).fetchone()
        if not row:
            raise ValueError("Pseudonymous person record not found.")
        # Normal detection does not open identity_enc. The role is stored in a
        # separate protected field so only the authenticated admin review path
        # needs to decrypt the actual name/email identity mapping.
        person = {
            "id": row["id"], "person_token": row["person_token"],
            "campus_status": decrypt_json(row["campus_status_enc"], "Unknown"),
            "institutional_role": decrypt_json(row["institutional_role_enc"], "Unknown role"),
        }
        permissions = [_decrypt_permission(r) for r in con.execute(
            "SELECT * FROM permissions WHERE person_id=?", (person_id,)).fetchall()]
        permissions = [p for p in permissions if p["active"]]
        events = []
        for r in con.execute("SELECT * FROM lifecycle_events WHERE person_id=? ORDER BY id DESC",
                             (person_id,)).fetchall():
            payload = decrypt_json(r["payload_enc"], {})
            events.append({"id": r["id"], **payload})
        return person, permissions, events


def investigate_person(result):
    payload = {"reason": result["reason"], "evidence": result["evidence"]}
    with connect() as con:
        cur = con.execute("""
            INSERT INTO investigations
            (person_id,status,recommendation,reason,evidence,created_at,person_token,result_enc)
            VALUES(?,?,?,?,?,?,?,?)
        """, (result["person_id"], "Report issued", "ENCRYPTED",
              "ENCRYPTED", "ENCRYPTED", now(), result["person_token"], encrypt_json({
                  **payload, "recommendation": result["recommendation"],
                  "flagged_permission_tokens": result.get("flagged_permission_tokens", [])
              })))
        inv_id = cur.lastrowid
        con.execute("""
            INSERT INTO audit_logs
            (investigation_id,person_id,actor,action,details,created_at,person_token,details_enc)
            VALUES(?,?,?,?,?,?,?,?)
        """, (inv_id, result["person_id"], "CampusGhost agent", "Investigation report generated",
              "ENCRYPTED", now(), result["person_token"], encrypt_json({
                  "recommendation": result["recommendation"], "reason": result["reason"]
              })))
        return inv_id


def get_audit_logs():
    with connect() as con:
        rows = con.execute("""
            SELECT id, investigation_id, person_token, actor, action, details_enc, created_at
            FROM audit_logs ORDER BY id DESC LIMIT 100
        """).fetchall()
        return [{"id": r["id"], "investigation_id": r["investigation_id"],
                 "person_token": r["person_token"] or "UNASSIGNED", "actor": r["actor"],
                 "action": r["action"],
                 "details": decrypt_json(r["details_enc"], {}).get("reason") or
                           decrypt_json(r["details_enc"], {}).get("recommendation") or
                           json.dumps(decrypt_json(r["details_enc"], {}), ensure_ascii=False),
                 "created_at": r["created_at"]} for r in rows]


def reset_demo():
    with connect() as con:
        con.execute("DELETE FROM audit_logs")
        con.execute("DELETE FROM investigations")
        con.execute("DELETE FROM permissions")
        con.execute("DELETE FROM platform_accounts")
        con.execute("DELETE FROM lifecycle_events")
        con.execute("DELETE FROM persons")
        seed(con)


def get_admin_review(person_token):
    """Return identity and access mapping only to the authenticated admin route."""
    with connect() as con:
        person = con.execute("SELECT * FROM persons WHERE person_token=?", (person_token,)).fetchone()
        if not person:
            raise ValueError("Pseudonymous identity not found.")
        identity = decrypt_json(person["identity_enc"], {})
        latest = con.execute("SELECT result_enc FROM investigations WHERE person_token=? ORDER BY id DESC LIMIT 1", (person_token,)).fetchone()
        latest_result = decrypt_json(latest[0], {}) if latest else {}
        flagged_tokens = set(latest_result.get("flagged_permission_tokens", []))
        rows = con.execute("""SELECT p.id AS person_id, p.person_token, pa.id AS account_id,
            pa.platform_key, pa.platform_name, pa.external_account_id_enc, pa.account_status_enc,
            g.id AS permission_id, g.permission_token, g.payload_enc
            FROM persons p JOIN platform_accounts pa ON pa.person_id=p.id
            LEFT JOIN permissions g ON g.platform_account_id=pa.id
            WHERE p.id=? ORDER BY pa.platform_name, g.id""", (person["id"],)).fetchall()
        accounts = {}
        for row in rows:
            account = accounts.setdefault(row["account_id"], {
                "platform_key": row["platform_key"], "platform_name": row["platform_name"],
                "external_account_id": decrypt_json(row["external_account_id_enc"], ""),
                "account_status": decrypt_json(row["account_status_enc"], "Unknown"),
                "permissions": []
            })
            if row["permission_id"]:
                grant = decrypt_json(row["payload_enc"], {})
                account["permissions"].append({"id": row["permission_id"],
                    "permission_token": row["permission_token"],
                    "flagged_for_review": row["permission_token"] in flagged_tokens, **grant})
        return {"person_token": person_token, "identity": identity,
                "campus_status": decrypt_json(person["campus_status_enc"], "Unknown"),
                "department": decrypt_json(person["department_enc"], "Unknown"), "accounts": list(accounts.values())}


def revoke_permission_record(person_token, permission_token, actor):
    """Mark a permission revoked only after the platform connector confirms success."""
    with connect() as con:
        row = con.execute("""SELECT g.*, pa.platform_key, pa.external_account_id_enc
            FROM permissions g JOIN persons p ON p.id=g.person_id
            JOIN platform_accounts pa ON pa.id=g.platform_account_id
            WHERE p.person_token=? AND g.permission_token=?""", (person_token, permission_token)).fetchone()
        if not row:
            raise ValueError("Permission does not belong to the selected pseudonymous identity.")
        payload = decrypt_json(row["payload_enc"], {})
        if not payload.get("active"):
            raise ValueError("This permission is already inactive.")
        latest = con.execute("SELECT result_enc FROM investigations WHERE person_token=? ORDER BY id DESC LIMIT 1", (person_token,)).fetchone()
        latest_result = decrypt_json(latest[0], {}) if latest else {}
        if latest_result.get("recommendation") != "RECOMMEND_REVOKE" or row["permission_token"] not in latest_result.get("flagged_permission_tokens", []):
            raise ValueError("This permission is not flagged by the latest investigation for revocation review.")
        external_id = decrypt_json(row["external_account_id_enc"], "")
        return {"platform_key": row["platform_key"], "external_account_id": external_id,
                "resource": payload.get("resource", ""), "payload": payload, "permission_id": row["id"]}


def confirm_permission_revoked(permission_id, person_token, actor, platform_result):
    with connect() as con:
        row = con.execute("SELECT person_id, permission_token, payload_enc FROM permissions WHERE id=?", (permission_id,)).fetchone()
        if not row:
            raise ValueError("Permission record not found after platform confirmation.")
        payload = decrypt_json(row["payload_enc"], {})
        payload["active"] = False
        con.execute("UPDATE permissions SET payload_enc=? WHERE id=?", (encrypt_json(payload), permission_id))
        details = {"permission_token": row["permission_token"], "platform": payload.get("platform"),
                   "resource": payload.get("resource"), "result": platform_result}
        con.execute("""INSERT INTO audit_logs
            (person_id,actor,action,details,created_at,person_token,details_enc)
            VALUES(?,?,?,?,?,?,?)""", (row["person_id"], actor, "Administrator revoked permission",
            "ENCRYPTED", now(), person_token, encrypt_json(details)))


def admin_review_cases():
    """Only pseudonymous case references are listed until an admin opens a case."""
    with connect() as con:
        rows = con.execute("""SELECT i.person_token, i.created_at, i.result_enc FROM investigations i
            JOIN (SELECT person_token, MAX(id) AS latest_id FROM investigations GROUP BY person_token) latest
            ON latest.latest_id=i.id ORDER BY i.created_at DESC""").fetchall()
        cases = []
        for row in rows:
            result = decrypt_json(row["result_enc"], {})
            if result.get("recommendation") == "RECOMMEND_REVOKE":
                cases.append({"person_token": row["person_token"], "created_at": row["created_at"],
                              "reason": result.get("reason", "Review recommended")})
        return cases


def has_current_revoke_recommendation(person_token):
    with connect() as con:
        row = con.execute("""SELECT result_enc FROM investigations WHERE person_token=?
            ORDER BY id DESC LIMIT 1""", (person_token,)).fetchone()
        return bool(row and decrypt_json(row[0], {}).get("recommendation") == "RECOMMEND_REVOKE")
