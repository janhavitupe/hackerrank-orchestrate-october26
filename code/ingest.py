"""Evidence ingestion: turns every participant-facing evidence file into a flat
list of *observations*.

An observation is one statement of the form "at time T, file F showed resource R
of system S in state X, carrying identifiers I".  Every downstream decision
(identity linking, state-at-audit reconstruction, evidence citation) is made
from these observations plus ``system_activity.csv``.

Supported formats: JSON record bundles, SQLite-compatible SQL snapshots
(typed tables and JSON-in-SQL replica tables), the many log dialects
(key=value, JSON lines, syslog, bracketed, pipe-delimited, cloud runtime),
pipe-delimited handover text, PDFs (via ``pdftotext``) and screenshots (via
the multimodal extraction cache in ``image_extractions.json``).
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass, field
from typing import Any, Iterable

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"\buser_\d+\b")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
RID_RE = re.compile(
    r"\b(account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|"
    r"legal_hold|marketing|object|cache|email_delivery)_\d+\b"
)

PREFIX_SYSTEM = [
    ("audit_record_", "security_service"),
    ("data_flow_", "integration_service"),
    ("legal_hold_", "legal_service"),
    ("email_delivery_", "email_delivery_service"),
    ("account_", "account_service"),
    ("search_", "search_service"),
    ("analytics_", "analytics_platform"),
    ("support_", "support_platform"),
    ("export_", "export_service"),
    ("backup_", "backup_service"),
    ("tombstone_", "identity_service"),
    ("marketing_", "marketing_platform"),
    ("object_", "object_storage"),
    ("cache_", "cache_service"),
]


def system_for(rid: str) -> str:
    for prefix, system in PREFIX_SYSTEM:
        if rid.startswith(prefix):
            return system
    return "unknown"


def kind_of(rid: str) -> str:
    for prefix, _ in PREFIX_SYSTEM:
        if rid.startswith(prefix):
            return prefix[:-1]
    return "unknown"


def norm_phone(value: str) -> str:
    return re.sub(r"\D", "", value or "")


@dataclass
class Obs:
    file_id: str
    t: str                      # observation time (ISO-8601, Z)
    rid: str
    system: str
    present: bool | None = True  # False = lookup proved absence
    category: str | None = None  # data category when the evidence states it
    result: str | None = None    # raw result token (FOUND, IDENTIFIABLE, ...)
    emails: set = field(default_factory=set)
    users: set = field(default_factory=set)
    hashes: set = field(default_factory=set)
    phones: set = field(default_factory=set)
    names: set = field(default_factory=set)
    # direct identifiers physically stored in the record (as opposed to lookup keys)
    pii: bool | None = None
    enabled: bool | None = None          # data flows
    restore_allowed: bool | None = None  # backups
    source: str = ""                     # parser name, for debugging

    def add_value(self, key: str, value: Any, stored: bool = True) -> None:
        """Register an identifier-bearing field value."""
        if value is None:
            return
        if isinstance(value, (dict, list)):
            for k, v in (value.items() if isinstance(value, dict) else enumerate(value)):
                self.add_value(str(k), v, stored)
            return
        s = str(value).strip()
        if not s or s.lower() in {"null", "none", "[redacted]", "-", "—", "no direct identifier"}:
            return
        k = key.lower()
        hit = False
        for e in EMAIL_RE.findall(s):
            self.emails.add(e.lower())
            hit = True
        for u in USER_RE.findall(s):
            self.users.add(u)
        for h in HASH_RE.findall(s.lower()):
            self.hashes.add(h)
            hit = True
        if "phone" in k and norm_phone(s):
            self.phones.add(norm_phone(s))
            hit = True
        if k in {"full_name", "name", "display_name", "requester_name", "customer_name"}:
            self.names.add(s.lower())
            hit = True
        if stored and hit:
            self.pii = True


# ---------------------------------------------------------------------------
# helpers

STORED_ID_KEYS = {
    "email", "owner_email", "customer_email", "requester_email", "phone", "owner_phone",
    "requester_phone", "email_hash", "full_name", "name", "display_name", "requester_name",
    "subject_selector", "matched_value",
}
REF_KEYS = {"customer_reference", "subject_reference", "user_id", "subject_ref", "correlation_key",
            "lookup_key", "match_key", "scan_key", "subject_key", "owner_key"}


def _record_obs(file_id: str, t: str, rec: dict, system: str | None = None,
                collection: str = "", source: str = "") -> Obs | None:
    rid = rec.get("resource_id")
    if not rid:
        return None
    o = Obs(file_id=file_id, t=t, rid=rid, system=system or system_for(rid), source=source)
    o.pii = False
    _absorb_record(o, rec)
    coll = collection.lower()
    if "attachment" in coll:
        o.category = "SUPPORT_ATTACHMENT"
    elif "support_conversation" in coll:
        o.category = "SUPPORT_MESSAGE"
    elif "deleted_customer_reference" in coll:
        o.category = "ACCOUNT_TOMBSTONE"
    elif "retained_order" in coll:
        o.category = "LEGAL_HOLD_RECORD"
    return o


def _absorb_record(o: Obs, rec: dict) -> None:
    for k, v in rec.items():
        lk = k.lower()
        if lk in ("resource_id", "source_resource_id"):
            continue
        if lk in STORED_ID_KEYS:
            o.add_value(lk, v, stored=True)
        elif lk in REF_KEYS:
            o.add_value(lk, v, stored=False)
        elif lk == "document" and isinstance(v, dict):
            _absorb_record(o, v)
        elif lk == "enabled":
            o.enabled = _truthy(v)
        elif lk == "restore_allowed":
            o.restore_allowed = _truthy(v)
        elif lk == "download_available":
            o.present = _truthy(v)
        elif lk in ("archive_path", "archive_key", "object_key"):
            continue
        elif isinstance(v, str) and EMAIL_RE.search(v):
            o.add_value(lk, v, stored=True)


def _truthy(v: Any) -> bool | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "allowed", "enabled", "active"):
        return True
    if s in ("0", "false", "no", "denied", "disabled", "stopped"):
        return False
    return None


# ---------------------------------------------------------------------------
# record_lookup style rows (handover text, JSON manifests, delivery logs)

def _lookup_obs(file_id: str, t: str, system: str, rid: str, record_type: str, result: str,
                subject: str, source: str) -> Obs:
    result = (result or "").strip().upper()
    o = Obs(file_id=file_id, t=t, rid=rid, system=system or system_for(rid),
            category=(record_type or "").strip().upper() or None, result=result, source=source)
    o.add_value("subject_reference", subject, stored=False)
    if result in ("NOT_FOUND", "ABSENT", "DELETED"):
        o.present = False
    if result in ("IDENTIFIABLE", "FOUND") and o.emails:
        o.pii = True
    if result in ("ANONYMIZED", "REDACTED"):
        o.pii = False
    if result == "ACTIVE":
        if o.category == "DATA_FLOW":
            o.enabled = True
        if o.category == "BACKUP_ARCHIVE":
            o.restore_allowed = True
    if result == "DISABLED":
        o.enabled = False
    if result == "BLOCKED":
        o.restore_allowed = False
    return o


# ---------------------------------------------------------------------------
# JSON

def parse_json(file_id: str, path: str, captured: str) -> list[Obs]:
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    out: list[Obs] = []
    base_t = d.get("exported_at") or d.get("captured_at") or captured
    if "snapshots" in d:
        for snap in d["snapshots"]:
            t = snap.get("captured_at", base_t)
            store, coll = snap.get("data_store"), snap.get("collection", "")
            for rec in snap.get("records", []):
                if "record_type" in rec and "result" in rec:
                    out.append(_lookup_obs(file_id, rec.get("recorded_at", t), rec.get("system", store),
                                           rec["resource_id"], rec["record_type"], rec["result"],
                                           rec.get("subject_reference") or rec.get("lookup_value", ""),
                                           "snapshot_lookup"))
                    continue
                o = _record_obs(file_id, t, rec, store if store != "legal_service" else None, coll,
                                "snapshot")
                if o:
                    if store and system_for(o.rid) != store and store not in (
                            "backup_restore_service", "support_storage_service", "privacy_treatment_service"):
                        o.system = store
                    out.append(o)
    elif "service_exports" in d:
        for svc, colls in d["service_exports"].items():
            for coll, recs in colls.items():
                for rec in recs:
                    t = rec.get("observed_at", base_t)
                    if coll == "profile_lookups":
                        o = Obs(file_id, t, rec["resource_id"], svc, source="svc_export")
                        o.present = rec.get("status_code") == 200 and rec.get("profile") is not None
                        o.pii = False
                        if rec.get("profile"):
                            _absorb_record(o, rec["profile"])
                        out.append(o)
                    elif coll == "index_queries":
                        docs = (rec.get("hits") or {}).get("documents") or []
                        found = False
                        for doc in docs:
                            o = Obs(file_id, t, doc.get("resource_id", rec["resource_id"]), svc,
                                    source="svc_export")
                            o.pii = False
                            _absorb_record(o, doc)
                            o.add_value("query", rec.get("query"), stored=False)
                            out.append(o)
                            found = found or o.rid == rec["resource_id"]
                        if not found:
                            o = Obs(file_id, t, rec["resource_id"], svc, present=False, source="svc_export")
                            o.add_value("query", rec.get("query"), stored=False)
                            out.append(o)
                    else:
                        o = _record_obs(file_id, t, rec, svc, coll, "svc_export")
                        if o:
                            out.append(o)
    elif "records" in d:
        for rec in d["records"]:
            if "record_type" in rec and "result" in rec:
                out.append(_lookup_obs(file_id, rec.get("recorded_at", base_t), rec.get("system"),
                                       rec["resource_id"], rec["record_type"], rec["result"],
                                       rec.get("subject_reference", ""), "json_lookup"))
            else:
                o = _record_obs(file_id, base_t, rec, None, d.get("collection", ""), "json_records")
                if o:
                    out.append(o)
    return out


# ---------------------------------------------------------------------------
# SQL snapshots

TABLE_HINTS = {
    "customer_profiles": "account_service",
    "customer_search_documents": "search_service",
    "search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
}


def parse_sql(file_id: str, path: str, captured: str) -> list[Obs]:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    with open(path, encoding="utf-8") as fh:
        conn.executescript(fh.read())
    m = re.search(r"Captured at:\s*(\S+)", open(path, encoding="utf-8").read(400))
    t = m.group(1) if m else captured
    out: list[Obs] = []
    tables = [r[0] for r in conn.execute("select name from sqlite_master where type='table'")]
    scope = {}
    if "snapshot_scope" in tables:
        scope = {r[0]: r[1] for r in conn.execute("select origin_system, captured_at from snapshot_scope")}
    for tb in tables:
        if tb == "snapshot_scope":
            continue
        rows = [dict(r) for r in conn.execute(f'select * from "{tb}"')]
        for row in rows:
            if "record_json" in row:
                rec = json.loads(row["record_json"])
                o = _record_obs(file_id, t, rec, row.get("origin_system"), row.get("collection_name", ""),
                                f"sql:{tb}")
            else:
                sys_hint = next((s for k, s in TABLE_HINTS.items() if tb.startswith(k)), None)
                o = _record_obs(file_id, scope.get(sys_hint, t), row, sys_hint, tb, f"sql:{tb}")
            if o:
                o.result = (row.get("account_status") or None)
                out.append(o)
    conn.close()
    return out


def account_snapshots(dataset_dir: str, manifest: dict[str, dict]) -> list[tuple[str, str, set, bool]]:
    """Point-in-time captures of the customer-profile table:
    (captured_at, file_id, account ids present, is_full).

    ``is_full`` marks captures that enumerate the whole profile table at that
    instant (scoped inventories that cover account_service, typed profile
    table dumps, or an explicitly empty profile collection); an account that
    is missing from such a capture was absent when it was taken."""
    out = []
    for fid, meta in manifest.items():
        path = os.path.join(dataset_dir, meta["file_path"])
        if path.endswith(".sql"):
            text = open(path, encoding="utf-8").read()
            if "customer_profiles" not in text:
                continue
            m = re.search(r"INSERT INTO snapshot_scope VALUES \('account_service', '([^']+)'\)", text)
            scoped = "CREATE TABLE snapshot_scope" in text
            if scoped and not m:
                continue  # scoped capture that did not cover the account service
            typed = bool(re.search(r"CREATE TABLE customer_profiles\w*\s*\(", text))
            t = m.group(1) if m else meta["captured_at"]
            ids = set(re.findall(r"\('(account_\d+)'", text)) | set(re.findall(r"VALUES\('(account_\d+)'", text))
            out.append((t, fid, ids, typed))
        elif path.endswith(".json"):
            try:
                d = json.load(open(path, encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for snap in d.get("snapshots", []):
                if snap.get("data_store") == "account_service" and snap.get("collection") == "customer_profiles":
                    ids = {r.get("resource_id") for r in snap.get("records", [])}
                    out.append((snap.get("captured_at", meta["captured_at"]), fid, ids, not ids))
    return sorted(out)


# ---------------------------------------------------------------------------
# Logs

KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=(?:"((?:[^"\\]|\\.)*)"|(\S+))')
TS_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s+(.*)$")
STARTED_KEYS = ("lookup_key", "match_key", "scan_key", "subject_key", "subject_ref", "owner_key")


def _parse_log_line(line: str) -> dict | None:
    m = TS_RE.match(line.strip())
    if not m:
        return None
    ts, rest = m.groups()
    d: dict[str, Any] = {"_ts": ts}
    if rest.startswith("{"):
        try:
            d.update(json.loads(rest))
        except json.JSONDecodeError:
            return d
        return d
    rest_u = rest.replace('\\"', '"')
    # cloud runtime: message="k=\"v\" ..."
    for k, q, bare in KV_RE.findall(rest_u):
        d.setdefault(k, q if q or bare == "" else bare)
    mb = re.match(r"\[(\w+)\] \[([\w\-]+)\] \[([\w\-]+)\] (\w+):", rest)
    if mb:
        d.setdefault("level", mb.group(1))
        d.setdefault("service", mb.group(2))
        d.setdefault("trace_id", mb.group(3))
        d.setdefault("event", mb.group(4))
    mp = re.match(r"\| (\w+) \| ([\w\-]+) \| ([\w\-]+) \| (\w+) \|", rest)
    if mp:
        d.setdefault("level", mp.group(1))
        d.setdefault("service", mp.group(2))
        d.setdefault("trace_id", mp.group(3))
        d.setdefault("event", mp.group(4))
    ms = re.match(r"<\d+>1 \S+ ([\w\-]+) ([\w\-]+) - - ", rest)
    if ms:
        d.setdefault("service", ms.group(1))
        d.setdefault("trace_id", ms.group(2))
    if "function" in d:
        d.setdefault("service", d["function"])
    if "requestId" in d:
        d.setdefault("trace_id", d["requestId"])
    return d


def parse_log(file_id: str, path: str, captured: str) -> list[Obs]:
    with open(path, encoding="utf-8") as fh:
        lines = [l for l in (_parse_log_line(x) for x in fh) if l]
    traces: dict[str, list[dict]] = {}
    for d in lines:
        traces.setdefault(d.get("trace_id") or f"_{id(d)}", []).append(d)
    out: list[Obs] = []
    for tid, evs in traces.items():
        keys = [e[k] for e in evs for k in STARTED_KEYS if e.get(k)]
        for e in evs:
            o = _log_event_obs(file_id, e, keys)
            if o:
                out.append(o)
    return out


def _log_event_obs(file_id: str, e: dict, trace_keys: list[str]) -> Obs | None:
    ev = e.get("event", "")
    rid = e.get("resource_id")
    if not rid or not RID_RE.fullmatch(rid):
        return None
    t = e["_ts"]
    if ev == "record_lookup":
        return _lookup_obs(file_id, t, e.get("system"), rid, e.get("record_type"), e.get("result"),
                           e.get("subject_reference", ""), "log_lookup")
    o = Obs(file_id, t, rid, system_for(rid), source=f"log:{ev}")
    for k in trace_keys:
        o.add_value("lookup_key", k, stored=False)
    for k in ("correlation_key", "subject_ref", "subject_reference", "customer_reference", "lookup_key"):
        if e.get(k):
            o.add_value(k, e[k], stored=False)
    stored_fields = ("email", "phone", "email_hash", "requester_email", "requester_name",
                     "requester_phone", "customer_email", "display_name", "full_name")
    has_stored = any(k in e for k in stored_fields)
    if has_stored:
        o.pii = False
        for k in stored_fields:
            if k in e:
                o.add_value(k, e[k], stored=True)
    if ev in ("profile_lookup_completed",):
        rows = e.get("rows")
        status = e.get("http_status")
        o.present = (rows not in ("0", None) and rows != 0) if rows is not None else status == "200"
        if status == "404":
            o.present = False
        o.category = "USER_PROFILE"
    elif ev == "index_query_completed":
        o.present = e.get("result", "hit") == "hit"
        o.category = "SEARCH_INDEX_ENTRY"
    elif ev in ("analytics_profile_read", "analytics_profile_read_completed"):
        o.category = "ANALYTICS_PROFILE"
        if e.get("direct_identifiers") not in (None, "0"):
            o.pii = True
        elif o.pii is None:
            o.pii = False
    elif ev == "analytics_identity_scan":
        o.category = "ANALYTICS_PROFILE"
        o.add_value("matched_value", e.get("matched_value"), stored=True)
        o.pii = True
    elif ev == "message_pii_scan":
        o.category = "SUPPORT_MESSAGE"
        o.add_value("matched_value", e.get("matched_value"), stored=True)
        o.pii = True
    elif ev == "attachment_pii_scan":
        o.category = "SUPPORT_ATTACHMENT"
        o.add_value("matched_value", e.get("matched_value"), stored=True)
        o.pii = True
    elif ev == "message_read":
        o.category = "SUPPORT_MESSAGE"
        txt = e.get("message_text", "")
        o.pii = not (txt.strip().upper() in ("[REDACTED]", "") ) and bool(EMAIL_RE.search(txt))
    elif ev == "support_ticket_read_completed":
        if o.pii is None:
            o.pii = False
    elif ev in ("audit_record_read_completed",):
        o.category = "SECURITY_AUDIT_LOG"
        o.present = e.get("rows", "1") != "0"
    elif ev in ("connector_config_read_completed", "connector_config_loaded", "connector_heartbeat"):
        o.category = "DATA_FLOW"
        o.enabled = _truthy(e.get("enabled"))
    elif ev == "restore_policy_read_completed":
        o.category = "BACKUP_ARCHIVE"
        o.restore_allowed = _truthy(e.get("restore_allowed"))
        if e.get("archive_present") == "false":
            o.present = False
    elif ev == "restore_candidate_evaluated":
        o.category = "BACKUP_ARCHIVE"
        o.restore_allowed = e.get("eligible") == "true" and e.get("deletion_block") != "true"
    elif ev == "restore_authorization_completed":
        o.category = "BACKUP_ARCHIVE"
        o.restore_allowed = e.get("decision") not in ("deny", "denied")
    elif ev in ("export_download_check_completed", "export_metadata_read_completed"):
        o.category = "USER_EXPORT"
        o.present = e.get("available", "true") == "true"
        if e.get("owner_email"):
            o.add_value("owner_email", e["owner_email"], stored=True)
    elif ev == "contact_lookup_completed":
        # a secondary contact record keyed only by an identifier (e.g. an old email hash)
        o.category = "SECONDARY_IDENTIFIER"
        o.present = e.get("rows", "1") != "0"
        o.add_value("correlation_key", e.get("correlation_key"), stored=True)
    elif ev == "retained_order_loaded":
        o.category = "LEGAL_HOLD_RECORD"
    elif ev == "contact_query_completed":
        # replica of the legacy support contact index: a contact record, not a conversation
        o.category = "SECONDARY_IDENTIFIER"
        o.present = e.get("rows", "1") != "0"
        if e.get("lookup_key"):
            o.add_value("lookup_key", e["lookup_key"], stored=False)
    elif ev == "deletion_marker_check":
        o.category = "SECONDARY_IDENTIFIER"
        o.present = e.get("marker_found") != "true"
    else:
        return None
    return o


# ---------------------------------------------------------------------------
# Text / PDF / images

def parse_handover(file_id: str, path: str, captured: str) -> list[Obs]:
    out = []
    for line in open(path, encoding="utf-8"):
        if not line.startswith("- "):
            continue
        parts = [p.strip() for p in line[2:].split("|")]
        if len(parts) >= 6:
            t, system, rid, rtype, result, subject = parts[:6]
            out.append(_lookup_obs(file_id, t, system, rid, rtype, result, subject, "handover"))
    return out


def pdf_text(path: str) -> str:
    exe = shutil.which("pdftotext")
    if exe:
        try:
            return subprocess.run([exe, "-layout", path, "-"], capture_output=True, text=True,
                                  encoding="utf-8", check=True).stdout
        except (subprocess.SubprocessError, OSError):
            pass
    try:
        from pypdf import PdfReader  # type: ignore
        return "\n".join((p.extract_text() or "") for p in PdfReader(path).pages)
    except Exception:
        return ""


def parse_pdf(file_id: str, path: str, captured: str, aliases: dict[str, str] | None = None) -> list[Obs]:
    """PDFs are business documents.  We extract every resource id they mention
    (directly, or through a catalogued business alias such as a statement
    number) together with the identifiers printed alongside it."""
    text = pdf_text(path)
    out = []
    rids = set(m.group(0) for m in RID_RE.finditer(text))
    for alias, rid in (aliases or {}).items():
        # only business aliases (statement numbers, file names); never bare ids
        if alias != rid and not USER_RE.fullmatch(alias) and not RID_RE.fullmatch(alias) and alias in text:
            rids.add(rid)
    rids = sorted(rids)
    for rid in rids:
        o = Obs(file_id, captured, rid, system_for(rid), source="pdf")
        o.add_value("text", text, stored=kind_of(rid) not in ("audit_record",))
        if kind_of(rid) == "audit_record":
            o.category = "SECURITY_AUDIT_LOG"
        if kind_of(rid) == "support" and "attachment" in text.lower():
            o.category = "SUPPORT_ATTACHMENT"
        out.append(o)
    return out


def parse_images(cache_path: str, manifest: dict[str, dict]) -> list[Obs]:
    """Screenshots were transcribed once with a multimodal model; the
    structured transcription is cached in image_extractions.json."""
    if not os.path.exists(cache_path):
        return []
    with open(cache_path, encoding="utf-8") as fh:
        cache = json.load(fh)
    out = []
    for item in cache["images"]:
        fid = item["file_id"]
        cap = manifest.get(fid, {}).get("captured_at", item.get("captured_at"))
        for rec in item.get("focus_records", []):
            o = Obs(fid, cap, rec["resource_id"], rec.get("system") or system_for(rec["resource_id"]),
                    source="image")
            o.pii = False
            o.category = rec.get("category")
            for k, v in rec.get("stored_identifiers", {}).items():
                o.add_value(k, v, stored=True)
            for k, v in rec.get("references", {}).items():
                o.add_value(k, v, stored=False)
            if "present" in rec:
                o.present = rec["present"]
            if "enabled" in rec:
                o.enabled = rec["enabled"]
            if "restore_allowed" in rec:
                o.restore_allowed = rec["restore_allowed"]
            out.append(o)
    return out


# ---------------------------------------------------------------------------

def load_manifest(dataset_dir: str) -> dict[str, dict]:
    with open(os.path.join(dataset_dir, "evidence_files.csv"), encoding="utf-8") as fh:
        return {r["file_id"]: r for r in csv.DictReader(fh)}


LINK_RE = re.compile(r"linked (\S+) \(([^)]+)\)|confirmed (\S+) \(([^)]+)\)")


def catalog_aliases(dataset_dir: str) -> dict[str, str]:
    """Business aliases (file names, statement numbers) published by the data
    catalog in LINK_RESOURCE_IDENTITY activity rows."""
    out = {}
    with open(os.path.join(dataset_dir, "system_activity.csv"), encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["event_type"] == "LINK_RESOURCE_IDENTITY":
                m = LINK_RE.search(r["details"])
                if m:
                    rid, alias = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
                    out[alias] = rid
    return out


def ingest(dataset_dir: str, image_cache: str) -> tuple[list[Obs], dict[str, dict]]:
    manifest = load_manifest(dataset_dir)
    aliases = catalog_aliases(dataset_dir)
    obs: list[Obs] = []
    for fid, meta in manifest.items():
        path = os.path.join(dataset_dir, meta["file_path"])
        cap = meta["captured_at"]
        ext = os.path.splitext(path)[1].lower()
        if not os.path.exists(path):
            continue
        if ext == ".json":
            obs += parse_json(fid, path, cap)
        elif ext == ".sql":
            obs += parse_sql(fid, path, cap)
        elif ext == ".log":
            obs += parse_log(fid, path, cap)
        elif ext == ".txt":
            obs += parse_handover(fid, path, cap)
        elif ext == ".pdf":
            obs += parse_pdf(fid, path, cap, aliases)
    obs += parse_images(image_cache, manifest)
    return obs, manifest


def iter_debug(obs: Iterable[Obs]) -> Iterable[str]:
    for o in obs:
        yield (f"{o.file_id} {o.t} {o.system}/{o.rid} present={o.present} cat={o.category} res={o.result} "
               f"pii={o.pii} en={o.enabled} ra={o.restore_allowed} e={sorted(o.emails)} u={sorted(o.users)} "
               f"src={o.source}")
