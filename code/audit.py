"""Deterministic deletion-audit engine.

For one request it
  1. resolves the subject's current and historical identifiers,
  2. links resources to the subject (evidence identifiers first, then the
     deletion-worker activity stream as a fallback for records that no longer
     carry any identifier),
  3. reconstructs each resource's state at ``audit_at`` from the latest
     evidence captured at or before that time,
  4. applies ``deletion_rules.csv`` and emits ordered findings, remediation and
     verification steps.
"""

from __future__ import annotations

import csv
import hashlib
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ingest import Obs, account_snapshots, kind_of, norm_phone, system_for

# ---------------------------------------------------------------------------
# constants

FINDING_ORDER = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"]
REMEDIATION_ORDER = ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"]
VERIFY_ORDER = ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]

# required final state -> (finding, finding_state, remediation, remediation_state, verification)
TREATMENT = {
    "ABSENT": ("REPORT_REMAINING_RECORD", "PRESENT", "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT"),
    "REDACTED": ("REPORT_EXPOSED_PII", "PRESENT", "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED"),
    "ANONYMIZED": ("REPORT_EXPOSED_PII", "PRESENT", "ANONYMIZE_RECORD", "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED"),
    "DISABLED": ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "DISABLE_DATA_FLOW", "DISABLED", "VERIFY_DATA_FLOW_DISABLED"),
    "BLOCKED": ("REPORT_RESTORE_RISK", "ACTIVE", "BLOCK_RESTORE", "BLOCKED", "VERIFY_RESTORE_BLOCKED"),
    "PRESENT": (None, None, None, None, "VERIFY_RECORD_PRESENT"),
}
VERIFY_STATE = {"VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
                "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
                "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED"}

# category inferred from resource kind when the evidence does not state it
KIND_CATEGORY = {
    "account": "USER_PROFILE", "search": "SEARCH_INDEX_ENTRY", "cache": "CACHE_ENTRY",
    "analytics": "ANALYTICS_PROFILE", "export": "USER_EXPORT", "marketing": "MARKETING_PROFILE",
    "email_delivery": "EMAIL_DELIVERY_LOG", "audit_record": "SECURITY_AUDIT_LOG",
    "legal_hold": "LEGAL_HOLD_RECORD", "backup": "BACKUP_ARCHIVE", "data_flow": "DATA_FLOW",
    "tombstone": "ACCOUNT_TOMBSTONE", "object": "SUPPORT_ATTACHMENT",
}
ACTION_TO_STATE = {"DELETE": "ABSENT", "REDACT": "REDACTED", "ANONYMIZE": "ANONYMIZED", "RETAIN": "PRESENT"}

# deletion-worker policy actions run at a fixed second offset from the case's
# anonymisation anchor (observed across the activity stream)
POLICY_OFFSETS = {
    ("ANONYMIZE_RECORD", "analytics_platform"): 0.0,
    ("REDACT_RECORD", "identity_service"): 0.0,
    ("RETAIN_RECORD", "legal_service"): 0.0,
    ("REDACT_RECORD", "support_platform"): 29.5,
    ("DISABLE_DATA_FLOW", "integration_service"): -1.5,
    ("BLOCK_RESTORE", "backup_service"): 28.5,
}
ACCOUNT_TO_ANCHOR = 41.0          # anchor second = account-delete second + 41 (mod 60)
# the worker's post-report "final result" events land at the account-delete
# second + 21.5 (mod 30): two waves, +51.5 and +21.5 seconds
ACCOUNT_TO_POST = 21.5
POST_WINDOW = 180                 # minutes after reported_at
ACCOUNT_WINDOW = (80, 39)        # account deletions run 39-80 minutes before reported_at
STATUS_TO_RESULT = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}


def P(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def sec_dist(a: float, b: float) -> float:
    d = abs((a - b) % 60)
    return min(d, 60 - d)


def sha(s: str) -> str:
    return hashlib.sha256(s.lower().encode()).hexdigest()


# ---------------------------------------------------------------------------
# data

@dataclass
class Identity:
    user_id: str
    emails: set = field(default_factory=set)
    hashes: set = field(default_factory=set)
    phones: set = field(default_factory=set)
    names: set = field(default_factory=set)

    def matches(self, o: Obs) -> bool:
        return bool(self.user_id in o.users or self.emails & o.emails or self.hashes & o.hashes
                    or self.phones & o.phones)

    def stored_match(self, o: Obs) -> bool:
        return bool(self.emails & o.emails or self.hashes & o.hashes or self.phones & o.phones)


class World:
    """All participant-facing data, indexed for the auditor."""

    def __init__(self, dataset_dir: str, obs: list[Obs], manifest: dict[str, dict]):
        self.dir = dataset_dir
        self.manifest = manifest
        self.obs = obs
        self.rules = {r["data_category"]: r for r in self._csv("deletion_rules.csv")}
        self.users = {r["user_id"]: r for r in self._csv("user_identities.csv")}
        self.audit_log = self._csv("user_audit_log.csv")
        self.activities = self._csv("system_activity.csv")
        self.by_rid: dict[str, list[Obs]] = defaultdict(list)
        for o in obs:
            self.by_rid[o.rid].append(o)
        self.acts_by_rid: dict[str, list[dict]] = defaultdict(list)
        for a in self.activities:
            self.acts_by_rid[a["resource_id"]].append(a)
        self.email_index: dict[str, set] = defaultdict(set)
        self.phone_index: dict[str, set] = defaultdict(set)
        self.hash_index: dict[str, set] = defaultdict(set)
        self._identities = {uid: self._build_identity(uid) for uid in self.users}
        for uid, ident in self._identities.items():
            for e in ident.emails:
                self.email_index[e].add(uid)
            for p in ident.phones:
                self.phone_index[p].add(uid)
            for h in ident.hashes:
                self.hash_index[h].add(uid)
        self.deletion_acts = [a for a in self.activities if a["source_system"] == "deletion_worker"]
        self.account_snapshots = account_snapshots(dataset_dir, manifest)
        self._owner_cache: dict[str, set] = {}

    def _csv(self, name: str) -> list[dict]:
        with open(os.path.join(self.dir, name), encoding="utf-8") as fh:
            return list(csv.DictReader(fh))

    def _build_identity(self, uid: str) -> Identity:
        u = self.users[uid]
        ident = Identity(uid)
        ident.emails.add(u["email"].strip().lower())
        ident.hashes.add(u["email_hash"].lower())
        ident.phones.add(norm_phone(u["phone"]))
        ident.names.add(u["name"].lower())
        for a in self.audit_log:
            if a["user_id"] != uid:
                continue
            for v in (a["old_value"], a["new_value"]):
                if a["field_name"] == "email":
                    ident.emails.add(v.strip().lower())
                elif a["field_name"] == "email_hash":
                    ident.hashes.add(v.lower())
                elif a["field_name"] == "phone":
                    ident.phones.add(norm_phone(v))
                elif a["field_name"] in ("name", "full_name"):
                    ident.names.add(v.lower())
        ident.hashes |= {sha(e) for e in ident.emails}
        ident.phones.discard("")
        return ident

    def identity(self, uid: str) -> Identity:
        return self._identities[uid]

    def user_for_email(self, email: str) -> str | None:
        uids = self.email_index.get(email.strip().lower(), set())
        return sorted(uids)[0] if len(uids) == 1 else (sorted(uids)[0] if uids else None)

    def owners_of_obs(self, o: Obs) -> set:
        """Users whose identifiers appear in an observation."""
        uids = set(o.users) & set(self.users)
        for e in o.emails:
            uids |= self.email_index.get(e, set())
        for h in o.hashes:
            uids |= self.hash_index.get(h, set())
        for p in o.phones:
            uids |= self.phone_index.get(p, set())
        return uids

    def stored_owners(self, o: Obs) -> set:
        uids = set()
        for e in o.emails:
            uids |= self.email_index.get(e, set())
        for h in o.hashes:
            uids |= self.hash_index.get(h, set())
        for p in o.phones:
            uids |= self.phone_index.get(p, set())
        return uids

    def resource_owners(self, rid: str, cutoff: datetime) -> set:
        out = set()
        for o in self.by_rid.get(rid, []):
            if self.visible(o, cutoff):
                out |= self.owners_of_obs(o)
        return out

    def visible(self, o: Obs, cutoff: datetime) -> bool:
        """The record existed in this state at or before the cutoff (the
        export carrying it may have been produced later)."""
        return P(o.t) <= cutoff

    def citable(self, o: Obs, cutoff: datetime) -> bool:
        """The evidence file itself was captured at or before the cutoff."""
        cap = self.manifest.get(o.file_id, {}).get("captured_at", o.t)
        return P(cap) <= cutoff and P(o.t) <= cutoff

    def global_owners(self, rid: str) -> set:
        """Everyone ever named by any observation of the resource (used only to
        rule a resource out for a different requester)."""
        if rid not in self._owner_cache:
            out = set()
            for o in self.by_rid.get(rid, []):
                out |= self.owners_of_obs(o)
            self._owner_cache[rid] = out
        return self._owner_cache[rid]


# ---------------------------------------------------------------------------
# state reconstruction

@dataclass
class ResState:
    rid: str
    system: str
    category: str
    present: bool | None
    pii: bool | None
    enabled: bool | None
    restore_allowed: bool | None
    evidence: str | None      # file id of the deciding observation
    t: str | None
    via: str = "evidence"     # how the resource was linked


def category_of(world: World, rid: str, obs: list[Obs]) -> str:
    for o in sorted(obs, key=lambda x: x.t, reverse=True):
        if o.category:
            return o.category
    kind = kind_of(rid)
    if kind == "support":
        return "SUPPORT_MESSAGE"
    return KIND_CATEGORY.get(kind, "USER_PROFILE")


def reconstruct(world: World, rid: str, cutoff: datetime) -> ResState:
    obs = [o for o in world.by_rid.get(rid, []) if world.visible(o, cutoff)]
    if kind_of(rid) == "account" and obs:
        # Omission from a later full profile-table capture is an observation of
        # absence - unless the copy we saw lives in a replica, which a primary
        # capture cannot see (replication drift).
        last = max(obs, key=lambda o: o.t)
        if not (last.present and "replica" in last.source):
            for t, fid, ids, full in world.account_snapshots:
                if full and rid not in ids and P(last.t) < P(t) <= cutoff:
                    obs.append(Obs(fid, t, rid, "account_service", present=False, source="omission"))
    system = obs[0].system if obs else system_for(rid)
    cat = category_of(world, rid, obs)
    st = ResState(rid, system, cat, None, None, None, None, None, None)
    if not obs:
        return st
    # latest observation time; aggregate all copies observed at that instant in that file
    obs.sort(key=lambda o: (o.t, o.file_id))
    last_t = obs[-1].t
    latest = [o for o in obs if o.t == last_t]
    st.t = last_t
    st.evidence = latest[-1].file_id
    pres = [o.present for o in latest if o.present is not None]
    st.present = any(pres) if pres else None
    piis = [o.pii for o in latest if o.pii is not None and o.present is not False]
    st.pii = any(piis) if piis else None
    en = [o.enabled for o in latest if o.enabled is not None]
    st.enabled = any(en) if en else None
    ra = [o.restore_allowed for o in latest if o.restore_allowed is not None]
    st.restore_allowed = any(ra) if ra else None
    # fill flags that the latest observation did not carry from earlier ones
    for o in reversed(obs):
        if st.enabled is None and o.enabled is not None:
            st.enabled = o.enabled
        if st.restore_allowed is None and o.restore_allowed is not None:
            st.restore_allowed = o.restore_allowed
        if st.pii is None and o.pii is not None and o.present is not False:
            st.pii = o.pii
    for o in latest:
        if o.present is not False and o.file_id:
            st.evidence = o.file_id
    # cite the latest file that was itself captured by the cutoff and agrees with the state
    citable = [o for o in obs if world.citable(o, cutoff)]
    agree = [o for o in citable if _agrees(o, st)]
    explicit = [o for o in agree if o.source != "omission"]
    pick = (explicit or agree or citable or [None])[-1]
    if pick is not None:
        st.evidence = pick.file_id
    return st


def _agrees(o: Obs, st: ResState) -> bool:
    if st.present is not None and o.present is not None and o.present != st.present:
        return False
    if st.pii is not None and o.pii is not None and o.present is not False and o.pii != st.pii:
        return False
    if st.enabled is not None and o.enabled is not None and o.enabled != st.enabled:
        return False
    if st.restore_allowed is not None and o.restore_allowed is not None and o.restore_allowed != st.restore_allowed:
        return False
    return True


# ---------------------------------------------------------------------------
# linking

@dataclass
class CaseContext:
    case: dict
    uid: str
    ident: Identity
    cutoff: datetime
    resources: dict = field(default_factory=dict)   # rid -> link reason
    link_evidence: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)          # linking diagnostics


def link_by_evidence(world: World, ctx: CaseContext) -> None:
    start = P(ctx.case["requested_at"])
    for rid, obs in world.by_rid.items():
        vis = [o for o in obs if world.visible(o, ctx.cutoff)]
        hits = [o for o in vis if ctx.ident.matches(o)]
        if not hits:
            continue
        # only records observed during the request window are in scope
        if not any(P(o.t) >= start for o in vis):
            continue
        # reject look-up hits whose stored identifiers belong to somebody else
        good = []
        for o in hits:
            if ctx.ident.stored_match(o) or ctx.uid in o.users:
                good.append(o)
                continue
            others = world.stored_owners(o) - {ctx.uid}
            if others:
                continue
            good.append(o)
        if not good:
            continue
        # a resource whose own stored identifiers consistently name a different person is not ours
        stored = [o for o in vis if o.emails and o.pii and world.stored_owners(o)]
        if stored and all(ctx.uid not in world.stored_owners(o) for o in stored) and \
                not any(ctx.uid in o.users for o in vis):
            continue
        ctx.resources[rid] = "evidence"


def link_by_catalog(world: World, ctx: CaseContext) -> None:
    """LINK_RESOURCE_IDENTITY rows are catalog claims: accepted unless the
    resource's own evidence shows a different person's identifiers."""
    start = P(ctx.case["requested_at"])
    for a in world.activities:
        if a["event_type"] != "LINK_RESOURCE_IDENTITY" or not (start <= P(a["event_time"]) <= ctx.cutoff):
            continue
        rid = a["resource_id"]
        det = a["details"].lower()
        if ctx.uid not in det.split() and f"{ctx.uid}." not in det and f"{ctx.uid};" not in det \
                and not any(e in det for e in ctx.ident.emails):
            continue
        vis = [o for o in world.by_rid.get(rid, []) if world.visible(o, ctx.cutoff)]
        # rejected only when the record's own identifiers resolve to a different known customer
        contradicted = any(o.pii and (world.stored_owners(o) - {ctx.uid}) and not ctx.ident.stored_match(o)
                           for o in vis)
        if contradicted:
            continue
        ctx.resources.setdefault(rid, "catalog")
        ctx.link_evidence.setdefault(rid, a["activity_id"])


def _slot_acts(world: World, ra: datetime, lo_min: float, hi_min: float) -> list[dict]:
    lo, hi = ra - timedelta(minutes=lo_min), ra + timedelta(minutes=hi_min)
    return [a for a in world.deletion_acts if lo <= P(a["event_time"]) <= hi]


def _policy_second(a: dict) -> float:
    return (P(a["event_time"]).second - POLICY_OFFSETS[(a["event_type"], a["target_system"])]) % 60


def _is_policy(a: dict) -> bool:
    return (a["event_type"], a["target_system"]) in POLICY_OFFSETS and a["reported_result"] == "SUCCESS"


def link_slot(world: World, ctxs: list[CaseContext], taken: set) -> None:
    """Activity fallback for records that no longer carry identifiers
    (deleted accounts, fully anonymised analytics).

    The deletion worker processes every request reported at the same instant
    in one burst that ends at that ``reported_at``: account deletions roughly
    40-75 minutes before, then the policy actions (anonymise, redact,
    disable, block) 7-29 minutes before.  Within a burst the actions of one
    request share a fixed second offset with that request's account
    deletion, which is what lets us pair them.  The account deletion's
    reported result mirrors the workflow claim (COMPLETE -> SUCCESS,
    PARTIALLY_COMPLETE -> PARTIAL, NOT_STARTED -> FAILED).  All requests of a
    burst are resolved together so one record is never handed to two people.
    """
    if not ctxs:
        return
    ra = P(ctxs[0].case["reported_at"])
    known = set(taken)
    for c in ctxs:
        known |= set(c.resources)

    def free(rid: str, ctx: CaseContext) -> bool:
        return rid not in known and not (world.global_owners(rid) - {ctx.uid})

    # single-target worker reports filed when the workflow reported its status
    for a in _slot_acts(world, ra, 20, 20):
        if "Target resource:" not in a["details"]:
            continue
        owners = [c for c in ctxs if free(a["resource_id"], c) and P(c.case["requested_at"]) <= P(a["event_time"])]
        if len(owners) == 1:
            owners[0].resources[a["resource_id"]] = "activity"
            owners[0].link_evidence[a["resource_id"]] = a["activity_id"]
            known.add(a["resource_id"])

    policy = [a for a in _slot_acts(world, ra, 35, 0) if _is_policy(a)]
    anchors: dict[int, list[float]] = {i: [] for i in range(len(ctxs))}
    for i, c in enumerate(ctxs):
        for a in policy:
            if a["resource_id"] in c.resources:
                anchors[i].append(_policy_second(a))

    # post-report results for each request's evidence-linked records
    post: dict[int, list[float]] = {i: [] for i in range(len(ctxs))}
    for i, c in enumerate(ctxs):
        for rid in c.resources:
            for a in world.acts_by_rid.get(rid, []):
                if a["source_system"] == "deletion_worker" and a["target_system"] != "account_service" and \
                        ra < P(a["event_time"]) <= ra + timedelta(minutes=POST_WINDOW):
                    post[i].append((P(a["event_time"]).second - ACCOUNT_TO_POST) % 30)

    def post_dist(a: dict, xs: list[float]) -> float:
        return min(min((P(a["event_time"]).second - x) % 30, (x - P(a["event_time"]).second) % 30) for x in xs)

    # --- accounts
    deletions = [a for a in _slot_acts(world, ra, ACCOUNT_WINDOW[0], -ACCOUNT_WINDOW[1])
                 if a["event_type"] == "DELETE_RECORD" and a["target_system"] == "account_service"]
    need = [i for i, c in enumerate(ctxs) if not any(r.startswith("account_") for r in c.resources)]
    cands: dict[int, list[dict]] = {}
    for i in need:
        c = ctxs[i]
        want = STATUS_TO_RESULT.get(c.case["reported_status"])
        cs = [a for a in deletions if free(a["resource_id"], c) and P(a["event_time"]) >= P(c.case["requested_at"])]
        typed = [a for a in cs if a["reported_result"] == want] or cs
        if anchors[i]:
            def dist(a, xs=anchors[i]):
                return min(sec_dist(P(a["event_time"]).second + ACCOUNT_TO_ANCHOR, x) for x in xs)
            fit = [a for a in typed if dist(a) <= 1.5]
            if fit:
                best = min(dist(a) for a in fit)
                typed = [a for a in fit if dist(a) <= best + 0.5]
        if post[i] and len(typed) > 1:
            fit = [a for a in typed if post_dist(a, post[i]) <= 1.5]
            if fit:
                best = min(post_dist(a, post[i]) for a in fit)
                typed = [a for a in fit if post_dist(a, post[i]) <= best + 0.5]
        cands[i] = typed
    assigned: dict[int, dict] = {}
    changed = True
    while changed:
        changed = False
        used = {a["resource_id"] for a in assigned.values()}
        for i in need:
            if i in assigned:
                continue
            opts = [a for a in cands[i] if a["resource_id"] not in used]
            if len(opts) == 1:
                assigned[i] = opts[0]
                used.add(opts[0]["resource_id"])
                ctxs[i].notes.append("account:unique")
                changed = True
    # still ambiguous: prefer the deletion whose anchor explains unclaimed policy actions
    used = {a["resource_id"] for a in assigned.values()}
    free_policy = [a for a in policy if a["resource_id"] not in known]
    for i in need:
        if i in assigned:
            continue
        opts = [a for a in cands[i] if a["resource_id"] not in used]
        if not opts:
            continue
        def support(a):
            anc = (P(a["event_time"]).second + ACCOUNT_TO_ANCHOR) % 60
            return sum(1 for p in free_policy if sec_dist(_policy_second(p), anc) <= 1.5)
        opts.sort(key=lambda a: (-support(a), a["event_time"]))
        ctxs[i].notes.append(f"account:tiebreak({len(opts)},{[support(a) for a in opts]})")
        assigned[i] = opts[0]
        used.add(opts[0]["resource_id"])
    for i, a in assigned.items():
        ctxs[i].resources[a["resource_id"]] = "activity"
        ctxs[i].link_evidence[a["resource_id"]] = a["activity_id"]
        known.add(a["resource_id"])

    # anchors implied by each request's account deletion
    for i, c in enumerate(ctxs):
        for rid in c.resources:
            if rid.startswith("account_"):
                for a in world.acts_by_rid.get(rid, []):
                    if a["event_type"] == "DELETE_RECORD" and                             ra - timedelta(minutes=ACCOUNT_WINDOW[0]) <= P(a["event_time"]) <= ra - timedelta(minutes=ACCOUNT_WINDOW[1]):
                        anchors[i].append((P(a["event_time"]).second + ACCOUNT_TO_ANCHOR) % 60)

    # --- policy actions on identifier-free records: nearest anchor wins
    for a in policy:
        rid = a["resource_id"]
        if rid in known:
            continue
        s = _policy_second(a)
        scored = sorted((min(sec_dist(s, x) for x in anchors[i]), i) for i in anchors if anchors[i]
                        and free(rid, ctxs[i]) and P(ctxs[i].case["requested_at"]) <= P(a["event_time"]))
        if not scored or scored[0][0] > 1.5:
            continue
        if len(scored) > 1 and scored[1][0] == scored[0][0]:
            continue
        c = ctxs[scored[0][1]]
        c.resources[rid] = "activity"
        c.link_evidence[rid] = a["activity_id"]
        known.add(rid)


def link_default_account(world: World, ctx: CaseContext, claimed: dict[str, set]) -> None:
    """Every request verifies a primary account.  When neither evidence nor the
    deletion-worker burst names one, fall back to the platform's naming
    convention (user_05 -> account_005, user_8741 -> account_8741, as seen in
    the profile tables)."""
    if not ctx.uid or any(r.startswith("account_") for r in ctx.resources):
        return
    rid = f"account_{int(ctx.uid.split('_')[1]):03d}"
    if (claimed.get(rid, set()) | world.global_owners(rid)) - {ctx.uid}:
        return
    ctx.resources[rid] = "convention"


# ---------------------------------------------------------------------------
# policy

def required_state(world: World, st: ResState) -> str | None:
    cat = st.category
    if cat == "DATA_FLOW":
        return "DISABLED"
    rule = world.rules.get(cat)
    if not rule:
        return "ABSENT"
    action = rule["required_action"].upper()
    if cat == "BACKUP_ARCHIVE":
        return "BLOCKED"
    return ACTION_TO_STATE.get(action, "ABSENT")


def violation(req: str, st: ResState) -> bool:
    if req == "ABSENT":
        return st.present is True
    if req in ("REDACTED", "ANONYMIZED"):
        return st.present is not False and st.pii is True
    if req == "DISABLED":
        return st.enabled is True
    if req == "BLOCKED":
        return st.restore_allowed is True and st.present is not False
    return False


def absence_evidence(world: World, rid: str, cutoff: datetime, after: datetime | None,
                     profiles_only: bool = False) -> str | None:
    """For an account with no observation of its own, the latest full
    account-table capture taken before the cutoff (and after the deletion)
    proves the record is gone by omission.  ``profiles_only`` skips captures
    that hold no profile rows at all."""
    best = None
    for t, fid, ids, full in world.account_snapshots:
        cap = world.manifest[fid]["captured_at"]
        if profiles_only and not ids:
            continue
        if full and P(t) <= cutoff and P(cap) <= cutoff and (after is None or P(t) >= after) and rid not in ids:
            best = fid
    return best


# ---------------------------------------------------------------------------

def build_context(world: World, case: dict) -> CaseContext:
    """Phase 1: identity resolution and evidence/catalog linking."""
    uid = world.user_for_email(case["email"])
    ctx = CaseContext(case, uid, world.identity(uid) if uid else Identity("none"), P(case["audit_at"]))
    if uid:
        link_by_evidence(world, ctx)
        link_by_catalog(world, ctx)
    return ctx


def finalize_case(world: World, ctx: CaseContext) -> tuple[str, list[dict]]:
    """Phase 3: state at audit_at, policy and ordered steps."""
    cutoff = ctx.cutoff
    states: list[tuple[ResState, str]] = []
    for rid in ctx.resources:
        st = reconstruct(world, rid, cutoff)
        st.via = ctx.resources[rid]
        req = required_state(world, st)
        if st.evidence is None and kind_of(rid) == "account":
            act_time = None
            for a in world.acts_by_rid.get(rid, []):
                if a["event_type"] == "DELETE_RECORD" and P(a["event_time"]) <= cutoff:
                    act_time = P(a["event_time"])
            ev = absence_evidence(world, rid, cutoff, act_time, profiles_only=st.via == "convention")
            st.present = False
            st.evidence = ev or ctx.link_evidence.get(rid)
        if st.evidence is None:
            # linked only through activity: state follows the policy action result
            st.evidence = ctx.link_evidence.get(rid)
            if req == "ANONYMIZED":
                st.pii = False
            elif req == "REDACTED":
                st.pii = False
            elif req == "ABSENT":
                st.present = False
        states.append((st, req))

    # every request verifies the primary account; make sure one exists
    steps_f, steps_r, steps_v = [], [], []
    incomplete = False
    for st, req in states:
        if req is None:
            continue
        tr = TREATMENT[req]
        if violation(req, st):
            incomplete = True
            steps_f.append((tr[0], tr[1], st, st.evidence))
            steps_r.append((tr[2], tr[3], st))
        if req == "PRESENT" and st.present is False:
            continue
        steps_v.append((tr[4], st))

    def k(order, op, st):
        return (order.index(op), st.system, st.rid)

    steps: list[dict] = []
    if incomplete:
        for op, state, st, ev in sorted(steps_f, key=lambda x: k(FINDING_ORDER, x[0], x[2])):
            steps.append(_step("FINDING", st, op, state, ev or ""))
        for op, state, st in sorted(steps_r, key=lambda x: k(REMEDIATION_ORDER, x[0], x[2])):
            steps.append(_step("REMEDIATION", st, op, state, ""))
        for op, st in sorted(steps_v, key=lambda x: k(VERIFY_ORDER, x[0], x[1])):
            steps.append(_step("VERIFICATION", st, op, VERIFY_STATE[op], ""))
        status = "INCOMPLETE"
    else:
        for op, st in sorted(steps_v, key=lambda x: k(VERIFY_ORDER, x[0], x[1])):
            steps.append(_step("VERIFICATION", st, op, VERIFY_STATE[op], st.evidence or ""))
        _cite_account_absence(world, ctx, steps)
        status = "COMPLETE"
    for i, s in enumerate(steps, 1):
        s["step_no"] = i
    return status, steps


def _cite_account_absence(world: World, ctx: CaseContext, steps: list[dict]) -> None:
    """A deleted account often has no citable observation of its own (it was
    linked through the activity stream, or its only read-back was exported
    after the audit).  Its absence is then evidenced by the capture that
    proves the rest of the case, provided that capture does not contain the
    account; otherwise by the latest full profile-table capture."""
    citable = [s["evidence_id"] for s in steps if s["evidence_id"].startswith("evidence_")
               and P(world.manifest[s["evidence_id"]]["captured_at"]) <= ctx.cutoff
               and not s["resource_id"].startswith("account_")]
    snaps = {fid: ids for _, fid, ids, _ in world.account_snapshots}
    dominant = max(set(citable), key=lambda f: (citable.count(f), f)) if citable else None
    for s in steps:
        if not s["resource_id"].startswith("account_") or s["operation"] != "VERIFY_RECORD_ABSENT":
            continue
        ev = s["evidence_id"]
        ok = ev.startswith("evidence_") and P(world.manifest[ev]["captured_at"]) <= ctx.cutoff
        own = ok and any(o.file_id == ev and o.source != "omission" for o in world.by_rid.get(s["resource_id"], []))
        # a convention-linked account was never seen: its proof is the profile
        # capture that omits it
        if own or (ok and ctx.resources.get(s["resource_id"]) == "convention"):
            continue
        if dominant and s["resource_id"] not in snaps.get(dominant, set()) and                 not any(o.file_id == dominant for o in world.by_rid.get(s["resource_id"], [])):
            s["evidence_id"] = dominant
        elif not ok:
            alt = absence_evidence(world, s["resource_id"], ctx.cutoff, None)
            if alt:
                s["evidence_id"] = alt


def _step(phase: str, st: ResState, op: str, state: str, ev: str) -> dict:
    return {"step_no": 0, "phase": phase, "system_id": st.system, "resource_id": st.rid,
            "operation": op, "state": state, "evidence_id": ev}
