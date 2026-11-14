"""Métricas por proyecto (RF-18) y comparación entre escaneos (RF-17)."""

from __future__ import annotations

import statistics
import uuid
from collections import defaultdict
from datetime import datetime

from sqlalchemy import select

from sast.rules.api import Severity

from ..extensions import db
from ..models.entities import Issue, Occurrence, Scan
from ..views.serializers import iso_utc

SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")


def project_metrics(project_id: uuid.UUID, start: datetime | None = None, end: datetime | None = None) -> dict:
    q = select(Scan).where(Scan.project_id == project_id, Scan.status == "done")
    if start:
        q = q.where(Scan.finished_at >= start)
    if end:
        q = q.where(Scan.finished_at <= end)
    scans = list(db.session.scalars(q.order_by(Scan.finished_at)))

    open_by_severity = []
    new_vs_fixed = []
    for s in scans:
        sev = (s.summary or {}).get("by_severity", {})
        date = iso_utc(s.finished_at)
        open_by_severity.append({"scan_id": str(s.id), "date": date, **{k: sev.get(k, 0) for k in SEVERITY_KEYS}})
        new_vs_fixed.append({"scan_id": str(s.id), "date": date, "new": (s.summary or {}).get("new", 0),
                             "fixed": (s.summary or {}).get("fixed", 0)})

    durations: dict[str, list[float]] = defaultdict(list)
    for issue in db.session.scalars(select(Issue).where(Issue.project_id == project_id, Issue.fixed_at.is_not(None),
                                                        Issue.triage != "false_positive")):
        days = (issue.fixed_at - issue.first_seen_at).total_seconds() / 86400
        durations[Severity(issue.severity).label].append(max(0.0, days))
    mttr = {k: {"median": round(statistics.median(v), 2), "mean": round(statistics.fmean(v), 2), "count": len(v)}
            for k, v in durations.items()}

    open_count = db.session.query(Issue).filter(Issue.project_id == project_id, Issue.lifecycle != "fixed",
                                                Issue.triage.not_in(["false_positive"])).count()
    last = scans[-1] if scans else None
    density = round(open_count / (last.loc_total / 1000), 2) if last and last.loc_total else None
    accepted = db.session.query(Issue).filter(Issue.project_id == project_id, Issue.lifecycle != "fixed",
                                              Issue.triage.in_(["accepted", "wont_fix"])).count()
    return {"open_by_severity": open_by_severity, "new_vs_fixed": new_vs_fixed, "mttr_days": mttr,
            "density_per_kloc": density, "open_issues": open_count, "accepted_issues": accepted}


def scan_diff(scan: Scan, base: Scan) -> dict:
    current = {o.issue_id: o for o in db.session.scalars(select(Occurrence).where(Occurrence.scan_id == scan.id))}
    previous = {o.issue_id: o for o in db.session.scalars(select(Occurrence).where(Occurrence.scan_id == base.id))}
    new = [o for iid, o in current.items() if iid not in previous]
    fixed = [o for iid, o in previous.items() if iid not in current]
    reopened = [o for o in current.values() if o.change == "reopened"]
    persisting = len([1 for iid in current if iid in previous])
    return {"new": new, "fixed": fixed, "reopened": reopened, "persisting_count": persisting}
