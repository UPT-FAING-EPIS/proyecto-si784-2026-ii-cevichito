"""F4: lectura segura de ZIP, descarga de GitHub, cola, worker, timeout y cancelación."""

from __future__ import annotations

import io
import stat
import zipfile
from datetime import timedelta

import pytest
from sqlalchemy import select

from api.errors import ApiError
from api.extensions import db
from api.models.entities import Issue, Scan, ScanUpload, utcnow
from api.services import scan_jobs
from api.services.archive import ArchiveError, Limits, read_zip
from api.services.github_fetch import GitHubError, RepoRef, download_zipball, parse_repo
from api.worker import queue
from api.worker.runner import ScanCanceledByUser, process, run_isolated

from .conftest import PG_URL, make_settings

SETTINGS = make_settings()
VULN = "import pickle\npickle.loads(b'')\n"


def make_zip(entries: dict[str, bytes], *, symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
    return buf.getvalue()


# --- ZIP -------------------------------------------------------------------------------

def test_zip_reads_code_and_skips_noise():
    data = make_zip({"src/app.py": VULN.encode(), "node_modules/x/index.js": b"eval(1)", "img.png": b"\x89PNG",
                     "README.md": b"# hola"})
    contents = read_zip(data)
    assert [p for p, _ in contents.files] == ["src/app.py"]


def test_zip_bomb_is_rejected_without_exhausting_memory():
    bomb = make_zip({"bomb.py": b"0" * (60 * 1024 * 1024)})
    assert len(bomb) < 200 * 1024
    with pytest.raises(ArchiveError) as e:
        read_zip(bomb)
    assert e.value.code in {"compression_ratio", "too_large"} and e.value.status == 413


def test_total_uncompressed_limit():
    data = make_zip({f"f{i}.py": bytes(range(256)) * 400 for i in range(10)})
    with pytest.raises(ArchiveError) as e:
        read_zip(data, Limits(max_total_bytes=500_000, max_ratio=10_000))
    assert e.value.code == "too_large"


@pytest.mark.parametrize("name", ["../../etc/x.py", "/abs/x.py", "C:/win/x.py", "a/../../x.py"])
def test_unsafe_paths_are_rejected(name):
    with pytest.raises(ArchiveError) as e:
        read_zip(make_zip({name: b"x = 1"}))
    assert e.value.code == "unsafe_path"


def test_symlinks_are_rejected():
    with pytest.raises(ArchiveError) as e:
        read_zip(make_zip({"a.py": b"x=1"}, symlink="link.py"))
    assert e.value.code == "symlink"


def test_only_source_files_count_for_the_file_limit():
    # 50 imágenes no cuentan para el límite de 5: solo los 3 archivos de código.
    files = {f"docs/img{i}.png": b"" for i in range(50)} | {f"app/m{i}.py": b"x = 1" for i in range(3)}
    assert len(read_zip(make_zip(files), Limits(max_entries=5)).files) == 3
    with pytest.raises(ArchiveError) as e:
        read_zip(make_zip({f"app/m{i}.py": b"x = 1" for i in range(6)}), Limits(max_entries=5))
    assert e.value.code == "too_many_files" and e.value.status == 413


def test_too_many_entries_in_total_is_still_rejected():
    data = make_zip({f"d/f{i}.txt": b"" for i in range(101)})
    with pytest.raises(ArchiveError) as e:
        read_zip(data, Limits(max_entries=5))          # tope total = 5 × 20 = 100
    assert e.value.code == "too_many_entries" and e.value.status == 413


def test_tests_dependencies_and_minified_are_dropped_on_decompression():
    files = {"app/main.py": b"x = 1", "tests/test_main.py": b"x = 1", "app/test_utils.py": b"x = 1",
             "node_modules/lib/index.js": b"x = 1", "static/jquery.min.js": b"x = 1",
             "static/bundle.js": b"var a=1;" * 600}       # minificado sin decirlo en el nombre
    contents = read_zip(make_zip(files))
    assert [p for p, _ in contents.files] == ["app/main.py"]
    assert {"path": "static/bundle.js", "reason": "código minificado"} in contents.skipped


def test_oversized_entry_is_skipped_not_fatal():
    data = make_zip({"big.py": bytes(range(256)) * 50_000, "ok.py": b"x = 1"})
    contents = read_zip(data, Limits(max_entry_bytes=1_000_000, max_ratio=10_000))
    assert [p for p, _ in contents.files] == ["ok.py"]
    assert contents.skipped[0]["path"] == "big.py"


def test_invalid_zip():
    with pytest.raises(ArchiveError) as e:
        read_zip(b"no soy un zip")
    assert e.value.code == "invalid_zip"


# --- GitHub ------------------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("owner/repo", "owner/repo"),
    ("https://github.com/owner/repo.git", "owner/repo"),
    ("github.com/Owner-1/my.repo/", "Owner-1/my.repo"),
])
def test_parse_repo_accepts(raw, expected):
    assert parse_repo(raw).repo == expected


@pytest.mark.parametrize("raw", ["http://169.254.169.254/latest", "owner", "owner/repo/extra", "../x/y", "a b/c"])
def test_parse_repo_rejects_urls_and_garbage(raw):
    with pytest.raises(GitHubError):
        parse_repo(raw)


def test_parse_ref_rejects_traversal():
    with pytest.raises(GitHubError):
        parse_repo("o/r", "../../main")


class _Resp:
    def __init__(self, url, status=200, body=b"", history=(), headers=None):
        self.url, self.status_code, self._body, self.history = url, status, body, list(history)
        self.headers = headers or {}

    def iter_content(self, size):
        for i in range(0, len(self._body), size):
            yield self._body[i:i + size]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Session:
    def __init__(self, resp):
        self.resp, self.calls = resp, []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        return self.resp


def test_download_streams_with_cap_and_timeouts():
    body = make_zip({"o-r-abc1234/app.py": VULN.encode()})
    s = _Session(_Resp("https://codeload.github.com/o/r/zip/main", body=body,
                       history=[_Resp("https://api.github.com/repos/o/r/zipball/main", 302)]))
    assert download_zipball(RepoRef("o/r", "main"), max_bytes=10_000_000, session=s) == body
    url, kw = s.calls[0]
    # Sin token: la descarga normal de github.com, que no gasta la cuota de la API.
    assert url == "https://github.com/o/r/archive/main.zip"
    assert "Authorization" not in kw["headers"]
    assert kw["stream"] is True and kw["timeout"] == (5, 15)
    with pytest.raises(GitHubError) as e:
        download_zipball(RepoRef("o/r"), max_bytes=10, session=s)
    assert e.value.code == "repo_too_large"


def test_download_without_ref_uses_default_branch_and_with_token_uses_api():
    body = make_zip({"o-r-abc1234/app.py": VULN.encode()})
    s = _Session(_Resp("https://codeload.github.com/o/r/zip/abc", body=body))
    download_zipball(RepoRef("o/r"), max_bytes=10_000_000, session=s)
    assert s.calls[-1][0] == "https://github.com/o/r/archive/HEAD.zip"
    download_zipball(RepoRef("o/r", "v1.0"), max_bytes=10_000_000, session=s, token="ghp_prueba")
    url, kw = s.calls[-1]
    assert url == "https://api.github.com/repos/o/r/zipball/v1.0"
    assert kw["headers"]["Authorization"] == "Bearer ghp_prueba"


def test_download_rejects_foreign_redirect():
    s = _Session(_Resp("http://evil.example/x", body=b"x", history=[_Resp("https://api.github.com/x", 302)]))
    with pytest.raises(GitHubError) as e:
        download_zipball(RepoRef("o/r"), max_bytes=1000, session=s)
    assert e.value.code == "bad_redirect"


class _SlowResp(_Resp):
    """Manda trozos sin parar pero muy despacio (simulado con un reloj falso)."""

    def __init__(self, clock, **kw):
        super().__init__("https://codeload.github.com/o/r/zip/main", body=b"x" * 64 * 1024 * 50, **kw)
        self.clock = clock

    def iter_content(self, size):
        for chunk in super().iter_content(size):
            self.clock["t"] += 10  # 10 s por trozo
            yield chunk


def test_download_has_total_deadline_and_ticks(monkeypatch):
    import api.services.github_fetch as gf

    clock = {"t": 0.0}
    monkeypatch.setattr(gf.time, "monotonic", lambda: clock["t"])
    ticks = []
    with pytest.raises(GitHubError) as e:
        download_zipball(RepoRef("o/r"), max_bytes=10**9, session=_Session(_SlowResp(clock)),
                         deadline_s=60, on_tick=ticks.append)
    assert e.value.code == "github_timeout"
    assert len(ticks) >= 4  # hubo latidos mientras descargaba


def test_download_tick_exception_aborts():
    class Stop(Exception):
        pass

    def tick(_n):
        raise Stop()

    import api.services.github_fetch as gf
    old = gf.TICK_EVERY_S
    gf.TICK_EVERY_S = 0
    try:
        with pytest.raises(Stop):
            download_zipball(RepoRef("o/r"), max_bytes=10**9, on_tick=tick,
                             session=_Session(_Resp("https://codeload.github.com/x", body=b"y" * 200_000)))
    finally:
        gf.TICK_EVERY_S = old


def test_download_maps_404():
    with pytest.raises(GitHubError) as e:
        download_zipball(RepoRef("o/r"), max_bytes=1000, session=_Session(_Resp("https://api.github.com/x", 404)))
    assert e.value.status == 404


# --- Creación de escaneos y cuotas -----------------------------------------------------------

def test_create_snippet_scan_stores_upload(user, project):
    scan = scan_jobs.create_scan(user, project, source="snippet", filename="../app.py", code=VULN, settings=SETTINGS)
    db.session.commit()
    assert scan.status == "queued" and scan.source_ref == "app.py"
    assert db.session.get(ScanUpload, scan.id).size == len(VULN)


@pytest.mark.parametrize("kwargs, code", [
    ({"source": "snippet", "filename": "a.exe", "code": "x"}, "unsupported_language"),
    ({"source": "snippet", "filename": "a.py", "code": "  "}, "empty_code"),
    ({"source": "zip", "zip_bytes": b"no zip"}, "not_a_zip"),
    ({"source": "github", "repo": "http://localhost:8080/admin"}, "invalid_repo"),
    ({"source": "snippet", "filename": "a.py", "code": "x=1", "rules": ["py/no-existe"]}, "unknown_rules"),
    ({"source": "ftp"}, "invalid_source"),
])
def test_create_scan_validation(user, project, kwargs, code):
    with pytest.raises(ApiError) as e:
        scan_jobs.create_scan(user, project, settings=SETTINGS, **kwargs)
    assert e.value.code == code


def test_running_scan_quota(user, project):
    s = make_settings(max_running_scans_per_user=2)
    for _ in range(2):
        scan_jobs.create_scan(user, project, source="snippet", filename="a.py", code=VULN, settings=s)
    db.session.commit()
    with pytest.raises(ApiError) as e:
        scan_jobs.create_scan(user, project, source="snippet", filename="a.py", code=VULN, settings=s)
    assert e.value.status == 429 and e.value.code == "too_many_running_scans"


def test_cancel_queued_scan_is_immediate(user, project):
    scan = scan_jobs.create_scan(user, project, source="snippet", filename="a.py", code=VULN, settings=SETTINGS)
    db.session.commit()
    assert scan_jobs.request_cancel(scan) == "canceled"
    db.session.commit()
    assert db.session.get(ScanUpload, scan.id) is None
    with pytest.raises(ApiError) as e:
        scan_jobs.request_cancel(scan)
    assert e.value.status == 409


# --- Cola y worker ------------------------------------------------------------------------------

def _queued(user, project, code=VULN, **kw) -> Scan:
    scan = scan_jobs.create_scan(user, project, source="snippet", filename="app.py", code=code, settings=SETTINGS, **kw)
    db.session.commit()
    return scan


def test_worker_processes_snippet_end_to_end(user, project):
    scan = _queued(user, project)
    assert queue.claim("w1") == scan.id
    assert process(scan.id, SETTINGS) == "done"
    db.session.refresh(scan)
    assert scan.status == "done" and scan.files_scanned == 1 and scan.summary["by_severity"]["critical"] == 1
    assert db.session.get(ScanUpload, scan.id) is None  # el código subido no se conserva
    assert db.session.scalars(select(Issue)).first().rule_id == "py/insecure-deserialization"


def test_worker_processes_zip(user, project):
    data = make_zip({"src/app.py": VULN.encode(), "src/util.py": b"import hashlib\nhashlib.md5(b'x')\n"})
    scan = scan_jobs.create_scan(user, project, source="zip", zip_bytes=data, filename="p.zip", settings=SETTINGS)
    db.session.commit()
    queue.claim("w1")
    assert process(scan.id, SETTINGS) == "done"
    db.session.refresh(scan)
    assert scan.files_scanned == 2 and scan.summary["total"] == 2


def test_worker_marks_zip_bomb_as_failed(user, project):
    bomb = make_zip({"bomb.py": b"0" * (60 * 1024 * 1024)})
    scan = scan_jobs.create_scan(user, project, source="zip", zip_bytes=bomb, filename="b.zip", settings=SETTINGS)
    db.session.commit()
    queue.claim("w1")
    assert process(scan.id, SETTINGS) == "failed"
    db.session.refresh(scan)
    assert scan.error_code in {"compression_ratio", "too_large"}


def test_timeout_gives_partial_result_not_failure(user, project):
    scan = _queued(user, project)
    queue.claim("w1")
    assert process(scan.id, make_settings(scan_timeout_s=0)) == "done"
    db.session.refresh(scan)
    assert scan.partial is True and scan.error_code is None
    assert scan.files_scanned == 0 and scan.progress_total >= 1   # se ve cuánto faltó


def test_run_isolated_cancel_and_timeout():
    files = [("a.py", VULN)]
    partial = run_isolated(list(files), None, timeout_s=0, on_tick=lambda d, t: False)
    assert partial.partial and partial.files_scanned == 0 and partial.files_total == 1
    with pytest.raises(ScanCanceledByUser):
        run_isolated([("a.py", VULN * 20000)], None, timeout_s=60, on_tick=lambda d, t: True)
    report = run_isolated(files, None, timeout_s=60, on_tick=lambda d, t: False)
    assert report.findings[0].rule_id == "py/insecure-deserialization"


def test_reaper_requeues_lost_jobs_then_fails(user, project):
    scan = _queued(user, project)
    for attempt in range(1, 4):
        assert queue.claim("w-muerto") == scan.id
        scan = db.session.get(Scan, scan.id)
        scan.heartbeat_at = utcnow() - timedelta(minutes=5)
        db.session.commit()
        requeued, failed = queue.reap()
        db.session.refresh(scan)
        if attempt < 3:
            assert (requeued, failed) == (1, 0) and scan.status == "queued"
    assert scan.status == "failed" and scan.error_code == "worker_lost"


@pytest.mark.skipif(not PG_URL, reason="SKIP LOCKED requiere PostgreSQL")
def test_skip_locked_gives_each_worker_a_different_job(app, user, project):
    a, b = _queued(user, project), _queued(user, project)
    other = db.engine.connect()
    tx = other.begin()
    row = other.execute(queue.CLAIM_SQL, queue.claim_params("w2")).first()  # w2 tiene una fila bloqueada
    mine = queue.claim("w1")
    tx.commit()
    other.close()
    assert {row[0], mine} == {a.id, b.id}


# --- Caché de resultados por contenido ------------------------------------------------------------

def test_identical_content_is_analyzed_once_and_each_project_keeps_its_own_issues(app, user, project):
    from api.models.entities import Project, ScanResultCache, User

    other = User(google_sub="test|otra", email="luis@example.com", name="Luis")
    db.session.add(other)
    db.session.flush()
    other_project = Project(owner_id=other.id, name="demo-luis")
    db.session.add(other_project)
    db.session.commit()

    first = _queued(user, project)
    queue.claim("w1")
    assert process(first.id, SETTINGS) == "done"
    second = _queued(other, other_project)
    queue.claim("w1")
    assert process(second.id, SETTINGS) == "done"

    db.session.refresh(first)
    db.session.refresh(second)
    assert first.result_reused is False and second.result_reused is True
    assert first.summary["by_severity"] == second.summary["by_severity"]
    assert db.session.scalar(select(ScanResultCache.hits)) == 1
    by_project = {i.project_id for i in db.session.scalars(select(Issue))}
    assert by_project == {project.id, other_project.id}  # cada uno con su propio historial


def test_cache_key_changes_with_content_rules_or_engine_scope():
    from api.services.result_cache import cache_key, content_digest

    a = content_digest([("app.py", "x = 1\n")])
    assert a == content_digest([("app.py", "x = 1\n")])
    assert a != content_digest([("app.py", "x = 2\n")])
    assert a != content_digest([("otro.py", "x = 1\n")])
    assert cache_key(a, None, True) != cache_key(a, ["py/sql-injection"], True)
    assert cache_key(a, None, True) != cache_key(a, None, False)


def test_partial_results_are_not_cached(user, project):
    from api.models.entities import ScanResultCache

    scan = _queued(user, project)
    queue.claim("w1")
    process(scan.id, make_settings(scan_timeout_s=0))
    assert db.session.scalar(select(ScanResultCache)) is None


# --- Orden de la cola: prioridad, turnos por usuario y envejecimiento ---------------------------

def _raw_scan(owner, proj, source, minutes_ago, size=None):
    s = Scan(project_id=proj.id, created_by=owner.id, source=source, source_ref=f"{source}-{minutes_ago}",
             status="queued", queued_at=utcnow() - timedelta(minutes=minutes_ago, seconds=0))
    db.session.add(s)
    db.session.flush()
    if size is not None:
        db.session.add(ScanUpload(scan_id=s.id, content=b"x", filename="a.zip", sha256="0" * 64, size=size))
    return s


def _users_and_projects(n):
    from api.models.entities import Project, User

    out = []
    for i in range(n):
        u = User(google_sub=f"test|cola{i}", email=f"u{i}@example.com", name=f"U{i}")
        db.session.add(u)
        db.session.flush()
        p = Project(owner_id=u.id, name=f"p{i}")
        db.session.add(p)
        db.session.flush()
        out.append((u, p))
    return out


def test_queue_puts_fast_scans_first_and_alternates_users(app):
    (a, pa), (b, pb), (c, pc) = _users_and_projects(3)
    a1 = _raw_scan(a, pa, "github", 3)
    a2 = _raw_scan(a, pa, "github", 2.5)
    a3 = _raw_scan(a, pa, "github", 2.4)
    b1 = _raw_scan(b, pb, "github", 2)
    big_zip = _raw_scan(c, pc, "zip", 1.5, size=5 * 1024 * 1024)
    small_zip = _raw_scan(c, pc, "zip", 1.2, size=10 * 1024)
    snippet = _raw_scan(b, pb, "snippet", 1)
    db.session.commit()

    claimed = [queue.claim("w1") for _ in range(7)]
    assert claimed[0] == snippet.id           # lo más rápido primero
    assert claimed[1] == small_zip.id         # luego ZIP pequeños
    # Después, por turnos: a nunca fue atendido, así que va antes que nadie; luego b (atendido
    # en el 1.º turno), luego c (en el 2.º) y al final el resto de a.
    assert claimed[2] == a1.id
    assert claimed[3] == b1.id
    assert claimed[4] == big_zip.id
    assert claimed[5:] == [a2.id, a3.id]


def test_queue_aging_lifts_old_scans_over_fast_ones(app):
    (a, pa), (b, pb) = _users_and_projects(2)
    old_repo = _raw_scan(a, pa, "github", 6)     # más de 5 min esperando
    snippet = _raw_scan(b, pb, "snippet", 0.1)
    db.session.commit()
    assert queue.queue_order()[0] == old_repo.id
    assert queue.claim("w1") == old_repo.id
    assert queue.claim("w1") == snippet.id


def test_queue_position_counts_running_and_estimates_with_median(app):
    (a, pa), (b, pb) = _users_and_projects(2)
    # Historial: tres escaneos de 10, 20 y 600 s -> la mediana (20 s) no se dispara por el lento.
    for secs in (10, 20, 600):
        done = _raw_scan(a, pa, "github", 60)
        done.status, done.started_at = "done", utcnow() - timedelta(minutes=30)
        done.finished_at = done.started_at + timedelta(seconds=secs)
    running = _raw_scan(a, pa, "github", 5)
    running.status, running.started_at = "running", utcnow()
    first = _raw_scan(a, pa, "github", 2)
    second = _raw_scan(b, pb, "github", 1)
    db.session.commit()
    assert queue.typical_duration_s() == 20
    # a ya tiene uno en curso, así que el de b (nunca atendido) pasa delante del de a.
    assert queue.position(second) == {"ahead": 1, "eta_s": 40}    # el que está en curso + él
    assert queue.position(first) == {"ahead": 2, "eta_s": 60}
    assert queue.position(running) is None
