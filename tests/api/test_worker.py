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
from api.worker.runner import ScanCanceledByUser, ScanTimeout, process, run_isolated

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


def test_too_many_entries():
    data = make_zip({f"d/f{i}.txt": b"" for i in range(20_001)})
    with pytest.raises(ArchiveError) as e:
        read_zip(data)
    assert e.value.code == "too_many_entries" and e.value.status == 413


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


def test_timeout_marks_scan_failed(user, project):
    scan = _queued(user, project)
    queue.claim("w1")
    assert process(scan.id, make_settings(scan_timeout_s=0)) == "failed"
    db.session.refresh(scan)
    assert scan.error_code == "timeout"


def test_run_isolated_cancel_and_timeout():
    files = [("a.py", VULN)]
    with pytest.raises(ScanTimeout):
        run_isolated(files, None, timeout_s=0, on_tick=lambda d, t: False)
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
    row = other.execute(queue.CLAIM_SQL, {"worker": "w2"}).first()  # w2 tiene una fila bloqueada
    mine = queue.claim("w1")
    tx.commit()
    other.close()
    assert {row[0], mine} == {a.id, b.id}
