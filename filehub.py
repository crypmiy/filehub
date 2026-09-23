#!/usr/bin/env python3
"""
filehub — file manager berbasis web untuk Jetson, diakses lewat Tailscale.

Jalan di 127.0.0.1:8791, di-expose lewat `tailscale serve --bg --set-path /files`.
Semua URL di frontend bersifat relatif, jadi aman dipasang di subpath.

Env:
  FILEHUB_ROOT      root direktori yang boleh dibrowse (default: /home/jetson)
  FILEHUB_PASSWORD  kalau diisi, wajib login. Kosong = tanpa login (andalkan tailnet)
  FILEHUB_SECRET    secret untuk tanda tangan cookie (default: random per-restart)
  FILEHUB_HOST      default 127.0.0.1
  FILEHUB_PORT      default 8791
  FILEHUB_READONLY  "1" untuk mode baca saja
"""

from __future__ import annotations

import hashlib
import hmac
import mimetypes
import os
import secrets
import shutil
import stat
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
)
from pydantic import BaseModel
from starlette.background import BackgroundTask

__version__ = "1.2.0"

ROOT = Path(os.environ.get("FILEHUB_ROOT", "/home/jetson")).expanduser().resolve()
PASSWORD = os.environ.get("FILEHUB_PASSWORD", "")
SECRET = os.environ.get("FILEHUB_SECRET") or secrets.token_hex(32)
READONLY = os.environ.get("FILEHUB_READONLY", "") == "1"
COOKIE = "filehub_session"
SESSION_TTL = 7 * 24 * 3600
TEXT_MAX = 2 * 1024 * 1024
EDITABLE_SUFFIX = {
    ".py", ".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".sh", ".bash", ".service", ".env", ".sql", ".csv", ".log",
    ".html", ".css", ".js", ".ts", ".jsx", ".tsx", ".xml", ".rs", ".go",
    ".c", ".h", ".cpp", ".java", ".rb", ".php", ".lua", ".gitignore",
}
PREVIEW_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".ico"}

app = FastAPI(title="filehub", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)


# ---------------------------------------------------------------- auth

def sign(value: str) -> str:
    mac = hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"{value}.{mac}"


def verify(token: str) -> bool:
    try:
        value, mac = token.rsplit(".", 1)
        expected = hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            return False
        return int(value) + SESSION_TTL > time.time()
    except Exception:
        return False


def authed(request: Request) -> bool:
    if not PASSWORD:
        return True
    token = request.cookies.get(COOKIE, "")
    return bool(token) and verify(token)


def require(request: Request) -> None:
    if not authed(request):
        raise HTTPException(status_code=401, detail="Sesi habis. Login lagi.")


def require_write(request: Request) -> None:
    require(request)
    if READONLY:
        raise HTTPException(status_code=403, detail="Mode baca saja aktif.")


# ---------------------------------------------------------------- paths

def resolve(rel: str) -> Path:
    rel = (rel or "").strip().lstrip("/")
    target = (ROOT / rel).resolve() if rel else ROOT
    if target != ROOT and ROOT not in target.parents:
        raise HTTPException(status_code=400, detail="Path di luar root.")
    return target


def relname(p: Path) -> str:
    return "" if p == ROOT else str(p.relative_to(ROOT))


def check_name(name: str) -> str:
    name = (name or "").strip()
    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        raise HTTPException(status_code=400, detail="Nama tidak valid.")
    return name


def unique(folder: Path, name: str) -> Path:
    """Cari nama yang belum dipakai di folder tujuan: 'x.txt' -> 'x (1).txt'."""
    target = folder / name
    if not target.exists():
        return target
    base = Path(name)
    stem, suffix = base.stem, base.suffix
    n = 1
    while True:
        candidate = folder / f"{stem} ({n}){suffix}"
        if not candidate.exists():
            return candidate
        n += 1


ARCHIVE_SUFFIX = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")


def is_archive(p: Path) -> bool:
    return p.name.lower().endswith(ARCHIVE_SUFFIX)


def describe(p: Path) -> dict:
    try:
        st = p.lstat()
    except OSError:
        return {}
    is_link = stat.S_ISLNK(st.st_mode)
    is_dir = p.is_dir()
    suffix = p.suffix.lower()
    return {
        "name": p.name,
        "rel": relname(p),
        "dir": is_dir,
        "link": is_link,
        "size": 0 if is_dir else st.st_size,
        "mtime": int(st.st_mtime),
        "mode": stat.filemode(st.st_mode),
        "editable": (not is_dir) and (suffix in EDITABLE_SUFFIX or not suffix) and st.st_size <= TEXT_MAX,
        "image": (not is_dir) and suffix in PREVIEW_SUFFIX,
        "archive": (not is_dir) and is_archive(p),
        "exec": bool(st.st_mode & stat.S_IXUSR) and not is_dir,
    }


# ---------------------------------------------------------------- models

class PathBody(BaseModel):
    path: str = ""


class NameBody(BaseModel):
    path: str = ""
    name: str


class RenameBody(BaseModel):
    path: str
    name: str


class DeleteBody(BaseModel):
    paths: List[str]


class SaveBody(BaseModel):
    path: str
    content: str


class MoveBody(BaseModel):
    paths: List[str]
    dest: str = ""


class ChmodBody(BaseModel):
    path: str
    executable: bool


# ---------------------------------------------------------------- routes

@app.post("/api/login")
def login(password: str = Form(...)):
    if not PASSWORD:
        return {"ok": True}
    if not hmac.compare_digest(password, PASSWORD):
        time.sleep(0.7)
        raise HTTPException(status_code=401, detail="Password salah.")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        COOKIE, sign(str(int(time.time()))),
        max_age=SESSION_TTL, httponly=True, samesite="lax", path="/",
    )
    return resp


@app.post("/api/logout")
def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE, path="/")
    return resp


@app.get("/api/config")
def config(request: Request):
    usage = shutil.disk_usage(ROOT)
    return {
        "authed": authed(request),
        "locked": bool(PASSWORD),
        "readonly": READONLY,
        "root": str(ROOT),
        "version": __version__,
        "host": os.uname().nodename,
        "disk": {"total": usage.total, "used": usage.used, "free": usage.free},
    }


@app.get("/api/list", dependencies=[Depends(require)])
def listing(path: str = ""):
    target = resolve(path)
    if not target.is_dir():
        raise HTTPException(status_code=404, detail="Folder tidak ditemukan.")
    items = []
    try:
        entries = list(target.iterdir())
    except PermissionError:
        raise HTTPException(status_code=403, detail="Tidak ada izin baca folder ini.")
    for child in entries:
        info = describe(child)
        if info:
            items.append(info)
    items.sort(key=lambda i: (not i["dir"], i["name"].lower()))
    crumbs, acc = [], []
    for part in (relname(target).split("/") if relname(target) else []):
        acc.append(part)
        crumbs.append({"name": part, "rel": "/".join(acc)})
    return {
        "path": relname(target),
        "parent": relname(target.parent) if target != ROOT else None,
        "crumbs": crumbs,
        "items": items,
    }


@app.get("/api/download", dependencies=[Depends(require)])
def download(path: str, inline: int = 0):
    target = resolve(path)
    if not target.is_file():
        raise HTTPException(status_code=404, detail="File tidak ditemukan.")
    media, _ = mimetypes.guess_type(target.name)
    return FileResponse(
        target,
        media_type=media or "application/octet-stream",
        filename=None if inline else target.name,
        content_disposition_type="inline" if inline else "attachment",
    )


@app.get("/api/zip", dependencies=[Depends(require)])
def zip_folder(path: str = ""):
    target = resolve(path)
    if not target.is_dir():
        raise HTTPException(status_code=400, detail="Hanya folder yang bisa di-zip.")
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp.close()
    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED, compresslevel=5) as zf:
        for file in target.rglob("*"):
            if file.is_file() and not file.is_symlink():
                try:
                    zf.write(file, file.relative_to(target))
                except (PermissionError, OSError):
                    continue
    name = (target.name or "root") + ".zip"
    return FileResponse(
        tmp.name, media_type="application/zip", filename=name,
        background=BackgroundTask(lambda: os.unlink(tmp.name)),
    )


@app.get("/api/bundle", dependencies=[Depends(require)])
def bundle(paths: List[str] = Query(default=[]), name: str = "pilihan"):
    """Unduh beberapa item terpilih sekaligus sebagai satu arsip .zip."""
    targets = [resolve(p) for p in paths if p]
    if not targets:
        raise HTTPException(status_code=400, detail="Tidak ada item yang dipilih.")
    if len(targets) == 1 and targets[0].is_file():
        return download(relname(targets[0]))

    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp.close()
    used: set[str] = set()

    def arcname(base: str) -> str:
        candidate, stem, n = base, base, 1
        while candidate in used:
            head, dot, tail = stem.partition(".")
            candidate = f"{head} ({n}){dot}{tail}"
            n += 1
        used.add(candidate)
        return candidate

    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED, compresslevel=5) as zf:
        for target in targets:
            if target == ROOT:
                continue
            try:
                if target.is_file() and not target.is_symlink():
                    zf.write(target, arcname(target.name))
                elif target.is_dir():
                    top = arcname(target.name)
                    for file in target.rglob("*"):
                        if file.is_file() and not file.is_symlink():
                            zf.write(file, f"{top}/{file.relative_to(target)}")
            except (PermissionError, OSError):
                continue

    safe_name = "".join(c for c in name if c.isalnum() or c in "-_ ").strip() or "pilihan"
    return FileResponse(
        tmp.name, media_type="application/zip", filename=f"{safe_name}.zip",
        background=BackgroundTask(lambda: os.unlink(tmp.name)),
    )


@app.get("/api/read", dependencies=[Depends(require)])
def read_file(path: str):
    target = resolve(path)
    if not target.is_file():
        raise HTTPException(status_code=404, detail="File tidak ditemukan.")
    if target.stat().st_size > TEXT_MAX:
        raise HTTPException(status_code=413, detail="File terlalu besar untuk diedit di sini.")
    try:
        return {"content": target.read_text(encoding="utf-8")}
    except UnicodeDecodeError:
        raise HTTPException(status_code=415, detail="Bukan file teks.")


@app.post("/api/save", dependencies=[Depends(require_write)])
def save_file(body: SaveBody):
    target = resolve(body.path)
    if target.is_dir():
        raise HTTPException(status_code=400, detail="Itu folder, bukan file.")
    tmp = target.with_name(target.name + ".filehub.tmp")
    tmp.write_text(body.content, encoding="utf-8")
    os.replace(tmp, target)
    return {"ok": True, "size": target.stat().st_size}


@app.post("/api/mkdir", dependencies=[Depends(require_write)])
def mkdir(body: NameBody):
    parent = resolve(body.path)
    target = parent / check_name(body.name)
    if target.exists():
        raise HTTPException(status_code=409, detail="Sudah ada yang bernama itu.")
    target.mkdir(parents=False)
    return {"ok": True, "rel": relname(target)}


@app.post("/api/newfile", dependencies=[Depends(require_write)])
def newfile(body: NameBody):
    parent = resolve(body.path)
    target = parent / check_name(body.name)
    if target.exists():
        raise HTTPException(status_code=409, detail="Sudah ada yang bernama itu.")
    target.touch()
    return {"ok": True, "rel": relname(target)}


@app.post("/api/rename", dependencies=[Depends(require_write)])
def rename(body: RenameBody):
    target = resolve(body.path)
    if target == ROOT:
        raise HTTPException(status_code=400, detail="Root tidak bisa diganti nama.")
    dest = target.with_name(check_name(body.name))
    if dest.exists():
        raise HTTPException(status_code=409, detail="Sudah ada yang bernama itu.")
    target.rename(dest)
    return {"ok": True, "rel": relname(dest)}


@app.post("/api/move", dependencies=[Depends(require_write)])
def move(body: MoveBody):
    dest = resolve(body.dest)
    if not dest.is_dir():
        raise HTTPException(status_code=400, detail="Tujuan bukan folder.")
    moved = 0
    for rel in body.paths:
        src = resolve(rel)
        if src == ROOT or src == dest or src in dest.parents:
            continue
        shutil.move(str(src), str(unique(dest, src.name)))
        moved += 1
    return {"ok": True, "moved": moved}


@app.post("/api/copy", dependencies=[Depends(require_write)])
def copy(body: MoveBody):
    dest = resolve(body.dest)
    if not dest.is_dir():
        raise HTTPException(status_code=400, detail="Tujuan bukan folder.")
    copied = 0
    for rel in body.paths:
        src = resolve(rel)
        if src == ROOT or src == dest or src in dest.parents:
            continue
        target = unique(dest, src.name)
        if src.is_dir():
            shutil.copytree(src, target, symlinks=True)
        else:
            shutil.copy2(src, target, follow_symlinks=False)
        copied += 1
    return {"ok": True, "copied": copied}


@app.post("/api/duplicate", dependencies=[Depends(require_write)])
def duplicate(body: PathBody):
    src = resolve(body.path)
    if src == ROOT:
        raise HTTPException(status_code=400, detail="Root tidak bisa diduplikat.")
    target = unique(src.parent, src.name)
    if src.is_dir():
        shutil.copytree(src, target, symlinks=True)
    else:
        shutil.copy2(src, target, follow_symlinks=False)
    return {"ok": True, "rel": relname(target)}


@app.post("/api/extract", dependencies=[Depends(require_write)])
def extract(body: PathBody):
    src = resolve(body.path)
    if not src.is_file() or not is_archive(src):
        raise HTTPException(status_code=400, detail="Bukan arsip yang didukung.")
    out = unique(src.parent, src.name.split(".")[0] or "hasil-ekstrak")
    out.mkdir()

    def inside(name: str) -> bool:
        target = (out / name).resolve()
        return target == out or out in target.parents

    try:
        if src.name.lower().endswith(".zip"):
            with zipfile.ZipFile(src) as zf:
                members = [m for m in zf.namelist() if inside(m)]
                zf.extractall(out, members=members)
        else:
            with tarfile.open(src) as tf:
                tf.extractall(out, filter="data")
    except Exception as exc:
        shutil.rmtree(out, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"Gagal mengekstrak: {exc}")
    return {"ok": True, "rel": relname(out)}


@app.post("/api/chmod", dependencies=[Depends(require_write)])
def chmod(body: ChmodBody):
    target = resolve(body.path)
    if not target.is_file():
        raise HTTPException(status_code=400, detail="Hanya berlaku untuk file.")
    mode = target.stat().st_mode
    bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    target.chmod(mode | bits if body.executable else mode & ~bits)
    return {"ok": True, "mode": stat.filemode(target.stat().st_mode)}


@app.get("/api/search", dependencies=[Depends(require)])
def search(path: str = "", q: str = "", limit: int = 300):
    needle = q.strip().lower()
    if len(needle) < 2:
        raise HTTPException(status_code=400, detail="Kata kunci minimal 2 huruf.")
    base = resolve(path)
    if not base.is_dir():
        raise HTTPException(status_code=404, detail="Folder tidak ditemukan.")
    hits, truncated = [], False
    for child in base.rglob("*"):
        if needle not in child.name.lower():
            continue
        info = describe(child)
        if info:
            hits.append(info)
        if len(hits) >= max(1, min(limit, 1000)):
            truncated = True
            break
    hits.sort(key=lambda i: (not i["dir"], i["name"].lower()))
    return {"items": hits, "truncated": truncated, "base": relname(base)}


@app.post("/api/delete", dependencies=[Depends(require_write)])
def delete(body: DeleteBody):
    removed = 0
    for rel in body.paths:
        target = resolve(rel)
        if target == ROOT:
            continue
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
        removed += 1
    return {"ok": True, "removed": removed}


@app.post("/api/upload", dependencies=[Depends(require_write)])
async def upload(path: str = Form(""), files: List[UploadFile] = File(...)):
    parent = resolve(path)
    if not parent.is_dir():
        raise HTTPException(status_code=400, detail="Tujuan upload bukan folder.")
    saved = []
    for item in files:
        name = check_name(os.path.basename(item.filename or ""))
        dest = parent / name
        with dest.open("wb") as out:
            while chunk := await item.read(1024 * 1024):
                out.write(chunk)
        saved.append(name)
    return {"ok": True, "saved": saved}


@app.get("/health")
def health():
    return PlainTextResponse(f"filehub {__version__} ok")


@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse(PAGE)


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


# ---------------------------------------------------------------- frontend

PAGE = r"""<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>filehub</title>
<style>
:root{
  --ink:#151a21; --panel:#1c232c; --panel-2:#222b36; --line:#2d3947;
  --text:#dbe3ec; --dim:#8b99ab; --accent:#79a6d2; --accent-soft:#2a3d51;
  --warn:#d99a55; --danger:#cf6b6b; --ok:#7fb582;
  --mono:ui-monospace,"JetBrains Mono","SF Mono",Menlo,Consolas,monospace;
  --sans:"Inter",system-ui,-apple-system,"Segoe UI",sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--ink);color:var(--text);font-family:var(--sans);font-size:15px;
     -webkit-font-smoothing:antialiased;display:flex;flex-direction:column}
button,input,textarea{font:inherit;color:inherit}
button{cursor:pointer;background:none;border:none}

header{position:sticky;top:0;z-index:20;background:var(--panel);border-bottom:1px solid var(--line);
       padding:10px 14px calc(10px + env(safe-area-inset-bottom,0px)/6);display:flex;flex-direction:column;gap:9px}
.top{display:flex;align-items:center;gap:10px}
.brand{font-family:var(--mono);font-size:14px;letter-spacing:.02em;color:var(--accent)}
.brand em{font-style:normal;color:var(--dim);font-size:11px;margin-left:5px}
.host{font-family:var(--mono);font-size:11px;color:var(--dim);margin-left:auto;text-align:right;line-height:1.35}
.crumbs{display:flex;gap:4px;align-items:center;overflow-x:auto;font-family:var(--mono);font-size:12.5px;
        white-space:nowrap;scrollbar-width:none}
.crumbs::-webkit-scrollbar{display:none}
.crumbs button{color:var(--accent);padding:2px 0}
.crumbs span{color:var(--dim)}
.crumbs .here{color:var(--text)}

.bar{display:flex;gap:7px;overflow-x:auto;scrollbar-width:none;padding-bottom:1px}
.bar::-webkit-scrollbar{display:none}
.act{border:1px solid var(--line);background:var(--panel-2);border-radius:7px;padding:6px 11px;
     font-size:13px;color:var(--text);white-space:nowrap}
.act:hover{border-color:var(--accent);color:var(--accent)}
.act:disabled{opacity:.4}
.act.danger:hover{border-color:var(--danger);color:var(--danger)}
.act.go{background:var(--accent-soft);border-color:#3c566f}

main{flex:1;overflow-y:auto;padding:4px 0 90px}
.row{display:flex;align-items:center;gap:10px;padding:9px 14px;border-bottom:1px solid #232c37}
.row:hover{background:#1a212a}
.row.sel{background:var(--accent-soft)}
.tick{width:17px;height:17px;flex:none;border:1px solid #3d4c5d;border-radius:4px;display:grid;place-items:center;
      font-size:11px;color:var(--ink);background:transparent}
.row.sel .tick{background:var(--accent);border-color:var(--accent)}
.glyph{width:22px;flex:none;text-align:center;font-family:var(--mono);font-size:13px;color:var(--dim)}
.row.d .glyph{color:var(--warn)}
.meta{min-width:0;flex:1}
.nm{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:14.5px}
.row.d .nm{color:#ecd9bd}
.sub{font-family:var(--mono);font-size:11px;color:var(--dim);margin-top:2px}
.chev{color:var(--dim);font-size:18px;padding:0 2px}

.empty{padding:44px 22px;text-align:center;color:var(--dim);line-height:1.6}
.empty b{display:block;color:var(--text);font-weight:500;margin-bottom:5px}

footer{position:fixed;bottom:0;left:0;right:0;background:var(--panel);border-top:1px solid var(--line);
       padding:8px 14px calc(8px + env(safe-area-inset-bottom,0px));display:flex;gap:10px;align-items:center;
       font-family:var(--mono);font-size:11.5px;color:var(--dim);z-index:20}
.gauge{flex:1;height:4px;background:#2a333f;border-radius:3px;overflow:hidden;max-width:150px}
.gauge i{display:block;height:100%;background:var(--accent)}

.sheet{position:fixed;inset:0;background:rgba(8,11,15,.72);z-index:40;display:none;align-items:flex-end;
       justify-content:center;backdrop-filter:blur(2px)}
.sheet.on{display:flex}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px 14px 0 0;width:100%;max-width:640px;
      padding:16px 16px calc(16px + env(safe-area-inset-bottom,0px));max-height:92vh;display:flex;flex-direction:column;gap:11px}
@media(min-width:680px){.sheet{align-items:center}.card{border-radius:12px}}
.card h2{margin:0;font-size:15px;font-weight:600}
.card p{margin:0;font-size:13px;color:var(--dim);font-family:var(--mono);word-break:break-all}
.card input[type=text],.card input[type=password]{width:100%;background:var(--ink);border:1px solid var(--line);
      border-radius:8px;padding:10px 11px;font-family:var(--mono);font-size:14px}
.card input:focus,.act:focus-visible,.row:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.card textarea{width:100%;flex:1;min-height:46vh;background:var(--ink);border:1px solid var(--line);border-radius:8px;
      padding:11px;font-family:var(--mono);font-size:13px;line-height:1.55;resize:none;white-space:pre;overflow-wrap:normal}
.card img{max-width:100%;max-height:66vh;object-fit:contain;border-radius:8px;background:#0d1116}
.opts{display:flex;flex-direction:column;gap:1px}
.opt{text-align:left;padding:11px 4px;border-bottom:1px solid #232c37;font-size:14px}
.opt:last-child{border-bottom:none}
.opt.danger{color:var(--danger)}
.ends{display:flex;gap:8px;justify-content:flex-end;padding-top:2px}
.msg{position:fixed;left:50%;transform:translateX(-50%);bottom:58px;background:var(--panel-2);
     border:1px solid var(--line);border-radius:8px;padding:9px 14px;font-size:13px;z-index:60;
     opacity:0;transition:opacity .18s;pointer-events:none;max-width:88vw;text-align:center}
.msg.on{opacity:1}
.msg.bad{border-color:var(--danger);color:#f0b5b5}
.drop{position:fixed;inset:0;border:2px dashed var(--accent);background:rgba(121,166,210,.1);z-index:50;
      display:none;place-items:center;font-family:var(--mono);color:var(--accent)}
.drop.on{display:grid}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
</head>
<body>

<header>
  <div class="top">
    <span class="brand">filehub<em id="ver"></em></span>
    <span class="host" id="host"></span>
  </div>
  <nav class="crumbs" id="crumbs"></nav>
  <div class="bar" id="bar">
    <button class="act go" id="bUp">Unggah</button>
    <button class="act" id="bFolder">Folder baru</button>
    <button class="act" id="bFile">File baru</button>
    <button class="act" id="bZip">Unduh folder .zip</button>
    <button class="act" id="bCari">Cari</button>
    <button class="act" id="bSort">Urut: nama</button>
    <button class="act" id="bHidden">Tampilkan tersembunyi</button>
    <button class="act" id="bAll">Pilih semua</button>
    <button class="act" id="bReload">Muat ulang</button>
    <button class="act" id="bOut">Keluar</button>
  </div>
</header>

<main id="list"></main>

<footer>
  <span id="count"></span>
  <span class="gauge"><i id="gauge"></i></span>
  <span id="disk"></span>
</footer>

<div class="sheet" id="sheet"><div class="card" id="card"></div></div>
<div class="drop" id="drop">Lepas file untuk mengunggah</div>
<div class="msg" id="msg"></div>
<input type="file" id="picker" multiple hidden>

<script>
if (!location.pathname.endsWith('/')) history.replaceState(null, '', location.pathname + '/');

const $ = id => document.getElementById(id);
const listEl = $('list'), sheet = $('sheet'), card = $('card');
let cwd = '', items = [], picked = new Set(), cfg = {};
let clip = null, sortBy = 'name', showHidden = false, searching = false;
const SORTS = {name: 'nama', size: 'ukuran', time: 'waktu'};

const fmtSize = n => {
  if (n < 1024) return n + ' B';
  const u = ['KB','MB','GB','TB']; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < 3);
  return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i];
};
const fmtDate = t => new Date(t * 1000).toLocaleString('id-ID',
  {day:'2-digit', month:'short', year:'2-digit', hour:'2-digit', minute:'2-digit'});

let msgTimer;
function toast(text, bad) {
  const m = $('msg');
  m.textContent = text; m.className = 'msg on' + (bad ? ' bad' : '');
  clearTimeout(msgTimer); msgTimer = setTimeout(() => m.className = 'msg', 2600);
}

async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  if (res.status === 401) { askLogin(); throw new Error('unauth'); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || 'Gagal (' + res.status + ')');
  return data;
}

function closeSheet() { sheet.className = 'sheet'; card.innerHTML = ''; }
sheet.onclick = e => { if (e.target === sheet) closeSheet(); };
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeSheet(); });

function openSheet(html, wire) {
  card.innerHTML = html; sheet.className = 'sheet on';
  if (wire) wire();
  const first = card.querySelector('input,textarea');
  if (first) { first.focus(); if (first.select) first.select(); }
}

// ---------- login
function askLogin() {
  openSheet(`
    <h2>Masuk ke filehub</h2>
    <p>Jetson hanya bisa dibuka dari tailnet kamu.</p>
    <input type="password" id="pw" placeholder="Password" autocomplete="current-password">
    <div class="ends"><button class="act go" id="ok">Masuk</button></div>`, () => {
    const go = async () => {
      const fd = new FormData(); fd.append('password', $('pw').value);
      try {
        await api('api/login', {method:'POST', body:fd});
        closeSheet(); boot();
      } catch (e) { toast(e.message, true); }
    };
    $('ok').onclick = go;
    $('pw').onkeydown = e => { if (e.key === 'Enter') go(); };
  });
}

// ---------- listing
async function load(path) {
  try {
    const data = await api('api/list?path=' + encodeURIComponent(path));
    cwd = data.path; picked.clear(); items = data.items; searching = false;
    drawCrumbs(data.crumbs); draw();
  } catch (e) { if (e.message !== 'unauth') toast(e.message, true); }
}

function drawCrumbs(crumbs) {
  const el = $('crumbs'); el.innerHTML = '';
  const home = document.createElement('button');
  home.textContent = cfg.root || '/'; home.onclick = () => load('');
  el.appendChild(home);
  crumbs.forEach((c, i) => {
    const sep = document.createElement('span'); sep.textContent = '/'; el.appendChild(sep);
    const b = document.createElement('button');
    b.textContent = c.name;
    if (i === crumbs.length - 1) b.className = 'here';
    b.onclick = () => load(c.rel);
    el.appendChild(b);
  });
  el.scrollLeft = el.scrollWidth;
}

function visible() {
  let out = showHidden ? items.slice() : items.filter(i => !i.name.startsWith('.'));
  const by = {
    name: (a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()),
    size: (a, b) => b.size - a.size,
    time: (a, b) => b.mtime - a.mtime,
  }[sortBy];
  out.sort((a, b) => (a.dir === b.dir ? by(a, b) : (a.dir ? -1 : 1)));
  return out;
}

function draw() {
  listEl.innerHTML = '';
  const rows = visible();
  if (!rows.length) {
    listEl.innerHTML = searching
      ? '<div class="empty"><b>Tidak ada yang cocok</b>Coba kata kunci lain.</div>'
      : '<div class="empty"><b>Folder ini kosong</b>Unggah file atau buat folder baru.</div>';
  }
  for (const it of rows) {
    const row = document.createElement('div');
    row.className = 'row' + (it.dir ? ' d' : '') + (picked.has(it.rel) ? ' sel' : '');
    row.tabIndex = 0;

    const tick = document.createElement('button');
    tick.className = 'tick'; tick.textContent = picked.has(it.rel) ? '\u2713' : '';
    tick.onclick = e => { e.stopPropagation(); toggle(it.rel); };

    const glyph = document.createElement('span');
    glyph.className = 'glyph';
    glyph.textContent = it.dir ? '[]' : (it.link ? '->' : (it.image ? '<>' : '\u00b7'));

    const meta = document.createElement('div');
    meta.className = 'meta';
    const nm = document.createElement('span'); nm.className = 'nm'; nm.textContent = it.name;
    const sub = document.createElement('span'); sub.className = 'sub';
    const where = searching ? (it.rel.split('/').slice(0, -1).join('/') || '/') + '  ·  ' : '';
    sub.textContent = where + (it.dir ? 'folder' : fmtSize(it.size)) + '  ·  ' + fmtDate(it.mtime) + '  ·  ' + it.mode;
    meta.append(nm, sub);

    const chev = document.createElement('button');
    chev.className = 'chev'; chev.textContent = '\u22ee';
    chev.setAttribute('aria-label', 'Aksi untuk ' + it.name);
    chev.onclick = e => { e.stopPropagation(); actions(it); };

    row.append(tick, glyph, meta, chev);
    row.onclick = () => open(it);
    row.onkeydown = e => { if (e.key === 'Enter') open(it); };
    listEl.appendChild(row);
  }
  const n = picked.size;
  $('count').textContent = n ? n + ' dipilih' : rows.length + ' item';
  $('bSort').textContent = 'Urut: ' + SORTS[sortBy];
  $('bHidden').textContent = showHidden ? 'Sembunyikan tersembunyi' : 'Tampilkan tersembunyi';
  $('bAll').textContent = (n && n === rows.length) ? 'Batal pilih' : 'Pilih semua';
  drawSelectionBar();
  drawClipBar();
}

function drawSelectionBar() {
  let bar = document.getElementById('selbar');
  if (bar) bar.remove();
  if (!picked.size) return;
  bar = document.createElement('div');
  bar.id = 'selbar'; bar.className = 'bar'; bar.style.marginTop = '2px';
  const mk = (label, cls, fn) => {
    const b = document.createElement('button'); b.className = 'act ' + cls;
    b.textContent = label; b.onclick = fn; bar.appendChild(b);
  };
  mk('Unduh (' + picked.size + ')', 'go', downloadPicked);
  mk('Salin', '', () => setClip('copy'));
  mk('Potong', '', () => setClip('move'));
  mk('Hapus (' + picked.size + ')', 'danger', () => confirmDelete([...picked]));
  mk('Batal pilih', '', () => { picked.clear(); draw(); });
  $('bar').after(bar);
}

function drawClipBar() {
  let bar = document.getElementById('clipbar');
  if (bar) bar.remove();
  if (!clip) return;
  bar = document.createElement('div');
  bar.id = 'clipbar'; bar.className = 'bar'; bar.style.marginTop = '2px';
  const verb = clip.mode === 'copy' ? 'Salin' : 'Pindahkan';
  const mk = (label, cls, fn) => {
    const b = document.createElement('button'); b.className = 'act ' + cls;
    b.textContent = label; b.onclick = fn; bar.appendChild(b);
  };
  mk(verb + ' ' + clip.paths.length + ' item ke sini', 'go', pasteHere);
  mk('Batalkan papan klip', '', () => { clip = null; draw(); });
  ($('selbar') || $('bar')).after(bar);
}

function setClip(mode) {
  clip = {mode, paths: [...picked]};
  picked.clear(); draw();
  toast('Buka folder tujuan, lalu tekan tombol tempel');
}

async function pasteHere() {
  const url = clip.mode === 'copy' ? 'api/copy' : 'api/move';
  try {
    const r = await api(url, {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({paths: clip.paths, dest: cwd})});
    toast((r.copied ?? r.moved) + ' item ' + (clip.mode === 'copy' ? 'disalin' : 'dipindah'));
    clip = null; load(cwd);
  } catch (e) { toast(e.message, true); }
}

function downloadPicked() {
  const sel = [...picked];
  if (!sel.length) return;
  const only = items.find(i => i.rel === sel[0]);
  if (sel.length === 1 && only && !only.dir) {
    location.href = 'api/download?path=' + encodeURIComponent(sel[0]);
    return;
  }
  const name = cwd ? cwd.split('/').pop() : 'filehub';
  const q = sel.map(p => 'paths=' + encodeURIComponent(p)).join('&');
  toast('Menyiapkan arsip ' + sel.length + ' item…');
  location.href = 'api/bundle?name=' + encodeURIComponent(name) + '&' + q;
}

function toggle(rel) {
  picked.has(rel) ? picked.delete(rel) : picked.add(rel);
  draw();
}

function open(it) {
  if (it.dir) return load(it.rel);
  if (it.image) return preview(it);
  if (it.editable) return edit(it);
  location.href = 'api/download?path=' + encodeURIComponent(it.rel);
}

// ---------- per-item actions
function actions(it) {
  const ro = cfg.readonly;
  openSheet(`
    <h2>${esc(it.name)}</h2>
    <p>${esc(it.rel)}</p>
    <div class="opts" id="opts"></div>`, () => {
    const box = $('opts');
    const add = (label, fn, cls) => {
      const b = document.createElement('button');
      b.className = 'opt ' + (cls || ''); b.textContent = label;
      b.onclick = fn; box.appendChild(b);
    };
    if (it.dir) {
      add('Buka folder', () => { closeSheet(); load(it.rel); });
      add('Unduh sebagai .zip', () => { closeSheet(); location.href = 'api/zip?path=' + encodeURIComponent(it.rel); });
    } else {
      add('Unduh', () => { closeSheet(); location.href = 'api/download?path=' + encodeURIComponent(it.rel); });
      if (it.image) add('Lihat gambar', () => preview(it));
      if (it.editable) add(ro ? 'Lihat isi' : 'Edit teks', () => edit(it));
      add('Buka di tab baru', () => { window.open('api/download?inline=1&path=' + encodeURIComponent(it.rel), '_blank'); closeSheet(); });
    }
    if (!ro) {
      if (it.archive) add('Ekstrak di sini', () => runAction('api/extract', {path: it.rel}, 'Arsip diekstrak'));
      add('Duplikat', () => runAction('api/duplicate', {path: it.rel}, 'Salinan dibuat'));
      add('Ganti nama', () => renameItem(it));
      if (!it.dir) add(it.exec ? 'Cabut izin jalankan' : 'Jadikan bisa dijalankan',
        () => runAction('api/chmod', {path: it.rel, executable: !it.exec}, 'Izin diubah'));
      add('Hapus', () => confirmDelete([it.rel]), 'danger');
    }
  });
}

const esc = s => s.replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function renameItem(it) {
  openSheet(`
    <h2>Ganti nama</h2>
    <input type="text" id="nm" value="${esc(it.name)}">
    <div class="ends"><button class="act" id="no">Batal</button><button class="act go" id="ok">Simpan</button></div>`, () => {
    $('no').onclick = closeSheet;
    const go = async () => {
      try {
        await api('api/rename', {method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({path: it.rel, name: $('nm').value})});
        closeSheet(); toast('Nama diganti'); load(cwd);
      } catch (e) { toast(e.message, true); }
    };
    $('ok').onclick = go;
    $('nm').onkeydown = e => { if (e.key === 'Enter') go(); };
  });
}

function confirmDelete(paths) {
  openSheet(`
    <h2>Hapus ${paths.length} item?</h2>
    <p>${esc(paths.slice(0, 6).join('\n'))}${paths.length > 6 ? '\n…' : ''}</p>
    <p style="color:var(--danger)">Folder dihapus beserta isinya. Tidak bisa dibatalkan.</p>
    <div class="ends"><button class="act" id="no">Batal</button><button class="act danger" id="ok">Hapus</button></div>`, () => {
    $('no').onclick = closeSheet;
    $('ok').onclick = async () => {
      try {
        const r = await api('api/delete', {method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({paths})});
        closeSheet(); toast(r.removed + ' item dihapus'); load(cwd);
      } catch (e) { toast(e.message, true); }
    };
  });
}

// ---------- aksi umum & pencarian
async function runAction(url, body, okMsg) {
  try {
    await api(url, {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body)});
    closeSheet(); toast(okMsg); load(cwd);
  } catch (e) { toast(e.message, true); }
}

function askSearch() {
  openSheet(`
    <h2>Cari di folder ini</h2>
    <p>termasuk semua subfolder</p>
    <input type="text" id="q" placeholder="nama file atau sebagian nama">
    <div class="ends"><button class="act" id="no">Batal</button><button class="act go" id="ok">Cari</button></div>`, () => {
    $('no').onclick = closeSheet;
    const go = async () => {
      const q = $('q').value.trim();
      try {
        const data = await api('api/search?path=' + encodeURIComponent(cwd) + '&q=' + encodeURIComponent(q));
        closeSheet();
        items = data.items; picked.clear(); searching = true; draw();
        toast(data.items.length + ' hasil' + (data.truncated ? ' (dipotong)' : '') + ' untuk "' + q + '"');
      } catch (e) { toast(e.message, true); }
    };
    $('ok').onclick = go;
    $('q').onkeydown = e => { if (e.key === 'Enter') go(); };
  });
}

// ---------- editor & preview
async function edit(it) {
  try {
    const data = await api('api/read?path=' + encodeURIComponent(it.rel));
    openSheet(`
      <h2>${esc(it.name)}</h2>
      <textarea id="ta" spellcheck="false"></textarea>
      <div class="ends">
        <button class="act" id="no">Tutup</button>
        ${cfg.readonly ? '' : '<button class="act go" id="ok">Simpan file</button>'}
      </div>`, () => {
      $('ta').value = data.content;
      $('no').onclick = closeSheet;
      if ($('ok')) $('ok').onclick = async () => {
        try {
          await api('api/save', {method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({path: it.rel, content: $('ta').value})});
          closeSheet(); toast('Tersimpan'); load(cwd);
        } catch (e) { toast(e.message, true); }
      };
    });
  } catch (e) { toast(e.message, true); }
}

function preview(it) {
  openSheet(`
    <h2>${esc(it.name)}</h2>
    <img src="api/download?inline=1&path=${encodeURIComponent(it.rel)}" alt="${esc(it.name)}">
    <div class="ends"><button class="act" id="no">Tutup</button></div>`,
    () => { $('no').onclick = closeSheet; });
}

// ---------- create
function creator(kind) {
  const isDir = kind === 'dir';
  openSheet(`
    <h2>${isDir ? 'Folder baru' : 'File baru'}</h2>
    <p>di ${esc(cwd || cfg.root)}</p>
    <input type="text" id="nm" placeholder="${isDir ? 'nama-folder' : 'catatan.md'}">
    <div class="ends"><button class="act" id="no">Batal</button><button class="act go" id="ok">Buat</button></div>`, () => {
    $('no').onclick = closeSheet;
    const go = async () => {
      try {
        await api(isDir ? 'api/mkdir' : 'api/newfile', {method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({path: cwd, name: $('nm').value})});
        closeSheet(); toast(isDir ? 'Folder dibuat' : 'File dibuat'); load(cwd);
      } catch (e) { toast(e.message, true); }
    };
    $('ok').onclick = go;
    $('nm').onkeydown = e => { if (e.key === 'Enter') go(); };
  });
}

// ---------- upload
async function send(files) {
  if (!files || !files.length) return;
  const fd = new FormData();
  fd.append('path', cwd);
  for (const f of files) fd.append('files', f);
  toast('Mengunggah ' + files.length + ' file…');
  try {
    const r = await api('api/upload', {method:'POST', body: fd});
    toast(r.saved.length + ' file terunggah'); load(cwd);
  } catch (e) { toast(e.message, true); }
}

$('picker').onchange = e => { send(e.target.files); e.target.value = ''; };
let dragDepth = 0;
addEventListener('dragenter', e => { e.preventDefault(); if (++dragDepth === 1) $('drop').className = 'drop on'; });
addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; $('drop').className = 'drop'; } });
addEventListener('dragover', e => e.preventDefault());
addEventListener('drop', e => {
  e.preventDefault(); dragDepth = 0; $('drop').className = 'drop';
  send(e.dataTransfer.files);
});

// ---------- toolbar
$('bUp').onclick = () => $('picker').click();
$('bFolder').onclick = () => creator('dir');
$('bFile').onclick = () => creator('file');
$('bZip').onclick = () => location.href = 'api/zip?path=' + encodeURIComponent(cwd);
$('bReload').onclick = () => load(cwd);
$('bCari').onclick = askSearch;
$('bSort').onclick = () => {
  const keys = Object.keys(SORTS);
  sortBy = keys[(keys.indexOf(sortBy) + 1) % keys.length];
  draw();
};
$('bHidden').onclick = () => { showHidden = !showHidden; picked.clear(); draw(); };
$('bAll').onclick = () => {
  const rows = visible();
  if (picked.size === rows.length) picked.clear();
  else rows.forEach(i => picked.add(i.rel));
  draw();
};
$('bOut').onclick = async () => { await fetch('api/logout', {method:'POST'}); location.reload(); };

// ---------- boot
async function boot() {
  cfg = await (await fetch('api/config')).json();
  $('ver').textContent = 'v' + cfg.version;
  $('host').innerHTML = esc(cfg.host) + '<br>' + esc(cfg.root) + (cfg.readonly ? ' · baca saja' : '');
  const pct = cfg.disk.used / cfg.disk.total * 100;
  $('gauge').style.width = pct.toFixed(0) + '%';
  $('disk').textContent = fmtSize(cfg.disk.free) + ' sisa dari ' + fmtSize(cfg.disk.total);
  if (!cfg.locked) $('bOut').style.display = 'none';
  if (cfg.readonly) ['bUp','bFolder','bFile'].forEach(id => $(id).disabled = true);
  if (!cfg.authed) return askLogin();
  load('');
}
boot();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    import uvicorn

    if not ROOT.is_dir():
        raise SystemExit(f"FILEHUB_ROOT bukan folder: {ROOT}")
    print(f"[filehub] v{__version__} root={ROOT}")
    if not PASSWORD:
        print("[filehub] PERINGATAN: FILEHUB_PASSWORD kosong — akses hanya dijaga tailnet.")
    uvicorn.run(
        app,
        host=os.environ.get("FILEHUB_HOST", "127.0.0.1"),
        port=int(os.environ.get("FILEHUB_PORT", "8791")),
        log_level="info",
    )
