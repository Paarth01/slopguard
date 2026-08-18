"""FastAPI service: POST /scan against an uploaded zip, or scan a server-local path."""

from __future__ import annotations

import asyncio
import tempfile
import zipfile
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from slopguard.github_fetch import InvalidRepoUrl, RepoFetchError, fetch_repo_zip
from slopguard.input_parser import parse_exclude_arg
from slopguard.models import ScanResult
from slopguard.scanner import run_scan

app = FastAPI(
    title="SlopGuard",
    description="Security scanner for AI-generated code: hallucinated dependencies, "
    "unsafe patterns, and intent drift.",
    version="0.1.0",
)

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_TEMPLATE_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


def _extract_zip_bytes(zip_bytes: bytes, extract_dir: Path) -> None:
    """Blocking file I/O, run off the event loop via asyncio.to_thread."""
    zip_path = extract_dir.parent / "upload.zip"
    with open(zip_path, "wb") as f:
        f.write(zip_bytes)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(extract_dir)


async def _scan_zip_bytes(zip_bytes: bytes, exclude_arg: str, result_target: str) -> ScanResult:
    """Shared logic: extract a zip's bytes into a temp dir, run the scan, return the result."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        await asyncio.to_thread(_extract_zip_bytes, zip_bytes, extract_dir)

        result = run_scan(str(extract_dir), exclude=parse_exclude_arg(exclude_arg))
        result.target = result_target
        return result


@app.post("/scan", response_model=ScanResult)
async def scan_upload(
    file: Annotated[UploadFile, File()],
    exclude: Annotated[str, Form()] = "",
) -> ScanResult:
    """
    Accepts a .zip of a codebase, scans it, returns the aggregated result.

    exclude: optional comma-separated paths to exclude, same syntax as the
    CLI's --exclude flag (e.g. "tests,dist/*").
    """
    zip_bytes = await file.read()
    try:
        return await _scan_zip_bytes(zip_bytes, exclude, file.filename or "uploaded-archive")
    except zipfile.BadZipFile:
        return JSONResponse(status_code=400, content={"error": "not a valid zip file"})


class RepoScanRequest(BaseModel):
    repo_url: str
    exclude: str = ""


@app.post("/scan-repo", response_model=ScanResult)
async def scan_repo(body: RepoScanRequest) -> ScanResult:
    """
    Accepts a public GitHub repo URL (e.g. https://github.com/owner/repo,
    optionally .../tree/branch), fetches it as a zip server-side, scans
    it, and returns the aggregated result -- same response shape as
    /scan, so the frontend can render both identically.

    Only github.com URLs are accepted; see slopguard/github_fetch.py for
    the SSRF-safety reasoning (this endpoint is public, so a naive
    "fetch whatever URL the user gives us" implementation would let
    anyone use this server to probe internal network addresses).
    """
    try:
        zip_bytes = await asyncio.to_thread(fetch_repo_zip, body.repo_url)
    except InvalidRepoUrl as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except RepoFetchError as e:
        return JSONResponse(status_code=502, content={"error": str(e)})

    try:
        return await _scan_zip_bytes(zip_bytes, body.exclude, body.repo_url)
    except zipfile.BadZipFile:
        return JSONResponse(
            status_code=502, content={"error": "GitHub returned an unreadable archive"}
        )
