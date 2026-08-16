"""FastAPI service: POST /scan against an uploaded zip, or scan a server-local path."""

from __future__ import annotations

import asyncio
import tempfile
import zipfile
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse

from slopguard.models import ScanResult
from slopguard.scanner import run_scan

app = FastAPI(
    title="SlopGuard",
    description="Security scanner for AI-generated code: hallucinated dependencies, "
    "unsafe patterns, and intent drift.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


def _extract_upload(zip_bytes: bytes, extract_dir: Path) -> None:
    """Blocking file I/O, run off the event loop via asyncio.to_thread."""
    zip_path = extract_dir.parent / "upload.zip"
    with open(zip_path, "wb") as f:
        f.write(zip_bytes)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(extract_dir)


@app.post("/scan", response_model=ScanResult)
async def scan_upload(file: Annotated[UploadFile, File()]) -> ScanResult:
    """Accepts a .zip of a codebase, scans it, returns the aggregated result."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        zip_bytes = await file.read()
        try:
            await asyncio.to_thread(_extract_upload, zip_bytes, extract_dir)
        except zipfile.BadZipFile:
            return JSONResponse(status_code=400, content={"error": "not a valid zip file"})

        result = run_scan(str(extract_dir))
        # normalize the target name so it doesn't leak the temp path
        result.target = file.filename or "uploaded-archive"
        return result
