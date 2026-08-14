"""FastAPI service: POST /scan against an uploaded zip, or scan a server-local path."""

from __future__ import annotations

import shutil
import tempfile
import zipfile
from pathlib import Path

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


@app.post("/scan", response_model=ScanResult)
async def scan_upload(file: UploadFile = File(...)) -> ScanResult:
    """Accepts a .zip of a codebase, scans it, returns the aggregated result."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        zip_path = tmp_path / "upload.zip"
        with open(zip_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        try:
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(extract_dir)
        except zipfile.BadZipFile:
            return JSONResponse(status_code=400, content={"error": "not a valid zip file"})

        result = run_scan(str(extract_dir))
        # normalize the target name so it doesn't leak the temp path
        result.target = file.filename or "uploaded-archive"
        return result
