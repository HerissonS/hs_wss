import csv
import io
import json
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Scan, Finding
from app.scanner.rules import get_rules
from app.scanner.engine import ScanManager
from app.api.schemas import (
    ScanCreateRequest,
    ScanSummaryResponse,
    ScanDetailResponse,
    FindingResponse,
    RuleResponse,
    ActiveScanStatus,
)

logger = logging.getLogger("hs_wss.api")
router = APIRouter(prefix="/api", tags=["Scanner API"])


@router.post("/scans", response_model=ScanSummaryResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(request: ScanCreateRequest):
    """
    Initiates a new secret discovery scan against a target URL.
    """
    manager = ScanManager.get_instance()
    try:
        scan = await manager.start_scan(
            target_url=request.target_url,
            max_depth=request.max_depth,
            max_pages=request.max_pages,
            auth_enabled=request.auth_enabled,
            auth_username=request.auth_username,
            auth_password=request.auth_password,
            auth_login_url=request.auth_login_url
        )
        return scan
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ve))
    except Exception as e:
        logger.error(f"Failed to initiate scan: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to initiate scan: {e}")


@router.get("/scans/active", response_model=ActiveScanStatus)
def get_active_scan(db: Session = Depends(get_db)):
    """
    Returns the status of the currently active scan or the most recently executed scan.
    """
    manager = ScanManager.get_instance()
    active_id = manager.active_scan_id

    if active_id is not None:
        scan = db.query(Scan).filter(Scan.id == active_id).first()
        return ActiveScanStatus(is_active=True, active_scan_id=active_id, scan=scan)

    # Return most recent scan if available
    latest_scan = db.query(Scan).order_by(Scan.id.desc()).first()
    return ActiveScanStatus(is_active=False, active_scan_id=None, scan=latest_scan)


@router.post("/scans/active/stop")
async def stop_active_scan():
    """
    Aborts the currently running scan.
    """
    manager = ScanManager.get_instance()
    stopped = await manager.stop_scan()
    if not stopped:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active scan is currently running.")
    return {"message": "Scan cancellation signal sent successfully."}


@router.post("/scans/{scan_id}/stop")
async def stop_scan_by_id(scan_id: int):
    """
    Aborts a specific scan if it is currently running.
    """
    manager = ScanManager.get_instance()
    stopped = await manager.stop_scan(scan_id)
    if not stopped:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan {scan_id} is not currently running.")
    return {"message": f"Scan {scan_id} cancellation signal sent successfully."}


@router.post("/scans/clear")
def clear_all_scans(db: Session = Depends(get_db)):
    """
    Purges all past scans, findings, and visited URLs.
    """
    manager = ScanManager.get_instance()
    if manager.active_scan_id is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot clear data while a scan is currently active. Please stop the scan first."
        )
    from app.models import VisitedURL
    db.query(Finding).delete()
    db.query(VisitedURL).delete()
    db.query(Scan).delete()
    db.commit()
    return {"message": "All past scans and findings cleared successfully."}


@router.get("/scans", response_model=List[ScanSummaryResponse])
def list_scans(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    """
    Lists past scans with pagination.
    """
    scans = db.query(Scan).order_by(Scan.id.desc()).offset(offset).limit(limit).all()
    return scans


@router.get("/scans/{scan_id}", response_model=ScanDetailResponse)
def get_scan_detail(scan_id: int, db: Session = Depends(get_db)):
    """
    Returns full details and detected secret findings for a specific scan.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")
    return scan


@router.get("/scans/{scan_id}/export")
def export_scan_findings(scan_id: int, format: str = Query("json", regex="^(json|csv)$"), db: Session = Depends(get_db)):
    """
    Exports scan findings as downloadable JSON or CSV.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.id.asc()).all()

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Finding ID", "Scan ID", "URL", "Source Type", "Secret Type", "Masked Value", "Context Snippet", "Severity", "Timestamp"])
        for f in findings:
            writer.writerow([
                f.id,
                f.scan_id,
                f.url,
                f.source_type,
                f.secret_type,
                f.masked_value,
                f.context_snippet or "",
                f.severity,
                f.created_at.isoformat() if f.created_at else ""
            ])
        output.seek(0)
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=hs_wss_findings_scan_{scan_id}.csv"}
        )

    # Default to JSON
    data = [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "url": f.url,
            "source_type": f.source_type,
            "secret_type": f.secret_type,
            "masked_value": f.masked_value,
            "context_snippet": f.context_snippet,
            "severity": f.severity,
            "created_at": f.created_at.isoformat() if f.created_at else None
        }
        for f in findings
    ]
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=hs_wss_findings_scan_{scan_id}.json"}
    )


@router.get("/rules", response_model=List[RuleResponse])
def list_rules():
    """
    Returns active secret detection regex patterns and severities.
    """
    rules = get_rules()
    return [
        RuleResponse(
            id=r.id,
            name=r.name,
            severity=r.severity,
            description=r.description
        )
        for r in rules
    ]


@router.get("/stream")
async def sse_event_stream():
    """
    Server-Sent Events (SSE) stream broadcasting live scanner events and discoveries.
    """
    manager = ScanManager.get_instance()
    queue = manager.subscribe()

    async def event_generator():
        try:
            # Send initial keepalive/handshake
            yield "event: connected\ndata: {\"status\": \"ready\"}\n\n"
            while True:
                msg = await queue.get()
                yield msg
        except asyncio.CancelledError:
            manager.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
