import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
from app.database import get_db_context
from app.models import Scan, Finding, VisitedURL
from app.scanner.crawler import WebSecretCrawler, TargetSecurityError

logger = logging.getLogger("hs_wss.engine")


class ScanManager:
    _instance: Optional["ScanManager"] = None

    def __init__(self):
        self.active_scan_id: Optional[int] = None
        self.current_crawler: Optional[WebSecretCrawler] = None
        self.current_task: Optional[asyncio.Task] = None
        self._subscribers: List[asyncio.Queue] = []
        self._lock = asyncio.Lock()

    @classmethod
    def get_instance(cls) -> "ScanManager":
        if cls._instance is None:
            cls._instance = ScanManager()
        return cls._instance

    async def broadcast_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Broadcasts an event message to all connected SSE clients."""
        payload = json.dumps({"event": event_type, "data": data})
        message = f"event: {event_type}\ndata: {payload}\n\n"
        dead_queues = []
        for q in self._subscribers:
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                dead_queues.append(q)
        for dq in dead_queues:
            if dq in self._subscribers:
                self._subscribers.remove(dq)

    def subscribe(self) -> asyncio.Queue:
        """Registers a new SSE listener queue."""
        q = asyncio.Queue(maxsize=100)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Removes an SSE listener queue."""
        if q in self._subscribers:
            self._subscribers.remove(q)

    async def start_scan(
        self,
        target_url: str,
        max_depth: int = 3,
        max_pages: int = 50,
        auth_enabled: bool = False,
        auth_username: Optional[str] = None,
        auth_password: Optional[str] = None,
        auth_login_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Initiates a new scan execution.
        Saves scan record to database and starts background crawler.
        CRITICAL: Auth credentials are used purely in-memory by the crawler
        and are never stored in the database.
        """
        async with self._lock:
            if self.active_scan_id is not None:
                raise ValueError("A scan is currently running. Please stop it or wait for completion.")

            parsed = urlparse(target_url)
            domain = parsed.netloc

            # Insert initial scan in database (credentials are NEVER stored)
            with get_db_context() as db:
                scan = Scan(
                    target_url=target_url,
                    domain=domain,
                    status="running",
                    max_depth=max_depth,
                    max_pages=max_pages,
                    pages_scanned=0,
                    secrets_count=0
                )
                db.add(scan)
                db.flush()
                scan_id = scan.id
                db.refresh(scan)
                scan_summary = {
                    "id": scan.id,
                    "target_url": scan.target_url,
                    "domain": scan.domain,
                    "status": scan.status,
                    "max_depth": scan.max_depth,
                    "max_pages": scan.max_pages,
                    "pages_scanned": scan.pages_scanned,
                    "secrets_count": scan.secrets_count,
                    "started_at": scan.started_at,
                    "completed_at": scan.completed_at,
                    "error_message": scan.error_message,
                    "auth_status": scan.auth_status,
                    "auth_message": scan.auth_message
                }

            self.active_scan_id = scan_id

            # Start crawler background task with transient credentials
            self.current_task = asyncio.create_task(
                self._run_crawler_task(
                    scan_id=scan_id,
                    target_url=target_url,
                    max_depth=max_depth,
                    max_pages=max_pages,
                    auth_enabled=auth_enabled,
                    auth_username=auth_username,
                    auth_password=auth_password,
                    auth_login_url=auth_login_url
                )
            )

            await self.broadcast_event("scan_started", {
                "scan_id": scan_id,
                "target_url": target_url,
                "domain": domain,
                "status": "running"
            })

            return scan_summary

    async def _on_crawler_progress(self, scan_id: int, progress: Dict[str, Any]) -> None:
        """Handles crawler progress updates and synchronizes with database and SSE."""
        auth_status = progress.get("auth_status")
        auth_message = progress.get("auth_message")

        with get_db_context() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.pages_scanned = progress.get("pages_scanned", scan.pages_scanned)
                scan.secrets_count = progress.get("secrets_found", scan.secrets_count)
                if auth_status:
                    scan.auth_status = auth_status
                if auth_message:
                    scan.auth_message = auth_message
                if progress.get("current_url"):
                    visited = VisitedURL(
                        scan_id=scan_id,
                        url=progress["current_url"],
                        depth=0
                    )
                    db.add(visited)

        await self.broadcast_event("scan_progress", {
            "scan_id": scan_id,
            **progress
        })

    async def _on_crawler_finding(self, scan_id: int, finding_data: Dict[str, Any]) -> None:
        """Persists discovered secret finding into the SQLite database and broadcasts to UI."""
        with get_db_context() as db:
            finding = Finding(
                scan_id=scan_id,
                url=finding_data["url"],
                source_type=finding_data["source_type"],
                secret_type=finding_data["secret_type"],
                masked_value=finding_data["masked_value"],
                raw_value=finding_data.get("raw_value"),
                context_snippet=finding_data.get("context_snippet"),
                severity=finding_data.get("severity", "HIGH")
            )
            db.add(finding)
            db.flush()
            finding_id = finding.id

            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.secrets_count += 1

        finding_payload = {
            "id": finding_id,
            "scan_id": scan_id,
            **finding_data
        }
        await self.broadcast_event("secret_found", finding_payload)

    async def _run_crawler_task(
        self,
        scan_id: int,
        target_url: str,
        max_depth: int,
        max_pages: int,
        auth_enabled: bool = False,
        auth_username: Optional[str] = None,
        auth_password: Optional[str] = None,
        auth_login_url: Optional[str] = None
    ) -> None:
        """Background coroutine executing the crawler lifecycle."""
        error_msg: Optional[str] = None
        try:
            self.current_crawler = WebSecretCrawler(
                target_url=target_url,
                max_depth=max_depth,
                max_pages=max_pages,
                auth_enabled=auth_enabled,
                auth_username=auth_username,
                auth_password=auth_password,
                auth_login_url=auth_login_url,
                on_progress=lambda p: self._on_crawler_progress(scan_id, p),
                on_finding=lambda f: self._on_crawler_finding(scan_id, f)
            )

            result = await self.current_crawler.run()
            status = result["status"]
        except TargetSecurityError as tse:
            logger.warning(f"Target security validation error: {tse}")
            status = "failed"
            error_msg = str(tse)
        except Exception as e:
            logger.error(f"Scan task execution failed: {e}", exc_info=True)
            status = "failed"
            error_msg = str(e)
        finally:
            crawler_auth_status = getattr(self.current_crawler, "auth_status", None)
            crawler_auth_message = getattr(self.current_crawler, "auth_message", None)
            with get_db_context() as db:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = status
                    scan.completed_at = datetime.now(timezone.utc)
                    if error_msg:
                        scan.error_message = error_msg
                    if crawler_auth_status:
                        scan.auth_status = crawler_auth_status
                    if crawler_auth_message:
                        scan.auth_message = crawler_auth_message

            await self.broadcast_event("scan_finished", {
                "scan_id": scan_id,
                "status": status,
                "error": error_msg,
                "auth_status": crawler_auth_status,
                "auth_message": crawler_auth_message
            })

            async with self._lock:
                self.active_scan_id = None
                self.current_crawler = None
                self.current_task = None

    async def stop_scan(self, scan_id: Optional[int] = None) -> bool:
        """Cancels the active scan."""
        async with self._lock:
            if self.current_crawler and (scan_id is None or self.active_scan_id == scan_id):
                self.current_crawler.cancel()
                logger.info(f"Scan {self.active_scan_id} marked as cancelled.")
                return True
            return False

    async def shutdown(self) -> None:
        """Gracefully shuts down running scan during application exit."""
        if self.current_crawler:
            self.current_crawler.cancel()
        if self.current_task and not self.current_task.done():
            try:
                await asyncio.wait_for(self.current_task, timeout=5.0)
            except Exception:
                pass
