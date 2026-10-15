import asyncio
import ipaddress
import logging
import re
from typing import Set, List, Dict, Any, Optional, Callable, Coroutine
from urllib.parse import urlparse, urljoin, urldefrag
from playwright.async_api import async_playwright, Page, Response, Request, Browser, Playwright
from app.config import settings
from app.scanner.rules import get_rules, mask_secret, extract_context_snippet, SecretRule

logger = logging.getLogger("hs_wss.crawler")


class TargetSecurityError(Exception):
    """Raised when target URL violates SSRF or security constraints."""
    pass


def is_ssrf_safe_url(target_url: str) -> bool:
    """
    Validates whether the target URL is safe to crawl.
    Rejects non-HTTP schemes and sensitive cloud metadata IP addresses.
    """
    try:
        parsed = urlparse(target_url)
    except Exception:
        return False

    if parsed.scheme.lower() not in settings.ALLOWED_SCHEMES:
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    # Block AWS/GCP/Azure Cloud Metadata endpoints
    blocked_hosts = {
        "169.254.169.254",
        "metadata.google.internal",
        "100.100.100.200",  # Alibaba cloud metadata
    }
    if hostname.lower() in blocked_hosts:
        return False

    if settings.BLOCK_METADATA_IPS:
        try:
            ip = ipaddress.ip_address(hostname)
            # Block link-local addresses (e.g. 169.254.x.x)
            if ip.is_link_local or ip.is_multicast:
                return False
        except ValueError:
            # Hostname is a domain name, not a raw IP
            pass

    return True


def normalize_url(url: str) -> str:
    """Removes fragments and normalizes URL for deduplication."""
    clean_url, _ = urldefrag(url)
    parsed = urlparse(clean_url)
    # Normalize path
    path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}{('?' + parsed.query) if parsed.query else ''}"


class WebSecretCrawler:
    def __init__(
        self,
        target_url: str,
        max_depth: int = 3,
        max_pages: int = 50,
        auth_enabled: bool = False,
        auth_username: Optional[str] = None,
        auth_password: Optional[str] = None,
        auth_login_url: Optional[str] = None,
        on_progress: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]] = None,
        on_finding: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]] = None
    ):
        if not is_ssrf_safe_url(target_url):
            raise TargetSecurityError(
                f"Target URL '{target_url}' is not allowed due to security / SSRF protection rules."
            )

        self.target_url = target_url
        parsed = urlparse(target_url)
        self.target_domain = parsed.netloc.lower()
        self.base_scheme = parsed.scheme.lower()
        self.max_depth = min(max_depth, settings.MAX_CRAWL_DEPTH)
        self.max_pages = min(max_pages, settings.MAX_CRAWL_PAGES)
        
        # Transient in-memory authentication parameters (never saved to database or disk)
        self.auth_enabled = auth_enabled
        self.auth_username = auth_username
        self.auth_password = auth_password
        self.auth_login_url = auth_login_url
        self.auth_status: Optional[str] = None
        self.auth_message: Optional[str] = None

        self.on_progress = on_progress
        self.on_finding = on_finding

        self.visited_urls: Set[str] = set()
        self.queued_urls: Set[str] = set()
        self.seen_findings_hash: Set[str] = set()
        self.rules: List[SecretRule] = get_rules()
        self.is_cancelled: bool = False
        self.total_pages_scanned: int = 0
        self.total_secrets_found: int = 0

    def cancel(self) -> None:
        """Flags the crawler to abort further navigation and cleanup."""
        self.is_cancelled = True
        logger.info("Crawler cancellation requested.")

    def _is_same_domain(self, url: str) -> bool:
        """Ensures that the URL belongs strictly to the target host to prevent out-of-scope scans."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower() == self.target_domain
        except Exception:
            return False

    def _scan_text_content(self, content: str, source_url: str, source_type: str) -> List[Dict[str, Any]]:
        """Scans arbitrary text or code for secret patterns."""
        if not content:
            return []

        findings = []
        for rule in self.rules:
            for match in rule.pattern.finditer(content):
                secret_val = rule.evaluate(match)
                if not secret_val:
                    continue

                masked_val = mask_secret(secret_val)
                # Deduplication key based on rule, masked value, and source URL
                finding_key = f"{rule.id}:{masked_val}:{source_url}"
                if finding_key in self.seen_findings_hash:
                    continue
                self.seen_findings_hash.add(finding_key)

                snippet = extract_context_snippet(
                    content=content,
                    match_start=match.start(),
                    match_end=match.end(),
                    secret_value=secret_val,
                    masked_value=masked_val
                )

                finding_data = {
                    "url": source_url,
                    "source_type": source_type,
                    "secret_type": rule.name,
                    "masked_value": masked_val,
                    "raw_value": secret_val,
                    "context_snippet": snippet,
                    "severity": rule.severity
                }
                findings.append(finding_data)
                self.total_secrets_found += 1

        return findings

    async def _emit_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Dispatches discovered findings to the callback."""
        for finding in findings:
            if self.on_finding:
                try:
                    await self.on_finding(finding)
                except Exception as e:
                    logger.error(f"Error executing on_finding callback: {e}")

    async def _emit_progress(
        self,
        current_url: str,
        status: str = "scanning",
        auth_status: Optional[str] = None,
        auth_message: Optional[str] = None
    ) -> None:
        """Emits progress event."""
        if self.on_progress:
            try:
                await self.on_progress({
                    "status": status,
                    "current_url": current_url,
                    "pages_scanned": self.total_pages_scanned,
                    "secrets_found": self.total_secrets_found,
                    "queue_size": len(self.queued_urls) - len(self.visited_urls),
                    "auth_status": auth_status if auth_status is not None else self.auth_status,
                    "auth_message": auth_message if auth_message is not None else self.auth_message
                })
            except Exception as e:
                logger.error(f"Error executing on_progress callback: {e}")

    async def _handle_request(self, request: Request) -> None:
        """Intercepts outgoing network requests to inspect headers and body for secrets."""
        try:
            req_url = request.url
            # Inspect headers
            headers = await request.all_headers()
            header_str = "\n".join([f"{k}: {v}" for k, v in headers.items()])
            findings = self._scan_text_content(header_str, req_url, "REQUEST_HEADER")
            if findings:
                await self._emit_findings(findings)

            # Inspect post data if present
            post_data = request.post_data
            if post_data:
                body_findings = self._scan_text_content(post_data, req_url, "REQUEST_BODY")
                if body_findings:
                    await self._emit_findings(body_findings)
        except Exception as e:
            logger.debug(f"Error inspecting request: {e}")

    async def _handle_response(self, response: Response) -> None:
        """Intercepts network responses (XHR, Fetch, Scripts) to inspect payloads for secrets."""
        try:
            res_url = response.url
            content_type = response.headers.get("content-type", "").lower()
            scannable_types = ["text", "json", "javascript", "xml", "html"]

            if any(t in content_type for t in scannable_types):
                try:
                    body_text = await response.text()
                    source_label = "XHR_RESPONSE" if response.request.resource_type in ["xhr", "fetch"] else "SCRIPT"
                    findings = self._scan_text_content(body_text, res_url, source_label)
                    if findings:
                        await self._emit_findings(findings)
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Error inspecting response: {e}")

    async def _perform_login(self, page: Page) -> None:
        """
        Attempts to perform dynamic login on target site using transient credentials.
        CRITICAL: Credentials exist exclusively in memory during this operation
        and are never written to disk, database, or server logs.
        """
        if not self.auth_enabled:
            return

        login_url = self.auth_login_url.strip() if self.auth_login_url else self.target_url
        if not is_ssrf_safe_url(login_url) or not self._is_same_domain(login_url):
            self.auth_status = "failed"
            self.auth_message = "URL de login informada está fora do escopo ou é inválida."
            logger.warning("Auth login URL is not in scope or violates SSRF protection. Skipping auth.")
            await self._emit_progress(login_url, status="autenticando", auth_status=self.auth_status, auth_message=self.auth_message)
            return

        logger.info(f"Attempting automated transient login on {login_url}...")
        await self._emit_progress(login_url, status="autenticando", auth_status="authenticating", auth_message="Tentando realizar login com usuário e senha...")

        try:
            await page.goto(login_url, wait_until="domcontentloaded", timeout=settings.PAGE_TIMEOUT_MS)
            await asyncio.sleep(1.2)

            user_selectors = [
                'input[type="email"]',
                'input[name*="user" i]',
                'input[name*="login" i]',
                'input[name*="email" i]',
                'input[id*="user" i]',
                'input[id*="login" i]',
                'input[id*="email" i]',
                'input[type="text"]'
            ]
            pass_selectors = [
                'input[type="password"]',
                'input[name*="pass" i]',
                'input[id*="pass" i]'
            ]

            user_field = None
            for sel in user_selectors:
                el = await page.query_selector(sel)
                if el and await el.is_visible():
                    user_field = el
                    break

            pass_field = None
            for sel in pass_selectors:
                el = await page.query_selector(sel)
                if el and await el.is_visible():
                    pass_field = el
                    break

            if not user_field or not pass_field:
                self.auth_status = "failed"
                self.auth_message = "Formulário de login não identificado: campos de usuário ou senha não encontrados na página."
                logger.warning(self.auth_message)
                await self._emit_progress(login_url, status="scanning", auth_status=self.auth_status, auth_message=self.auth_message)
                return

            if not self.auth_username or not self.auth_password:
                self.auth_status = "failed"
                self.auth_message = "Usuário ou senha não foram informados para autenticação."
                await self._emit_progress(login_url, status="scanning", auth_status=self.auth_status, auth_message=self.auth_message)
                return

            url_before = page.url
            await user_field.fill(self.auth_username)
            await pass_field.fill(self.auth_password)

            submit_btn = await page.query_selector(
                'button[type="submit"], input[type="submit"], button:has-text("Login"), button:has-text("Entrar"), button:has-text("Sign in"), button:has-text("Log in"), button:has-text("Acessar")'
            )
            if submit_btn and await submit_btn.is_visible():
                await submit_btn.click()
            else:
                await pass_field.press("Enter")

            try:
                await page.wait_for_load_state("networkidle", timeout=6000)
            except Exception:
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=6000)
                except Exception:
                    pass
            await asyncio.sleep(2.0)

            # Verification: detect if login was rejected or failed
            url_after = page.url
            login_failed = False
            fail_reason = ""

            # Check 1: Look for visible error/alert messages on page
            error_selectors = [
                '[role="alert"]', '.alert', '.alert-danger', '.alert-error',
                '.error', '.error-message', '[class*="error" i]',
                '.toast', '.toast-error', '.notification.is-danger',
                '[class*="feedback" i]', '.invalid-feedback'
            ]
            error_keywords = [
                "invalid", "inval", "incorret", "incorrect", "falha", "erro",
                "wrong password", "bad credential", "não confere", "senha incorreta",
                "denied", "negado", "unauthorized", "não encontrado", "not found",
                "credenciais inválidas", "usuário ou senha incorretos"
            ]

            try:
                for sel in error_selectors:
                    alerts = await page.query_selector_all(sel)
                    for a in alerts:
                        if await a.is_visible():
                            txt = (await a.inner_text()).strip()
                            if any(kw in txt.lower() for kw in error_keywords):
                                login_failed = True
                                fail_reason = f"Erro no site: '{txt[:100]}'"
                                break
                    if login_failed:
                        break
            except Exception:
                pass

            # Check 2: Check if password input is STILL visible on screen
            if not login_failed:
                try:
                    pass_elements = await page.query_selector_all('input[type="password"]')
                    still_has_pass = False
                    for p in pass_elements:
                        if await p.is_visible():
                            still_has_pass = True
                            break
                    
                    if still_has_pass:
                        is_login_page = any(x in url_after.lower() for x in ["login", "signin", "auth", "entrar"])
                        if is_login_page or url_after == url_before:
                            login_failed = True
                            fail_reason = "Usuário ou senha recusados pelo site (a página permaneceu na tela de login)."
                except Exception:
                    pass

            if login_failed:
                self.auth_status = "failed"
                self.auth_message = fail_reason or "Falha ao realizar login: usuário ou senha inválidos."
                logger.warning(f"Auth failed: {self.auth_message}")
                await self._emit_progress(url_after, status="scanning", auth_status=self.auth_status, auth_message=self.auth_message)
            else:
                self.auth_status = "success"
                self.auth_message = "Login autenticado com sucesso! Rastreando rotas protegidas."
                logger.info("Auth successful.")
                await self._emit_progress(url_after, status="scanning", auth_status=self.auth_status, auth_message=self.auth_message)

        except Exception as e:
            self.auth_status = "failed"
            self.auth_message = f"Erro durante tentativa de login: {e}"
            logger.warning(self.auth_message)
            await self._emit_progress(login_url, status="scanning", auth_status=self.auth_status, auth_message=self.auth_message)
        finally:
            # Wipe credentials from crawler memory attributes immediately after login attempt
            self.auth_username = None
            self.auth_password = None

    async def run(self) -> Dict[str, Any]:
        """
        Executes dynamic crawl using Playwright headless browser.
        Returns summary dictionary.
        """
        initial_url = normalize_url(self.target_url)
        queue: List[tuple[str, int]] = [(initial_url, 0)]
        self.queued_urls.add(initial_url)

        playwright: Optional[Playwright] = None
        browser: Optional[Browser] = None

        try:
            playwright = await async_playwright().start()
            browser = await playwright.chromium.launch(
                headless=settings.HEADLESS,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ]
            )

            context = await browser.new_context(
                user_agent=settings.USER_AGENT,
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800}
            )

            page = await context.new_page()

            # Attach network interception handlers
            page.on("request", lambda req: asyncio.create_task(self._handle_request(req)))
            page.on("response", lambda res: asyncio.create_task(self._handle_response(res)))

            # If authentication is enabled and credentials are provided, perform login first
            if self.auth_enabled and self.auth_username and self.auth_password:
                await self._perform_login(page)

            while queue and not self.is_cancelled:
                if self.total_pages_scanned >= self.max_pages:
                    logger.info(f"Reached maximum page limit ({self.max_pages}). Stopping crawl.")
                    break

                current_url, depth = queue.pop(0)
                if current_url in self.visited_urls:
                    continue

                self.visited_urls.add(current_url)
                self.total_pages_scanned += 1

                await self._emit_progress(current_url, status="scanning")

                try:
                    # Navigate and wait for DOM readiness
                    response = await page.goto(
                        current_url,
                        wait_until="domcontentloaded",
                        timeout=settings.PAGE_TIMEOUT_MS
                    )

                    # Short grace period for client-side frameworks (React, Vue, SPA) to mount
                    await asyncio.sleep(0.5)

                    # Extract and scan full rendered DOM
                    dom_content = await page.content()
                    dom_findings = self._scan_text_content(dom_content, current_url, "DOM")
                    if dom_findings:
                        await self._emit_findings(dom_findings)

                    # If not at max depth, extract links to queue further exploration
                    if depth < self.max_depth:
                        hrefs = await page.eval_on_selector_all(
                            "a[href]",
                            "elements => elements.map(e => e.getAttribute('href'))"
                        )

                        for href in hrefs:
                            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                                continue
                            absolute_url = urljoin(current_url, href)
                            normalized = normalize_url(absolute_url)

                            # Validate domain and scheme
                            if (
                                self._is_same_domain(normalized)
                                and is_ssrf_safe_url(normalized)
                                and normalized not in self.visited_urls
                                and normalized not in self.queued_urls
                            ):
                                self.queued_urls.add(normalized)
                                queue.append((normalized, depth + 1))

                except Exception as page_err:
                    logger.warning(f"Failed to navigate to {current_url}: {page_err}")

            await context.close()
            await browser.close()
            await playwright.stop()

        except Exception as e:
            logger.error(f"Crawler error: {e}", exc_info=True)
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass
            if playwright:
                try:
                    await playwright.stop()
                except Exception:
                    pass
            raise

        final_status = "cancelled" if self.is_cancelled else "completed"
        await self._emit_progress("", status=final_status)

        return {
            "status": final_status,
            "pages_scanned": self.total_pages_scanned,
            "secrets_found": self.total_secrets_found,
            "visited_urls_count": len(self.visited_urls),
            "auth_status": self.auth_status,
            "auth_message": self.auth_message
        }
