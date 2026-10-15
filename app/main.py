import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
import uvicorn

from app.config import settings
from app.database import init_db
from app.scanner.engine import ScanManager
from app.api import api_router

# Configure Logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("hs_wss")

# Directories
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "app" / "templates"
STATIC_DIR = BASE_DIR / "app" / "static"


# Security Headers Middleware (Adheres to DevSecOps standards)
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'self';"
        )
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup Lifecycle
    logger.info("Initializing HS_WSS SQLite Database...")
    init_db(purge=settings.PURGE_ON_STARTUP)
    if settings.PURGE_ON_STARTUP:
        logger.info("PURGE_ON_STARTUP is enabled: Previous execution data was cleared for a fresh session.")
    else:
        logger.info("Database initialized successfully at %s", settings.DB_PATH)
    yield
    # Shutdown Lifecycle
    logger.info("Shutting down HS_WSS engine and active crawlers...")
    manager = ScanManager.get_instance()
    await manager.shutdown()
    logger.info("HS_WSS graceful shutdown complete.")


# Initialize FastAPI Application
app = FastAPI(
    title="HS_WSS - HS Tech Web Secret Scanner",
    description="DevSecOps dynamic secret scanner and ephemeral web panel using Playwright.",
    version="1.0.0",
    lifespan=lifespan
)

# Attach Security Middleware
app.add_middleware(SecurityHeadersMiddleware)

# Mount Static Assets and Templates
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Register API Router
app.include_router(api_router)


@app.get("/", response_class=HTMLResponse, tags=["Web Panel"])
async def render_dashboard(request: Request):
    """
    Renders the minimalist ephemeral web dashboard for the scanner.
    """
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "host": settings.HOST,
            "port": settings.PORT,
            "app_env": settings.APP_ENV
        }
    )


@app.get("/health", tags=["Monitoring"])
async def health_check():
    """
    Health check endpoint for Docker container and process supervisors.
    """
    return JSONResponse(content={"status": "healthy", "service": "hs_wss"})


def print_startup_banner():
    banner = f"""
================================================================================
  _    _  _____ __          __ _____  _____ 
 | |  | |/ ____|\ \        / // ____|/ ____|
 | |__| | (___   \ \  /\  / /| (___ | (___  
 |  __  |\___ \   \ \/  \/ /  \___ \ \___ \ 
 | |  | |____) |   \  /\  /   ____) |____) |
 |_|  |_|_____/     \/  \/   |_____/|_____/ 
                                            
 HS Tech Web Secret Scanner & Dynamic Interceptor
================================================================================
 [*] Modo de Execução: Efêmero atrelado ao terminal (Terminal-bound)
 [*] Binding Host:     {settings.HOST}
 [*] Porta do Painel:  {settings.PORT}
 [*] Persistência:     {settings.DB_PATH}
 [*] Engine:           Playwright Headless + Regex Scanner
--------------------------------------------------------------------------------
 [>>>] Painel Web acessível em: http://{settings.HOST}:{settings.PORT}
       (Na rede local, acesse via: http://<IP-DO-SERVIDOR>:{settings.PORT})
 [!]   Pressione Ctrl+C para encerrar o scanner e desativar o painel web.
================================================================================
"""
    print(banner, flush=True)


if __name__ == "__main__":
    print_startup_banner()
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level="info" if not settings.DEBUG else "debug",
        access_log=True
    )
