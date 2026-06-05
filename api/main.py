"""
ComplianceOS — Application Entry Point
Run: uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

from dotenv import load_dotenv
load_dotenv()

from contextlib import asynccontextmanager
from fastapi import FastAPI
import logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Démarre le scheduler APScheduler au boot, l'arrête proprement à l'extinction."""
    from scheduler import setup_scheduler, scheduler
    setup_scheduler()
    scheduler.start()
    logger.info("[BOOT] APScheduler started — 4 jobs active")

    yield  # ← l'app tourne ici

    scheduler.shutdown(wait=False)
    logger.info("[SHUTDOWN] APScheduler stopped")


# ── Import de l'app FastAPI depuis routes.py ──
# On remplace le lifespan par défaut avec le nôtre
from routes import app
app.router.lifespan_context = lifespan

# ── Routers ──
from auth import router as auth_router
app.include_router(auth_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
