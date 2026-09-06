"""RingWatch main application — Real-Time Ring -3 Monitor."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from app.api.routes import router

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🔥 RingWatch starting — Real-Time Ring -3 Monitor")
    logger.info("Target: Intel Core Ultra 5 125H (Meteor Lake-P), CSME v18.1.15.2544")
    logger.info("Mode: READ-ONLY — zero writes, zero risk")

    from app.core import timestorm, pmt_sensor
    timestorm.start()
    pmt_sensor.start()
    yield
    logger.info("RingWatch stopping")


app = FastAPI(
    title="RingWatch",
    description="Real-Time Ring -3 (Intel ME) Monitor",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")

# Health check
@app.get("/health")
async def health():
    return {"status": "healthy", "app": "RingWatch", "version": "0.1.0"}

# Serve frontend (if built)
frontend_dist = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
if os.path.isdir(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")