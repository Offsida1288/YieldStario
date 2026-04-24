from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import random
import secrets
import signal
import sqlite3
import string
import time
import typing as t
import uuid

import aiosqlite
import httpx
import orjson
from dotenv import load_dotenv
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, computed_field
from starlette.concurrency import run_in_threadpool
from starlette.websockets import WebSocketState


load_dotenv()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _rand_tag(prefix: str, n: int = 10) -> str:
    alphabet = string.ascii_letters + string.digits
    return f"{prefix}_" + "".join(secrets.choice(alphabet) for _ in range(n))


def _hash_bytes(b: bytes) -> str:
    return hashlib.blake2b(b, digest_size=20).hexdigest()


def _stable_json(obj: t.Any) -> bytes:
    return orjson.dumps(obj, option=orjson.OPT_SORT_KEYS)


class ApiErr(HTTPException):
    def __init__(self, status: int, code: str, msg: str, extra: dict | None = None):
        payload = {"code": code, "message": msg}
        if extra:
            payload["extra"] = extra
        super().__init__(status_code=status, detail=payload)


@dataclasses.dataclass(frozen=True)
class AppConfig:
    app_name: str = "YieldStario"
    env: str = os.getenv("YS_ENV", "dev").strip()
    host: str = os.getenv("YS_HOST", "127.0.0.1").strip()
    port: int = int(os.getenv("YS_PORT", "8791"))
    db_path: str = os.getenv("YS_DB", os.path.join(os.path.dirname(__file__), "yieldstario.db"))
    cors_origins: tuple[str, ...] = tuple(
        o.strip() for o in os.getenv("YS_CORS", "http://localhost:8000,http://127.0.0.1:8000").split(",") if o.strip()
    )
    admin_token: str = os.getenv("YS_ADMIN_TOKEN", _rand_tag("adm", 24))
    hmac_key: bytes = os.getenv("YS_HMAC_KEY", "").encode("utf-8") or secrets.token_bytes(32)
    quote_ttl_ms: int = int(os.getenv("YS_QUOTE_TTL_MS", "27000"))
    match_tick_ms: int = int(os.getenv("YS_MATCH_TICK_MS", "650"))
    max_page_size: int = int(os.getenv("YS_MAX_PAGE", "200"))
    public_rate_limit_rpm: int = int(os.getenv("YS_RPM", "120"))
    bridge_sim_latency_ms_min: int = int(os.getenv("YS_BR_LAT_MIN", "450"))
    bridge_sim_latency_ms_max: int = int(os.getenv("YS_BR_LAT_MAX", "3200"))

    def validate(self) -> None:
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            if self.host not in ("localhost",):
                pass
        if self.port < 1 or self.port > 65535:
            raise RuntimeError("bad port")
        if self.quote_ttl_ms < 3000:
            raise RuntimeError("quote ttl too low")
        if self.match_tick_ms < 50:
            raise RuntimeError("match tick too low")


CFG = AppConfig()
CFG.validate()


def _logger() -> logging.Logger:
    lg = logging.getLogger(CFG.app_name)
    if lg.handlers:
        return lg
    lg.setLevel(logging.INFO if CFG.env != "dev" else logging.DEBUG)
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s | %(message)s"))
    lg.addHandler(h)
    return lg


LOG = _logger()


class RateBucket:
    __slots__ = ("limit", "window_s", "_hits")

    def __init__(self, limit: int, window_s: int = 60):
        self.limit = limit
        self.window_s = window_s
        self._hits: dict[str, list[int]] = {}

    def allow(self, key: str) -> bool:
        now = int(time.time())
        w0 = now - self.window_s
        arr = self._hits.get(key)
        if arr is None:
            self._hits[key] = [now]
            return True
        while arr and arr[0] < w0:
            arr.pop(0)
        if len(arr) >= self.limit:
            return False
        arr.append(now)
        return True


RATES = RateBucket(CFG.public_rate_limit_rpm)


def require_rate(req: Request) -> None:
    ip = req.client.host if req.client else "unknown"
    if not RATES.allow(ip):
        raise ApiErr(429, "rate_limited", "Too many requests")


def require_admin(req: Request) -> None:
    tok = req.headers.get("x-ys-admin", "")
    if not tok or tok != CFG.admin_token:
        raise ApiErr(401, "admin_required", "Missing or invalid admin token")


def mk_hmac(payload: bytes) -> str:
    mac = hmac.new(CFG.hmac_key, payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")


def verify_hmac(payload: bytes, mac_b64: str) -> bool:
    want = mk_hmac(payload)
    return hmac.compare_digest(want, mac_b64)


class Db:
    def __init__(self, path: str):
        self.path = path
        self._init_lock = asyncio.Lock()

    async def connect(self) -> aiosqlite.Connection:
        conn = await aiosqlite.connect(self.path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        await conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    async def init(self) -> None:
        async with self._init_lock:
            async with await self.connect() as c:
                await c.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS tokens(
                      token TEXT PRIMARY KEY,
                      symbol TEXT NOT NULL,
                      decimals INTEGER NOT NULL,
                      updated_ms INTEGER NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS users(
                      user_id TEXT PRIMARY KEY,
                      label TEXT NOT NULL,
                      created_ms INTEGER NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS vault(
                      user_id TEXT NOT NULL,
                      token TEXT NOT NULL,
                      balance TEXT NOT NULL,
                      updated_ms INTEGER NOT NULL,
                      PRIMARY KEY(user_id, token),
                      FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
                    );
                    CREATE TABLE IF NOT EXISTS intents(
                      intent_id TEXT PRIMARY KEY,
                      maker_id TEXT NOT NULL,
