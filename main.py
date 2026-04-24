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
                      maker_addr TEXT NOT NULL,
                      input_token TEXT NOT NULL,
                      input_amount TEXT NOT NULL,
                      output_token TEXT NOT NULL,
                      min_output_amount TEXT NOT NULL,
                      dst_chain_id INTEGER NOT NULL,
                      dst_receiver TEXT NOT NULL,
                      expiry_ms INTEGER NOT NULL,
                      nonce INTEGER NOT NULL,
                      strategy_tag TEXT NOT NULL,
                      max_fee_bps INTEGER NOT NULL,
                      created_ms INTEGER NOT NULL,
                      cancel_earliest_ms INTEGER NOT NULL,
                      status TEXT NOT NULL,
                      filled_input TEXT NOT NULL,
                      risk_code INTEGER NOT NULL,
                      risk_at_ms INTEGER NOT NULL,
                      UNIQUE(maker_id, nonce)
                    );
                    CREATE TABLE IF NOT EXISTS fills(
                      fill_id TEXT PRIMARY KEY,
                      intent_id TEXT NOT NULL,
                      filler_id TEXT NOT NULL,
                      filler_addr TEXT NOT NULL,
                      route_tag TEXT NOT NULL,
                      pay_token TEXT NOT NULL,
                      pay_amount TEXT NOT NULL,
                      receive_token TEXT NOT NULL,
                      receive_amount TEXT NOT NULL,
                      src_chain_id INTEGER NOT NULL,
                      dst_chain_id INTEGER NOT NULL,
                      fill_deadline_ms INTEGER NOT NULL,
                      created_ms INTEGER NOT NULL,
                      fee_paid TEXT NOT NULL,
                      status TEXT NOT NULL,
                      FOREIGN KEY(intent_id) REFERENCES intents(intent_id) ON DELETE CASCADE
                    );
                    CREATE TABLE IF NOT EXISTS routes(
                      route_tag TEXT PRIMARY KEY,
                      dst_chain_id INTEGER NOT NULL,
                      enabled INTEGER NOT NULL,
                      risk_tier INTEGER NOT NULL,
                      latency_hint_sec INTEGER NOT NULL,
                      curator TEXT NOT NULL,
                      score_bps INTEGER NOT NULL,
                      updated_ms INTEGER NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS audit(
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      at_ms INTEGER NOT NULL,
                      kind TEXT NOT NULL,
                      payload_json TEXT NOT NULL
                    );
                    """
                )
                await c.commit()

    async def audit(self, kind: str, payload: dict) -> None:
        async with await self.connect() as c:
            await c.execute(
                "INSERT INTO audit(at_ms, kind, payload_json) VALUES(?,?,?)",
                (_now_ms(), kind, json.dumps(payload, separators=(",", ":"), sort_keys=True)),
            )
            await c.commit()


DB = Db(CFG.db_path)


def _as_int(x: str) -> int:
    return int(x, 10)


def _as_str_int(x: int) -> str:
    if x < 0:
        raise ValueError("negative")
    return str(x)


class TokenIn(BaseModel):
    token: str = Field(..., min_length=3, max_length=64)
    symbol: str = Field(..., min_length=1, max_length=16)
    decimals: int = Field(..., ge=0, le=36)


class TokenOut(TokenIn):
    updated_ms: int


class UserIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=64)


class UserOut(BaseModel):
    user_id: str
    label: str
    created_ms: int


class VaultDelta(BaseModel):
    token: str
    amount: int = Field(..., ge=1)


class VaultRow(BaseModel):
    user_id: str
    token: str
    balance: int
    updated_ms: int


class IntentIn(BaseModel):
    maker_id: str
    maker_addr: str = Field(..., min_length=6, max_length=128)
    input_token: str
    input_amount: int = Field(..., ge=1)
    output_token: str
    min_output_amount: int = Field(..., ge=1)
    dst_chain_id: int = Field(..., ge=1)
    dst_receiver: str = Field(..., min_length=6, max_length=128)
    expiry_ms: int = Field(..., ge=1)
    nonce: int = Field(..., ge=0)
    strategy_tag: str = Field(..., min_length=3, max_length=96)
    max_fee_bps: int = Field(..., ge=0, le=77)

    @computed_field  # type: ignore[misc]
    @property
    def intent_id(self) -> str:
        payload = _stable_json(
            {
                "maker_addr": self.maker_addr,
                "input_token": self.input_token,
                "input_amount": self.input_amount,
                "output_token": self.output_token,
                "min_output_amount": self.min_output_amount,
                "dst_chain_id": self.dst_chain_id,
                "dst_receiver": self.dst_receiver,
                "expiry_ms": self.expiry_ms,
                "nonce": self.nonce,
                "strategy_tag": self.strategy_tag,
                "max_fee_bps": self.max_fee_bps,
            }
        )
        return "it_" + _hash_bytes(payload)


class IntentOut(BaseModel):
    intent_id: str
    maker_id: str
    maker_addr: str
    input_token: str
    input_amount: int
    output_token: str
    min_output_amount: int
    dst_chain_id: int
    dst_receiver: str
    expiry_ms: int
    nonce: int
    strategy_tag: str
    max_fee_bps: int
    created_ms: int
    cancel_earliest_ms: int
    status: str
    filled_input: int
    risk_code: int
    risk_at_ms: int


class FillIn(BaseModel):
    intent_id: str
    filler_id: str
    filler_addr: str = Field(..., min_length=6, max_length=128)
    route_tag: str = Field(..., min_length=3, max_length=128)
    pay_token: str
    pay_amount: int = Field(..., ge=1)
    receive_token: str
    receive_amount: int = Field(..., ge=1)
    src_chain_id: int = Field(..., ge=1)
    dst_chain_id: int = Field(..., ge=1)
    fill_deadline_ms: int = Field(..., ge=1)

    @computed_field  # type: ignore[misc]
    @property
    def fill_id(self) -> str:
        payload = _stable_json(
            {
                "intent_id": self.intent_id,
                "filler_addr": self.filler_addr,
                "route_tag": self.route_tag,
                "pay_token": self.pay_token,
                "pay_amount": self.pay_amount,
                "receive_token": self.receive_token,
                "receive_amount": self.receive_amount,
                "src_chain_id": self.src_chain_id,
                "dst_chain_id": self.dst_chain_id,
                "fill_deadline_ms": self.fill_deadline_ms,
            }
        )
        return "fl_" + _hash_bytes(payload)


class FillOut(BaseModel):
    fill_id: str
    intent_id: str
    filler_id: str
    filler_addr: str
    route_tag: str
    pay_token: str
    pay_amount: int
    receive_token: str
    receive_amount: int
    src_chain_id: int
    dst_chain_id: int
    fill_deadline_ms: int
    created_ms: int
    fee_paid: int
    status: str


class RouteIn(BaseModel):
    route_tag: str = Field(..., min_length=3, max_length=128)
    dst_chain_id: int = Field(..., ge=1)
    enabled: bool = True
    risk_tier: int = Field(..., ge=0, le=65535)
    latency_hint_sec: int = Field(..., ge=0, le=24 * 3600)
    curator: str = Field(..., min_length=3, max_length=128)
    score_bps: int = Field(..., ge=0, le=10000)


class RouteOut(RouteIn):
    updated_ms: int


class QuoteRequest(BaseModel):
    intent_id: str
    route_tag: str
    filler_id: str
    pay_amount: int = Field(..., ge=1)
    receive_amount: int = Field(..., ge=1)


class QuoteResponse(BaseModel):
    quote_id: str
    intent_id: str
    route_tag: str
    filler_id: str
    pay_amount: int
    receive_amount: int
    score_bps: int
    expires_ms: int
    mac: str


class WsEnvelope(BaseModel):
    kind: str
    at_ms: int
    payload: dict


class WsHub:
    def __init__(self):
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def add(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.add(ws)

    async def remove(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, kind: str, payload: dict) -> None:
        env = WsEnvelope(kind=kind, at_ms=_now_ms(), payload=payload)
        data = orjson.dumps(env.model_dump(), option=orjson.OPT_NON_STR_KEYS)
        dead: list[WebSocket] = []
        async with self._lock:
            for ws in list(self._clients):
                if ws.application_state != WebSocketState.CONNECTED:
                    dead.append(ws)
                    continue
                try:
                    await ws.send_bytes(data)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self._clients.discard(ws)


HUB = WsHub()


class BridgeSim:
    def __init__(self):
        self._rng = random.Random(secrets.randbits(64))

    async def submit(self, intent_id: str, dst_chain_id: int, receiver: str, route_tag: str) -> dict:
        delay = self._rng.randint(CFG.bridge_sim_latency_ms_min, CFG.bridge_sim_latency_ms_max)
        await asyncio.sleep(delay / 1000.0)
        msg = {
            "bridge_msg_id": "br_" + uuid.uuid4().hex,
            "intent_id": intent_id,
            "dst_chain_id": dst_chain_id,
            "receiver": receiver,
            "route_tag": route_tag,
            "latency_ms": delay,
            "observed_at": _utc_iso(),
        }
        return msg


BRIDGE = BridgeSim()


def _calc_fee(receive_amount: int, max_fee_bps: int, protocol_fee_bps: int = 19) -> tuple[int, int]:
    bps = min(max_fee_bps, protocol_fee_bps)
    fee = (receive_amount * bps) // 10_000
    fee = min(fee, receive_amount)
    net = receive_amount - fee
    return fee, net


def _quote_score(route_score_bps: int, pay_amount: int, receive_amount: int) -> int:
    if receive_amount <= 0:
        return 0
    px_bps = min(20_000, (pay_amount * 10_000) // receive_amount)
    if route_score_bps <= 0:
        route_score_bps = 5001
    return (route_score_bps * 7 + px_bps * 3) // 10


async def _ensure_user(user_id: str) -> None:
    async with await DB.connect() as c:
        cur = await c.execute("SELECT 1 FROM users WHERE user_id=?", (user_id,))
        row = await cur.fetchone()
        if row:
            return
        raise ApiErr(404, "user_missing", f"Unknown user_id {user_id}")


async def _get_intent(intent_id: str) -> aiosqlite.Row:
    async with await DB.connect() as c:
        cur = await c.execute("SELECT * FROM intents WHERE intent_id=?", (intent_id,))
        row = await cur.fetchone()
        if not row:
            raise ApiErr(404, "intent_missing", "Intent not found", {"intent_id": intent_id})
        return row


async def _get_route(route_tag: str) -> aiosqlite.Row | None:
    async with await DB.connect() as c:
        cur = await c.execute("SELECT * FROM routes WHERE route_tag=?", (route_tag,))
        return await cur.fetchone()


async def _vault_get(user_id: str, token: str) -> int:
    async with await DB.connect() as c:
        cur = await c.execute("SELECT balance FROM vault WHERE user_id=? AND token=?", (user_id, token))
        row = await cur.fetchone()
        if not row:
            return 0
        return _as_int(row["balance"])


async def _vault_set(user_id: str, token: str, new_balance: int) -> None:
    async with await DB.connect() as c:
        await c.execute(
            "INSERT INTO vault(user_id, token, balance, updated_ms) VALUES(?,?,?,?) "
            "ON CONFLICT(user_id, token) DO UPDATE SET balance=excluded.balance, updated_ms=excluded.updated_ms",
            (user_id, token, _as_str_int(new_balance), _now_ms()),
        )
        await c.commit()


async def _vault_add(user_id: str, token: str, delta: int) -> int:
    bal = await _vault_get(user_id, token)
    nb = bal + delta
    if nb < 0:
        raise ApiErr(400, "vault_low", "Insufficient vault balance", {"token": token, "need": -delta, "have": bal})
    await _vault_set(user_id, token, nb)
    return nb


def _page_params(limit: int, offset: int) -> tuple[int, int]:
    if limit <= 0:
        limit = 50
    limit = min(limit, CFG.max_page_size)
    if offset < 0:
        offset = 0
    return limit, offset


async def _intent_row_to_out(r: aiosqlite.Row) -> IntentOut:
    return IntentOut(
        intent_id=r["intent_id"],
        maker_id=r["maker_id"],
        maker_addr=r["maker_addr"],
        input_token=r["input_token"],
        input_amount=_as_int(r["input_amount"]),
        output_token=r["output_token"],
        min_output_amount=_as_int(r["min_output_amount"]),
        dst_chain_id=int(r["dst_chain_id"]),
        dst_receiver=r["dst_receiver"],
        expiry_ms=int(r["expiry_ms"]),
        nonce=int(r["nonce"]),
        strategy_tag=r["strategy_tag"],
        max_fee_bps=int(r["max_fee_bps"]),
        created_ms=int(r["created_ms"]),
        cancel_earliest_ms=int(r["cancel_earliest_ms"]),
        status=r["status"],
        filled_input=_as_int(r["filled_input"]),
        risk_code=int(r["risk_code"]),
        risk_at_ms=int(r["risk_at_ms"]),
    )


async def _fill_row_to_out(r: aiosqlite.Row) -> FillOut:
    return FillOut(
        fill_id=r["fill_id"],
        intent_id=r["intent_id"],
        filler_id=r["filler_id"],
        filler_addr=r["filler_addr"],
        route_tag=r["route_tag"],
        pay_token=r["pay_token"],
        pay_amount=_as_int(r["pay_amount"]),
        receive_token=r["receive_token"],
        receive_amount=_as_int(r["receive_amount"]),
        src_chain_id=int(r["src_chain_id"]),
        dst_chain_id=int(r["dst_chain_id"]),
        fill_deadline_ms=int(r["fill_deadline_ms"]),
        created_ms=int(r["created_ms"]),
        fee_paid=_as_int(r["fee_paid"]),
        status=r["status"],
    )


async def _route_row_to_out(r: aiosqlite.Row) -> RouteOut:
    return RouteOut(
        route_tag=r["route_tag"],
        dst_chain_id=int(r["dst_chain_id"]),
        enabled=bool(int(r["enabled"])),
        risk_tier=int(r["risk_tier"]),
        latency_hint_sec=int(r["latency_hint_sec"]),
        curator=r["curator"],
        score_bps=int(r["score_bps"]),
        updated_ms=int(r["updated_ms"]),
    )


class MatchEngine:
    def __init__(self):
        self._lock = asyncio.Lock()
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        async with self._lock:
            if self._running:
                return
            self._running = True
            self._task = asyncio.create_task(self._loop(), name="ys-match-loop")

    async def stop(self) -> None:
        async with self._lock:
            self._running = False
            if self._task:
                self._task.cancel()
                self._task = None

    async def _loop(self) -> None:
        LOG.info("match loop started tick_ms=%s", CFG.match_tick_ms)
        while self._running:
            try:
                await self._tick()
            except asyncio.CancelledError:
                break
            except Exception as e:
                LOG.exception("match tick error: %s", e)
            await asyncio.sleep(CFG.match_tick_ms / 1000.0)
        LOG.info("match loop stopped")

    async def _tick(self) -> None:
        now = _now_ms()
        async with await DB.connect() as c:
            # expire intents
            await c.execute(
                "UPDATE intents SET status='expired' WHERE status='open' AND expiry_ms < ?",
                (now,),
            )
            # detect intents ready for fill (open & not risky)
            cur = await c.execute(
                "SELECT intent_id FROM intents WHERE status='open' AND risk_code=0 ORDER BY created_ms ASC LIMIT 70"
            )
            ids = [r["intent_id"] for r in await cur.fetchall()]
            await c.commit()
        for intent_id in ids:
            await self._auto_fill_one(intent_id)

    async def _auto_fill_one(self, intent_id: str) -> None:
        r = await _get_intent(intent_id)
        if r["status"] != "open":
            return
        maker_id = r["maker_id"]
        input_token = r["input_token"]
        input_amount = _as_int(r["input_amount"])
        filled = _as_int(r["filled_input"])
        remain = max(0, input_amount - filled)
        if remain <= 0:
            return

        # simplistic synthetic filler selection: pick a route with best score for dst chain
        dst_chain_id = int(r["dst_chain_id"])
        output_token = r["output_token"]
        min_out = _as_int(r["min_output_amount"])
        max_fee_bps = int(r["max_fee_bps"])

        async with await DB.connect() as c:
            cur = await c.execute(
                "SELECT * FROM routes WHERE enabled=1 AND dst_chain_id=? ORDER BY score_bps DESC, updated_ms DESC LIMIT 8",
                (dst_chain_id,),
            )
            routes = await cur.fetchall()
        if not routes:
            return

        route = routes[0]
        route_tag = route["route_tag"]
        route_score = int(route["score_bps"])

        # create synthetic fill price as some improvement over minimum
        pay_amount = max(min_out, (min_out * (10_000 + random.randint(0, 240))) // 10_000)
        receive_amount = min(remain, max(1, remain - (remain * random.randint(0, 22) // 10_000)))
        fee, net = _calc_fee(receive_amount, max_fee_bps)
        if net <= 0:
            return

        # synthetic filler identity
        filler_id = "bot_" + _hash_bytes(secrets.token_bytes(12))
        filler_addr = "0x" + secrets.token_hex(20)
        fill_deadline = _now_ms() + 25_000
        fill_in = FillIn(
            intent_id=intent_id,
            filler_id=filler_id,
            filler_addr=filler_addr,
            route_tag=route_tag,
            pay_token=output_token,
            pay_amount=pay_amount,
            receive_token=input_token,
            receive_amount=receive_amount,
            src_chain_id=1,
            dst_chain_id=dst_chain_id,
            fill_deadline_ms=fill_deadline,
        )

        score = _quote_score(route_score, pay_amount, receive_amount)
        if score < 5100:
            return

        try:
            await apply_fill(fill_in, protocol_fee_bps=19)
        except HTTPException:
            return
        await HUB.broadcast("fill_auto", {"intent_id": intent_id, "fill_id": fill_in.fill_id, "route_tag": route_tag})


ENGINE = MatchEngine()


async def apply_fill(fill: FillIn, protocol_fee_bps: int) -> FillOut:
    now = _now_ms()
    if fill.fill_deadline_ms < now:
        raise ApiErr(400, "fill_expired", "Fill deadline passed")

    r = await _get_intent(fill.intent_id)
    if r["status"] != "open":
        raise ApiErr(409, "intent_not_open", "Intent not open", {"status": r["status"]})
    if int(r["risk_code"]) != 0:
        raise ApiErr(409, "intent_risky", "Intent is risk-flagged", {"risk_code": int(r["risk_code"])})

    # route checks
    rt = await _get_route(fill.route_tag)
    if rt is not None:
        if not bool(int(rt["enabled"])):
            raise ApiErr(409, "route_disabled", "Route disabled")
        if int(rt["dst_chain_id"]) != int(r["dst_chain_id"]):
            raise ApiErr(400, "route_mismatch", "Route dst chain mismatch")
        if int(rt["risk_tier"]) > 900:
            raise ApiErr(409, "route_risky", "Route risk tier too high", {"risk_tier": int(rt["risk_tier"])})

    if fill.pay_token != r["output_token"] or fill.receive_token != r["input_token"]:
        raise ApiErr(400, "token_mismatch", "Fill tokens do not match intent")
    if fill.dst_chain_id != int(r["dst_chain_id"]):
        raise ApiErr(400, "chain_mismatch", "Fill dst chain does not match intent")

    min_out = _as_int(r["min_output_amount"])
    if fill.pay_amount < min_out:
        raise ApiErr(400, "pay_too_low", "Pay amount below min_output_amount")

    input_amount = _as_int(r["input_amount"])
    filled = _as_int(r["filled_input"])
    remain = max(0, input_amount - filled)
    if fill.receive_amount > remain:
        raise ApiErr(400, "overfill", "Receive amount exceeds remaining input", {"remain": remain})

    # vault checks and movements
    maker_id = r["maker_id"]
    fee_paid, net = _calc_fee(fill.receive_amount, int(r["max_fee_bps"]), protocol_fee_bps=protocol_fee_bps)
    if net <= 0:
        raise ApiErr(400, "fee_too_high", "Net amount after fee is zero")

    await _vault_add(maker_id, fill.receive_token, -fill.receive_amount)
    await _vault_add(maker_id, fill.pay_token, +fill.pay_amount)

    # persist fill + update intent
    async with await DB.connect() as c:
        await c.execute(
            "INSERT INTO fills(fill_id,intent_id,filler_id,filler_addr,route_tag,pay_token,pay_amount,receive_token,receive_amount,src_chain_id,dst_chain_id,fill_deadline_ms,created_ms,fee_paid,status) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                fill.fill_id,
                fill.intent_id,
                fill.filler_id,
                fill.filler_addr,
                fill.route_tag,
                fill.pay_token,
                _as_str_int(fill.pay_amount),
                fill.receive_token,
                _as_str_int(fill.receive_amount),
                int(fill.src_chain_id),
                int(fill.dst_chain_id),
                int(fill.fill_deadline_ms),
                now,
                _as_str_int(fee_paid),
                "settled",
            ),
        )
        nb_filled = filled + fill.receive_amount
        new_status = "filled" if nb_filled >= input_amount else "open"
        await c.execute(
            "UPDATE intents SET filled_input=?, status=? WHERE intent_id=?",
            (_as_str_int(nb_filled), new_status, fill.intent_id),
        )
        await c.commit()

    await DB.audit(
        "fill_settled",
        {"fill_id": fill.fill_id, "intent_id": fill.intent_id, "fee_paid": fee_paid, "net": net, "at_ms": now},
    )

    out = FillOut(
        fill_id=fill.fill_id,
        intent_id=fill.intent_id,
        filler_id=fill.filler_id,
        filler_addr=fill.filler_addr,
        route_tag=fill.route_tag,
        pay_token=fill.pay_token,
        pay_amount=fill.pay_amount,
        receive_token=fill.receive_token,
        receive_amount=fill.receive_amount,
        src_chain_id=fill.src_chain_id,
        dst_chain_id=fill.dst_chain_id,
        fill_deadline_ms=fill.fill_deadline_ms,
        created_ms=now,
        fee_paid=fee_paid,
        status="settled",
    )
    return out


app = FastAPI(title=CFG.app_name, version="1.2.0", docs_url="/docs", redoc_url="/redoc")
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(CFG.cors_origins) if CFG.cors_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _startup() -> None:
    await DB.init()
    await ENGINE.start()
    LOG.info("startup ok db=%s cors=%s", CFG.db_path, CFG.cors_origins)


@app.on_event("shutdown")
async def _shutdown() -> None:
    await ENGINE.stop()
    LOG.info("shutdown ok")


@app.middleware("http")
async def _rate(req: Request, call_next):
    if req.url.path.startswith("/admin/"):
        pass
    else:
        require_rate(req)
    return await call_next(req)


@app.get("/health")
async def health():
    return {"ok": True, "at": _utc_iso(), "env": CFG.env, "app": CFG.app_name}


@app.get("/meta")
async def meta():
    return {
        "app": CFG.app_name,
        "env": CFG.env,
        "quote_ttl_ms": CFG.quote_ttl_ms,
        "match_tick_ms": CFG.match_tick_ms,
        "max_page_size": CFG.max_page_size,
        "server_time_ms": _now_ms(),
    }


@app.post("/admin/token", dependencies=[Depends(require_admin)])
async def upsert_token(tok: TokenIn):
    async with await DB.connect() as c:
        await c.execute(
            "INSERT INTO tokens(token,symbol,decimals,updated_ms) VALUES(?,?,?,?) "
            "ON CONFLICT(token) DO UPDATE SET symbol=excluded.symbol, decimals=excluded.decimals, updated_ms=excluded.updated_ms",
            (tok.token, tok.symbol, int(tok.decimals), _now_ms()),
        )
        await c.commit()
    await DB.audit("token_upsert", tok.model_dump())
    await HUB.broadcast("token_upsert", tok.model_dump())
    return {"ok": True}


@app.get("/tokens", response_model=list[TokenOut])
async def list_tokens(limit: int = 50, offset: int = 0):
    limit, offset = _page_params(limit, offset)
    async with await DB.connect() as c:
        cur = await c.execute("SELECT * FROM tokens ORDER BY token ASC LIMIT ? OFFSET ?", (limit, offset))
        rows = await cur.fetchall()
    return [TokenOut(token=r["token"], symbol=r["symbol"], decimals=int(r["decimals"]), updated_ms=int(r["updated_ms"])) for r in rows]


@app.post("/admin/user", dependencies=[Depends(require_admin)], response_model=UserOut)
async def create_user(inp: UserIn):
    user_id = "u_" + uuid.uuid4().hex
    row = UserOut(user_id=user_id, label=inp.label, created_ms=_now_ms())
    async with await DB.connect() as c:
        await c.execute("INSERT INTO users(user_id,label,created_ms) VALUES(?,?,?)", (row.user_id, row.label, row.created_ms))
        await c.commit()
    await DB.audit("user_create", row.model_dump())
    await HUB.broadcast("user_create", row.model_dump())
    return row


@app.get("/users", response_model=list[UserOut])
async def list_users(limit: int = 50, offset: int = 0):
    limit, offset = _page_params(limit, offset)
    async with await DB.connect() as c:
        cur = await c.execute("SELECT * FROM users ORDER BY created_ms DESC LIMIT ? OFFSET ?", (limit, offset))
        rows = await cur.fetchall()
    return [UserOut(user_id=r["user_id"], label=r["label"], created_ms=int(r["created_ms"])) for r in rows]


@app.post("/vault/deposit", response_model=VaultRow)
async def vault_deposit(d: VaultDelta, user_id: str):
    await _ensure_user(user_id)
    nb = await _vault_add(user_id, d.token, +d.amount)
    out = VaultRow(user_id=user_id, token=d.token, balance=nb, updated_ms=_now_ms())
    await DB.audit("vault_deposit", out.model_dump())
    await HUB.broadcast("vault_deposit", out.model_dump())
    return out


@app.post("/vault/withdraw", response_model=VaultRow)
async def vault_withdraw(d: VaultDelta, user_id: str):
    await _ensure_user(user_id)
    nb = await _vault_add(user_id, d.token, -d.amount)
    out = VaultRow(user_id=user_id, token=d.token, balance=nb, updated_ms=_now_ms())
    await DB.audit("vault_withdraw", out.model_dump())
    await HUB.broadcast("vault_withdraw", out.model_dump())
    return out


@app.get("/vault", response_model=list[VaultRow])
async def vault_list(user_id: str):
    await _ensure_user(user_id)
    async with await DB.connect() as c:
        cur = await c.execute("SELECT * FROM vault WHERE user_id=? ORDER BY token ASC", (user_id,))
        rows = await cur.fetchall()
    return [VaultRow(user_id=r["user_id"], token=r["token"], balance=_as_int(r["balance"]), updated_ms=int(r["updated_ms"])) for r in rows]


@app.post("/intent", response_model=IntentOut)
async def post_intent(inp: IntentIn):
    await _ensure_user(inp.maker_id)
    now = _now_ms()
    if inp.expiry_ms <= now:
        raise ApiErr(400, "expired", "expiry_ms must be in the future")
    if inp.expiry_ms - now > 9 * 24 * 3600 * 1000:
        raise ApiErr(400, "too_long", "expiry too far in the future")
    if inp.input_amount <= 0 or inp.min_output_amount <= 0:
        raise ApiErr(400, "bad_amount", "amounts must be positive")
    bal = await _vault_get(inp.maker_id, inp.input_token)
    if bal < inp.input_amount:
        raise ApiErr(400, "vault_low", "Insufficient maker vault balance", {"need": inp.input_amount, "have": bal})

    created = now
    cancel_earliest = now + (8 * 60 * 1000)
    row = {
        "intent_id": inp.intent_id,
        "maker_id": inp.maker_id,
        "maker_addr": inp.maker_addr,
        "input_token": inp.input_token,
        "input_amount": _as_str_int(inp.input_amount),
        "output_token": inp.output_token,
        "min_output_amount": _as_str_int(inp.min_output_amount),
        "dst_chain_id": int(inp.dst_chain_id),
        "dst_receiver": inp.dst_receiver,
        "expiry_ms": int(inp.expiry_ms),
        "nonce": int(inp.nonce),
        "strategy_tag": inp.strategy_tag,
        "max_fee_bps": int(inp.max_fee_bps),
        "created_ms": created,
        "cancel_earliest_ms": cancel_earliest,
        "status": "open",
        "filled_input": "0",
        "risk_code": 0,
        "risk_at_ms": 0,
    }
    async with await DB.connect() as c:
        try:
            await c.execute(
                "INSERT INTO intents(intent_id,maker_id,maker_addr,input_token,input_amount,output_token,min_output_amount,dst_chain_id,dst_receiver,expiry_ms,nonce,strategy_tag,max_fee_bps,created_ms,cancel_earliest_ms,status,filled_input,risk_code,risk_at_ms) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    row["intent_id"],
                    row["maker_id"],
                    row["maker_addr"],
                    row["input_token"],
                    row["input_amount"],
                    row["output_token"],
                    row["min_output_amount"],
                    row["dst_chain_id"],
                    row["dst_receiver"],
                    row["expiry_ms"],
                    row["nonce"],
                    row["strategy_tag"],
                    row["max_fee_bps"],
                    row["created_ms"],
