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
