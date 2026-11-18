import os

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.rate_limit import RateLimiter
from app.api.routes import router

MAX_BODY_BYTES = 4096          # a 128-char password is far below this
RATE_LIMIT_REQUESTS = 30       # per client, per window
RATE_LIMIT_WINDOW = 60.0       # seconds
_RATE_LIMITED_PATHS = {"/analyze", "/generate"}

rate_limiter = RateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW)

app = FastAPI(
    title="Password Security Analyzer",
    description=(
        "Evaluates password strength and provides recommendations. "
        "Scores and entropy values are estimates, not guarantees of security. "
        "Submitted passwords are never stored or logged."
    ),
    version="1.0.0",
)

# --- Middleware -------------------------------------------------------------
# Order matters: the LAST middleware defined is the OUTERMOST. A request passes
# security headers -> rate limit -> size limit -> route, so even 429 and 413
# responses get the security headers.


@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """Reject oversized bodies early, before parsing them."""
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            too_big = int(content_length) > MAX_BODY_BYTES
        except ValueError:
            too_big = True  # malformed header: reject
        if too_big:
            return JSONResponse(
                status_code=413, content={"detail": "Request body too large"}
            )
    return await call_next(request)


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    """Limit how often a client can call the analysis and generator endpoints."""
    if request.method == "POST" and request.url.path in _RATE_LIMITED_PATHS:
        client = request.client.host if request.client else "unknown"
        if not rate_limiter.allow(client):
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please slow down."},
                headers={"Retry-After": str(int(RATE_LIMIT_WINDOW))},
            )
    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Prevent caching of responses and add basic hardening headers."""
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.exception_handler(RequestValidationError)
async def sanitized_validation_error(request: Request, exc: RequestValidationError):
    """Return validation errors WITHOUT the submitted values."""
    errors = [
        {"loc": list(err["loc"]), "msg": err["msg"], "type": err["type"]}
        for err in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


app.include_router(router)

# --- CORS (opt-in) ----------------------------------------------------------
# With no configuration, no CORS headers are sent, so browsers block calls from
# other websites. To allow a frontend:  PSA_ALLOWED_ORIGINS=https://my-site.com
_origins = [
    o.strip() for o in os.getenv("PSA_ALLOWED_ORIGINS", "").split(",") if o.strip()
]
if _origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,          # explicit list, never "*"
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )