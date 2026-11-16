from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.routes import router

app = FastAPI(
    title="Password Security Analyzer",
    description=(
        "Evaluates password strength and provides recommendations. "
        "Scores and entropy values are estimates, not guarantees of security. "
        "Submitted passwords are never stored or logged."
    ),
    version="0.2.0",
)


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
    """Return validation errors WITHOUT the submitted values.

    FastAPI's default 422 body includes an `input` field echoing the invalid
    value, which could contain the password.
    """
    errors = [
        {"loc": list(err["loc"]), "msg": err["msg"], "type": err["type"]}
        for err in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


app.include_router(router)