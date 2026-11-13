from fastapi import FastAPI

from app.api.routes import router

app = FastAPI(
    title="Password Security Analyzer",
    description=(
        "Evaluates password strength and provides recommendations. "
        "Scores and entropy values are estimates, not guarantees of security."
    ),
    version="0.1.0",
)

app.include_router(router)