from fastapi import APIRouter

router = APIRouter()


@router.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    """Liveness probe: confirms the API is running."""
    return {"status": "ok"}