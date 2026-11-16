from fastapi import APIRouter

from app.analyzer.recommendations import generate_recommendations
from app.analyzer.strength import ESTIMATE_DISCLAIMER, analyze_strength
from app.api.schemas import (
    AnalysisReport,
    AnalyzeRequest,
    EntropyOut,
    GeneratedPassword,
    GenerateRequest,
    PatternOut,
    RecommendationOut,
)
from app.generator.password_generator import GeneratorOptions, generate_password

router = APIRouter()


@router.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    """Liveness probe: confirms the API is running."""
    return {"status": "ok"}


@router.post("/analyze", response_model=AnalysisReport, tags=["analysis"])
def analyze(payload: AnalyzeRequest) -> AnalysisReport:
    """Analyze a password. The password is processed in memory only."""
    result = analyze_strength(payload.password)
    recommendations = generate_recommendations(payload.password, result)

    return AnalysisReport(
        score=result.score,
        rating=result.rating,
        effective_entropy_bits=result.effective_entropy_bits,
        entropy=EntropyOut(
            bits=result.entropy.bits,
            pool_size=result.entropy.pool_size,
            length=result.entropy.length,
            rating=result.entropy.rating,
        ),
        is_common_password=result.common.is_common,
        common_match_type=result.common.match_type,
        patterns=[
            PatternOut(type=p.pattern_type, length=p.length, description=p.description)
            for p in result.patterns
        ],
        recommendations=[
            RecommendationOut(code=r.code, severity=r.severity, message=r.message)
            for r in recommendations
        ],
        disclaimer=ESTIMATE_DISCLAIMER,
    )


@router.post("/generate", response_model=GeneratedPassword, tags=["generator"])
def generate(payload: GenerateRequest) -> GeneratedPassword:
    """Generate a random password with a cryptographically secure RNG."""
    password = generate_password(GeneratorOptions(**payload.model_dump()))
    result = analyze_strength(password)

    return GeneratedPassword(
        password=password,
        length=len(password),
        entropy_bits=result.entropy.bits,
        score=result.score,
        rating=result.rating,
        disclaimer=ESTIMATE_DISCLAIMER,
    )