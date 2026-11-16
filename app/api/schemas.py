from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.analyzer.patterns import PatternType
from app.analyzer.recommendations import Severity
from app.generator.password_generator import DEFAULT_LENGTH, MAX_LENGTH, MIN_LENGTH

MAX_PASSWORD_LENGTH = 128


# ---------- Requests ----------

class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # reject unknown fields

    # repr=False keeps the password out of logs if the object is ever printed
    password: str = Field(
        min_length=1,
        max_length=MAX_PASSWORD_LENGTH,
        repr=False,
        description="The password to analyze. It is never stored or logged.",
    )


class GenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    length: int = Field(default=DEFAULT_LENGTH, ge=MIN_LENGTH, le=MAX_LENGTH)
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False

    @model_validator(mode="after")
    def require_one_character_type(self) -> "GenerateRequest":
        if not (self.use_lowercase or self.use_uppercase
                or self.use_digits or self.use_symbols):
            raise ValueError("at least one character type must be enabled")
        return self


# ---------- Responses ----------

class EntropyOut(BaseModel):
    bits: float
    pool_size: int
    length: int
    rating: str


class PatternOut(BaseModel):
    type: PatternType
    length: int
    description: str


class RecommendationOut(BaseModel):
    code: str
    severity: Severity
    message: str


class AnalysisReport(BaseModel):
    score: int = Field(description="0-100 strength score (an estimate)")
    rating: str
    effective_entropy_bits: float
    entropy: EntropyOut
    is_common_password: bool
    common_match_type: Literal["exact", "variation"] | None
    patterns: list[PatternOut]
    recommendations: list[RecommendationOut]
    disclaimer: str


class GeneratedPassword(BaseModel):
    password: str
    length: int
    entropy_bits: float
    score: int
    rating: str
    disclaimer: str