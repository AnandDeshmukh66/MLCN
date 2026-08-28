"""Feature vector model for Module 4 of the MLCN pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Mapping

from feature_engineering.schema import FEATURE_COUNT, FEATURE_ORDER, INTEGER_FEATURES


@dataclass(frozen=True)
class FeatureVector:
    """
    ML-ready numerical representation of a completed Module 3 ``Flow``.

    ``values`` is always length 24 and ordered exactly as ``FEATURE_ORDER``.
    Integer-schema features are stored as floats for a homogeneous ML vector
    but retain whole-number magnitudes.
    """

    values: tuple[float, ...]

    def __post_init__(self) -> None:
        if len(self.values) != FEATURE_COUNT:
            raise ValueError(
                f"FeatureVector requires exactly {FEATURE_COUNT} values, "
                f"got {len(self.values)}"
            )

    @property
    def names(self) -> tuple[str, ...]:
        return FEATURE_ORDER

    @property
    def feature_count(self) -> int:
        return FEATURE_COUNT

    def as_list(self) -> list[float]:
        """Return a mutable copy of the feature values in schema order."""
        return list(self.values)

    def as_tuple(self) -> tuple[float, ...]:
        return self.values

    def as_dict(self) -> dict[str, float]:
        """Map canonical feature names to values."""
        return dict(zip(FEATURE_ORDER, self.values))

    def get(self, name: str) -> float:
        """Return the value for a canonical feature name."""
        try:
            index = FEATURE_ORDER.index(name)
        except ValueError as exc:
            raise KeyError(f"Unknown feature name: {name!r}") from exc
        return self.values[index]

    def items(self) -> Iterator[tuple[str, float]]:
        yield from zip(FEATURE_ORDER, self.values)

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, float | int]) -> FeatureVector:
        """Build a vector from a name→value mapping (missing keys → 0.0)."""
        values: list[float] = []
        for name in FEATURE_ORDER:
            raw = mapping.get(name, 0.0)
            values.append(float(raw))
        return cls(values=tuple(values))

    @classmethod
    def zeros(cls) -> FeatureVector:
        """Return an all-zero feature vector (empty / unusable flow)."""
        return cls(values=tuple(0.0 for _ in range(FEATURE_COUNT)))

    def __len__(self) -> int:
        return FEATURE_COUNT

    def __iter__(self) -> Iterator[float]:
        return iter(self.values)

    def __getitem__(self, index: int) -> float:
        return self.values[index]

    def __repr__(self) -> str:
        preview = ", ".join(
            f"{name}={self.values[i]:.4g}"
            for i, name in enumerate(FEATURE_ORDER[:3])
        )
        return f"FeatureVector({preview}, ...; n={FEATURE_COUNT})"


def coerce_feature_value(name: str, value: float | int) -> float:
    """Normalize a computed feature to a finite float suitable for ML."""
    if name in INTEGER_FEATURES:
        return float(int(value))
    return float(value)
