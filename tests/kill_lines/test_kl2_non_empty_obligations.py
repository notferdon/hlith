"""KL2: Derivation cannot return empty obligation set; gate never treats empty as landed."""
from __future__ import annotations

import pytest

from hlith.types import ObligationSet


def test_kl2_empty_obligation_set_forbidden() -> None:
    with pytest.raises(ValueError, match="Empty obligation set is forbidden"):
        ObligationSet(())
