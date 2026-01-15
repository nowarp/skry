"""
Feature detection runner.

Orchestrates all feature detectors and collects project-level facts.
"""

from typing import List, Set, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import ProjectContext

from features.base import FeatureDetector
from features.version import VersionDetector
from features.category import CategoryDetector
from features.pause import PauseDetector
from core.facts import Fact
from core.utils import debug


# Mapping of feature name -> fact names it produces
# Used to filter cached facts when only specific features are required
FEATURE_FACT_NAMES: Dict[str, Set[str]] = {
    "version": {"FeatureVersion", "IsVersion", "HasVersionCheck", "IsVersionCheckMethod"},
    "category": {"FeatureCategory", "ProjectCategory"},
    "pause": {"FeaturePause", "IsGlobalPauseField", "ChecksPause", "IsPauseControl"},
}


class FeatureRunner:
    """Orchestrates all feature detectors."""

    def __init__(self):
        """Initialize with all available feature detectors."""
        self.detectors: List[FeatureDetector] = [
            VersionDetector(),
            CategoryDetector(),
            PauseDetector(),
        ]

    def detect_required(self, ctx: "ProjectContext", required_features: set) -> List[Fact]:
        """
        Run only the required feature detectors.

        Args:
            ctx: Project context
            required_features: Set of feature names to detect (e.g., {"version", "category"})

        Returns:
            List of facts from required detectors only
        """
        if not required_features:
            debug("No features required, skipping all detectors")
            return []

        all_facts: List[Fact] = []

        for detector in self.detectors:
            if detector.name not in required_features:
                debug(f"Skipping feature detector: {detector.name} (not required)")
                continue

            debug(f"Running feature detector: {detector.name}")
            try:
                facts = detector.detect(ctx)
                all_facts.extend(facts)
                debug(f"  -> {len(facts)} facts generated")
            except Exception as e:
                from core.utils import error

                error(f"Feature detector '{detector.name}' failed: {e}")
                raise

        return all_facts
