"""
Feature detection module for project-level semantic analysis.

Features are high-level patterns detected using both structural heuristics
and LLM reasoning.
"""

from features.runner import FeatureRunner
from features.base import FeatureDetector, FeatureContext

__all__ = ["FeatureRunner", "FeatureDetector", "FeatureContext"]
