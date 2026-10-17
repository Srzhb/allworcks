"""Educational, offline SIEM correlation for synthetic normalized events."""

from .analyzer import AnalysisConfig, Event, EventError, analyze, load_events

__all__ = ["AnalysisConfig", "Event", "EventError", "analyze", "load_events"]
