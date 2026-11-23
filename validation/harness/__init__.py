"""Event Zero validation harness (phase 1).

Infrastructure for the 100,000-case validation programme: canonical
JSONL manifests, an independent scorer, a deterministic runner, and
the pilot builder. The scorer module deliberately imports nothing
from event_zero: it judges the engine from the outside, from sealed
expectations and exhibited results only.
"""
