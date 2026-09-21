"""Normalize overlapping integer ranges."""

from __future__ import annotations


def merge_ranges(ranges: tuple[tuple[int, int], ...]) -> tuple[tuple[int, int], ...]:
    ordered = sorted(ranges)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if start > end:
            raise ValueError("range start must not exceed its end")
        if not merged or start > merged[-1][1] + 1:
            merged.append((start, end))
            continue
        merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return tuple(merged)
