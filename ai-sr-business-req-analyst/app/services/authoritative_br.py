"""
Authoritative BR Mode: honor explicit BRs from Jira when present.

When the input (e.g. Jira description) contains a "Business Requirements (Normalized):"
block with BR-\d{1,4}\s*: markers, we extract them in a newline-agnostic way and use them
as authoritative if extraction count matches marker count. Otherwise we fall back to
existing LLM/normalization behavior.
"""
import re
import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)

# BR marker pattern: 1-4 digits (BR-003, BR-026, BR-1234)
BR_MARKER_PATTERN = re.compile(r"BR-(\d{1,4})\s*:", re.IGNORECASE)
STOP_HEADER_PATTERN = re.compile(
    r"\n\s*(Identified Risks|Risk Level|Scope\s*\(\s*In\s*\)|Scope\s*\(\s*Out\s*\)|"
    r"Open Questions|Identified Gaps|Normalized Requirements)\s*:",
    re.IGNORECASE,
)

HEADER = "Business Requirements (Normalized):"


def _count_br_markers(text: str) -> int:
    """Return the number of occurrences of BR-\\d{1,4}\\s*: in text (newline-agnostic)."""
    if not text:
        return 0
    return len(BR_MARKER_PATTERN.findall(text))


def _extract_block_after_header(text: str) -> str:
    """Return the content block after HEADER until the first stop header or end of text."""
    idx = text.lower().find(HEADER.lower())
    if idx == -1:
        return ""
    after = text[idx + len(HEADER) :].lstrip()
    if not after:
        return ""
    stop = STOP_HEADER_PATTERN.search(after)
    if stop:
        after = after[: stop.start()].rstrip()
    return after


def extract_authoritative_brs(text: str) -> Tuple[List[Tuple[str, str]], int, int]:
    """
    Extract explicit BRs from input when present (e.g. Jira description).

    1) Detect BR markers in text using regex BR-\\d{1,4}\\s*: (in block after header).
    2) If marker_count > 0: extract all BR entries newline-agnostic; extracted_count = len.
    3) Validation gate: if extracted_count != marker_count, log BR_PARSE_PARTIAL and
       return ([], marker_count, extracted_count) so caller falls back.
    4) If marker_count == 0: return ([], 0, 0) — no behavioral change.

    Args:
        text: Raw input (e.g. Jira ticket description).

    Returns:
        (extracted_list, marker_count, extracted_count).
        extracted_list is non-empty only when marker_count > 0 and extracted_count == marker_count.
        Each item is (br_id, statement) e.g. ("BR-003", "The system shall ...").
    """
    if not text or not isinstance(text, str):
        return [], 0, 0
    text = text.strip()
    block = _extract_block_after_header(text)
    if not block:
        return [], 0, 0

    marker_count = _count_br_markers(block)
    if marker_count == 0:
        return [], 0, 0

    results: List[Tuple[str, str]] = []
    for match in BR_MARKER_PATTERN.finditer(block):
        br_num = match.group(1)
        start = match.end()
        rest = block[start:]
        next_br = BR_MARKER_PATTERN.search(rest)
        if next_br:
            statement = rest[: next_br.start()].strip()
        else:
            statement = rest.strip()
        if statement:
            results.append((f"BR-{br_num}", statement))

    extracted_count = len(results)
    if extracted_count != marker_count:
        logger.warning(
            "BR_PARSE_PARTIAL marker_count=%s extracted_count=%s (falling back to existing generation)",
            marker_count,
            extracted_count,
        )
        return [], marker_count, extracted_count
    return results, marker_count, extracted_count
