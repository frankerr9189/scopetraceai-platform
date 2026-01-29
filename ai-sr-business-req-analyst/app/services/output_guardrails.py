"""
Client-facing output guardrails for the BA Requirements Agent.

Runs after mapping (map_llm_output_to_package) to:
1) Remove UI/orchestration BR leakage (generic filter)
2) Promote trust & reviewability BRs when input signals human-in-the-loop
3) Set metadata.requires_human_review when those themes are present

Domain-agnostic; no kitchen/slab/drawing specifics.
"""
import re
from typing import List, Optional
from app.models.package import RequirementPackage
from app.models.requirement import Requirement, BusinessRequirement, ScopeBoundaries, RequirementMetadata
from app.models.enums import RequirementStatus, TicketType


# --- Guardrail 1: UI/Orchestration leakage filter ---

UI_ORCHESTRATION_TERMS = [
    "user interface", "ui", "screen", "view", "navigation", "button", "click",
    "trigger", "controls", "page", "tab", "dropdown", "modal", "wizard", "toolbar"
]

# Known junk BR patterns (substring match, case-insensitive)
JUNK_BR_PATTERNS = [
    "user interface inputs and triggers for artifact generation",
    "present generated artifacts in organized views with navigation controls",
]


def _is_ui_orchestration_br(statement: str) -> bool:
    """Return True if the BR statement contains UI/presentation/orchestration terms or known junk patterns."""
    lower = statement.lower().strip()
    for pattern in JUNK_BR_PATTERNS:
        if pattern in lower:
            return True
    for term in UI_ORCHESTRATION_TERMS:
        if re.search(r"\b" + re.escape(term) + r"\b", lower):
            return True
    return False


def filter_ui_orchestration_brs(package: RequirementPackage) -> None:
    """
    Remove BRs that contain UI/orchestration terms or known junk patterns.
    Modifies package in place. Prefer removal over rewrite to avoid implementation detail.
    """
    for req in package.requirements:
        if not req.business_requirements:
            continue
        kept = [br for br in req.business_requirements if not _is_ui_orchestration_br(br.statement)]
        req.business_requirements = kept


# --- Guardrail 2 & 3: Trust & reviewability (input-driven) ---

HUMAN_VERIFICATION_THEMES = [
    "human-in-the-loop", "review", "approve", "override", "confidence", "uncertainty",
    "assumptions", "explainable", "deterministic", "no black-box"
]

# Six canonical trust/reviewability BRs (domain-agnostic, "The system shall ...")
TRUST_REVIEWABILITY_BRS = [
    "The system shall communicate confidence or uncertainty per generated output item, or per output where item-level is not applicable.",
    "The system shall flag low-confidence outputs for review.",
    "The system shall support user modification or override of AI-generated outputs before finalization.",
    "The system shall require an explicit approval gate before outputs are finalized or exported, when applicable.",
    "The system shall make assumptions used in derived outputs visible to the user.",
    "The system shall provide traceability or provenance to source inputs where relevant.",
]

# For duplicate detection: keywords that indicate each theme is already covered (any existing BR)
TRUST_THEME_KEYWORDS = [
    ["confidence", "uncertainty", "indicator", "per item", "per output"],
    ["low confidence", "low-confidence", "flag", "flagged", "review"],
    ["override", "modify", "adjust", "correct", "edit", "user"],
    ["approval", "approve", "finaliz", "gate", "before export"],
    ["assumption", "visible", "stated", "clear", "derived"],
    ["traceability", "provenance", "source", "trace"],
]


def _input_has_human_verification_themes(original_input: str) -> bool:
    """Return True if the original input contains any human-verification theme."""
    if not original_input or not isinstance(original_input, str):
        return False
    lower = original_input.lower()
    return any(theme in lower for theme in HUMAN_VERIFICATION_THEMES)


def _existing_brs_cover_theme(package: RequirementPackage, theme_index: int) -> bool:
    """Return True if any BR in the package already covers the given trust theme (by keyword overlap)."""
    keywords = TRUST_THEME_KEYWORDS[theme_index]
    for req in package.requirements:
        for br in req.business_requirements:
            st = br.statement.lower()
            if sum(1 for k in keywords if k in st) >= 1:
                return True
    return False


def _max_br_number(package: RequirementPackage) -> int:
    """Return the highest BR number used in the package (e.g. BR-019 -> 19)."""
    max_n = 0
    for req in package.requirements:
        for br in req.business_requirements:
            m = re.match(r"BR-(\d+)", br.id, re.I)
            if m:
                max_n = max(max_n, int(m.group(1)))
    return max_n


def ensure_trust_reviewability_brs(package: RequirementPackage, original_input: str) -> None:
    """
    If original input signals human verification, add missing trust/reviewability BRs
    (confidence, low-confidence flagging, override, approval gate, visible assumptions, traceability).
    New BRs get IDs BR-020, BR-021, ... and are added to a single "Trust & Reviewability" requirement.
    Modifies package in place.
    """
    if not _input_has_human_verification_themes(original_input):
        return
    to_add: List[tuple] = []  # (statement, theme_index)
    for i, statement in enumerate(TRUST_REVIEWABILITY_BRS):
        if not _existing_brs_cover_theme(package, i):
            to_add.append((statement, i))
    if not to_add:
        return
    next_br = _max_br_number(package) + 1
    new_brs = [
        BusinessRequirement(
            id=f"BR-{next_br + j:03d}",
            statement=stmt,
            inferred=False,
            manual_override=None,
        )
        for j, (stmt, _) in enumerate(to_add)
    ]
    max_req_num = 0
    for req in package.requirements:
        m = re.match(r"REQ-(\d+)", req.id, re.I)
        if m:
            max_req_num = max(max_req_num, int(m.group(1)))
    new_req_id = f"REQ-{max_req_num + 1:03d}"
    trust_req = Requirement(
        id=new_req_id,
        parent_id=None,
        ticket_type=TicketType.STORY,
        summary="Trust & Reviewability",
        description="Human verification, confidence, override, and approval for AI-generated outputs.",
        business_requirements=new_brs,
        scope_boundaries=ScopeBoundaries(in_scope=[], out_of_scope=[]),
        constraints_policies=["N/A"],
        open_questions=["N/A"],
        metadata=RequirementMetadata(
            source_type="brd",
            enhancement_mode=3,
            enhancement_actions=["Output guardrail: trust & reviewability"],
            inferred_content=False,
            ui_orchestration=False,
        ),
        status=RequirementStatus.IN_REVIEW,
        gaps=["N/A"],
        risks=["N/A"],
        original_intent="Trust and reviewability requirements added when input signals human-in-the-loop.",
    )
    package.requirements.append(trust_req)


def set_requires_human_review_metadata(package: RequirementPackage, original_input: str) -> None:
    """If input has human verification themes, set metadata.requires_human_review = True."""
    if not _input_has_human_verification_themes(original_input):
        return
    if package.metadata is None:
        package.metadata = {}
    package.metadata["requires_human_review"] = True


def apply_output_guardrails(package: RequirementPackage, original_input: str) -> None:
    """
    Run all output guardrails in order:
    1) Filter UI/orchestration BRs from every requirement
    2) If input signals human verification, add missing trust/reviewability BRs
    3) If input signals human verification, set metadata.requires_human_review = True
    """
    filter_ui_orchestration_brs(package)
    ensure_trust_reviewability_brs(package, original_input)
    set_requires_human_review_metadata(package, original_input)
