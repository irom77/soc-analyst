"""Validation of the control records `--audit` assesses a case against.

Everything here runs **before** the LLM request. A control set with duplicate or empty
identifiers makes "exactly one response per control" ambiguous, and that ambiguity would
only surface after a paid request had already been spent — so the shape is settled first
and a bad set is rejected offline.

The record shape is provisional. It was designed against the requirements written down in
`examples/user-input-case-audit/README.md` rather than against a real policy export, and
the three decisions most likely to need revisiting are recorded here:

* **Controls are flat.** There are no sub-controls, because nesting is exactly what makes
  "one response per control" ambiguous. A policy with sub-controls flattens them into
  distinct ids (`IR-4.2`, `IR-4.2.a`) when the records are prepared.
* **Identity is `(policy_ref, control_id)`,** not `control_id` alone, so two policies that
  both number a control `4.2` can be supplied in one run. `policy_ref` stays optional and
  the pair degrades to the bare id for the single-policy case.
* **`applies_when` is optional, and a rationale is required for every status.** The field
  gives `not_applicable` a stated basis; requiring the rationale regardless is what stops
  `not_applicable` from becoming the escape hatch for a control the model could not
  evidence.
"""

from collections import Counter
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

# What a knowledge record must say it is to be read as a control. Absent is accepted --
# in `--audit` every supplied record is a control by definition -- but a record that
# names itself something else is rejected rather than silently audited.
CONTROL_RECORD_TYPE = "control"


class Control(BaseModel):
    """One requirement a case is audited against.

    `extra="allow"` so a real policy export can carry its own fields (owner, framework
    mapping, review date) through to the model without this schema having to anticipate
    them. Only the fields below are relied on by the code.
    """

    model_config = ConfigDict(extra="allow")

    control_id: str
    policy_ref: str = ""
    policy_version: str = ""
    title: str = ""
    # The only substantive field that is required: a control with no stated requirement
    # cannot be assessed, and asking the model to infer one from a title invites it to
    # invent the standard it then judges against.
    requirement: str
    applies_when: str = ""
    evidence_expectation: str = ""
    exceptions: list[str] = Field(default_factory=list)

    @property
    def key(self) -> tuple[str, str]:
        """Identity for coverage matching: the policy it came from, plus its own id."""
        return control_key(self.policy_ref, self.control_id)


def control_key(policy_ref: str, control_id: str) -> tuple[str, str]:
    """Identity, normalized the one way both sides use.

    Both `Control.key` and the coverage check route through here so the record side and
    the response side cannot drift into normalizing differently. They did once: only the
    response side stripped, so a control record whose id carried stray whitespace was
    unmatchable by a model that echoed it back verbatim exactly as instructed, and the
    run reported two coverage defects for a correct answer.

    Whitespace only. Case is left alone because control identifiers are frequently
    case-significant, and folding them would merge two distinct controls into one.
    """
    return (policy_ref.strip(), control_id.strip())


def parse_controls(records: list[Any]) -> list[Control]:
    """Every supplied knowledge record as a `Control`, or `ValueError` explaining why not.

    Raises rather than returning problems because there is no useful partial outcome: an
    audit that silently skipped a malformed control would report full coverage of a set
    the operator did not supply.
    """
    if not records:
        raise ValueError(
            "--audit needs a control set. Supply one with --knowledge FILE, as a JSON array "
            "of control records."
        )
    controls: list[Control] = []
    problems: list[str] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            problems.append(f"record {index} is {type(record).__name__}, not an object")
            continue
        declared = str(record.get("record_type", CONTROL_RECORD_TYPE)).strip()
        if declared != CONTROL_RECORD_TYPE:
            problems.append(
                f"{_where(record, index)} has record_type {declared!r}; --audit reads every "
                f"supplied record as a {CONTROL_RECORD_TYPE!r}"
            )
            continue
        try:
            control = Control.model_validate(record)
        except ValidationError as exc:
            # Named by its own id where it has one: an operator fixing a fifty-control
            # file needs to know which control, not which array offset.
            problems.append(f"{_where(record, index)} is not a valid control: {_first_error(exc)}")
            continue
        if not control.control_id.strip():
            problems.append(f"record {index} has an empty control_id")
            continue
        if not control.requirement.strip():
            problems.append(
                f"control {control.control_id!r} has an empty requirement and cannot be assessed"
            )
            continue
        controls.append(control)
    problems.extend(_duplicate_problems(controls))
    if problems:
        raise ValueError(
            "The control set supplied with --knowledge cannot be audited against:\n  - "
            + "\n  - ".join(problems)
        )
    return controls


def _duplicate_problems(controls: list[Control]) -> list[str]:
    """Duplicate identities, which would make one response per control unmatchable."""
    counts = Counter(control.key for control in controls)
    return [
        (
            f"control_id {control_id!r}"
            + (f" in policy_ref {policy_ref!r}" if policy_ref else "")
            + f" appears {count} times; identities must be unique"
        )
        for (policy_ref, control_id), count in sorted(counts.items())
        if count > 1
    ]


def _where(record: dict, index: int) -> str:
    """How to name a bad record: by its control id when it has one, by position otherwise."""
    control_id = str(record.get("control_id", "")).strip()
    return f"control {control_id!r}" if control_id else f"record {index}"


def _first_error(exc: ValidationError) -> str:
    error = exc.errors()[0]
    location = ".".join(str(part) for part in error["loc"]) or "record"
    return f"{location}: {error['msg']}"


def describe(controls: list[Control]) -> str:
    """One line for `--explain`, naming what the run will be audited against."""
    policies = sorted({control.policy_ref for control in controls if control.policy_ref})
    suffix = f" from {', '.join(policies)}" if policies else ""
    return f"{len(controls)} control(s){suffix}"
