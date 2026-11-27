# SPDX-License-Identifier: Apache-2.0
"""Layer 5 (feedback/): durable local-first feedback store, immutable FeedbackInput projection, probes, and lineage.

Re-exports legacy names from `_legacy` while callers migrate to `hlith.feedback.api.LocalFeedbackService`.
"""

from __future__ import annotations

from .api import LandingProbeContext, LocalFeedbackService  # noqa: F401
from .lineage import FeedbackLineage, build_lineage  # noqa: F401
from .project import project_feedback_input  # noqa: F401
from .store import StoredRecord, append_supersession, load_stored_records, persist_record  # noqa: F401

from ._legacy import (  # noqa: F401
    CHECKER_ID,
    EXT_BUDGET_S,
    EXT_PROBE_FAMILY,
    FEEDBACK_SUBDIR,
    SCHEMA_VERSION,
    DeriveFeedback,
    DifferentialConstraints,
    DirectiveKind,
    FeedbackIntegrityError,
    FeedbackRecord,
    FeedbackWriteRefused,
    Observation,
    Pinned,
    TurnLedger,
    TurnResult,
    Unresolvable,
    _ID_RE,
    _call_input,
    _canon,
    account_slice,
    after_gate,
    boundary_variants,
    constraints_for,
    delta_covers_pin,
    ext_probe_seed,
    eligible_for_f2,
    extended_probe,
    extended_seeds,
    feedback_dir,
    feedback_effect,
    generalisation,
    harvested_call_seeds,
    import_root_of,
    literal_seeds,
    literals_from_tests,
    load_for_derive,
    load_records,
    mark_construct_unresolvable,
    not_derived_construct,
    not_derived_obligations,
    observe,
    oracle_regression,
    persist,
    pin_observed,
    pin_oracle,
    pin_regression_counterexample,
    pool_seeds,
    post_gate_probe,
    probe_obligation,
    receiver_for,
    recurrent_constructs,
    register_probe_bridge,
    report,
    require_differential_domain_constraint,
    run_turn,
    split_symbol,
    stub_seeds,
    tests_referencing,
    tightens,
    unresolvable_for,
    with_provenance,
)
