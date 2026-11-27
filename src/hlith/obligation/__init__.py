# SPDX-License-Identifier: Apache-2.0
"""L3 obligation verification.

One writer for the whole semantic mechanism. Allowed imports: hlith.contract, hlith.hostio, declared effect read APIs.
Public API: `hlith.obligation.api.ObligationEngine` (implements contract.capabilities.ObligationApi).
"""


def probe_bridge() -> dict:
    """The L3 helpers L5's post-landing probe needs, as ONE public export (operator wires it at startup:
    ``feedback.register_probe_bridge(**obligation.probe_bridge())``). Keys are exactly: synthesize_dist_info,
    receiver_recipe, expr_matches, typed_match, delta_expected_matches, from_feedback, norm_call, evaluate_expected_expr,
    inert_from_repr, is_inert, value_matches. Imports are lazy so importing this package stays light."""
    from .. import differential as _d
    from .. import expected_expr as _e

    return {
        "synthesize_dist_info": _d.synthesize_dist_info,
        "receiver_recipe": _d.receiver_recipe,
        "expr_matches": _d.expr_matches,
        "typed_match": _d._typed_match,
        "delta_expected_matches": _d._delta_expected_matches,
        "from_feedback": _d._from_feedback,
        "norm_call": _d._norm_call,
        "evaluate_expected_expr": _e.evaluate_expected_expr,
        "inert_from_repr": _e.inert_from_repr,
        "is_inert": _e.is_inert,
        "value_matches": _e.value_matches,
    }
