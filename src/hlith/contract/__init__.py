# SPDX-License-Identifier: Apache-2.0
"""L0 contract boundary.

The sole owner of every shared serialized type, enum, identity and capability signature. It imports only the
standard library (and, until migration step M1, `legacy` re-exports hlith.types). It contains types and pure
helpers only: no I/O, no Git, no subprocess, no sandbox, no engine behaviour.
"""

CONTRACT_VERSION = 2  # v2.3 adds VerifiedEffect.required_scope/scope_discharge (gate refuses without them); v2.2 adds scope_limits and the 'cache' host namespace; v2.1: EffectAccount add-only fields (modified_constants, impacted_tests, added_reached_from, deleted_surviving_sites)
