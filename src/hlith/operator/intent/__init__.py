# SPDX-License-Identifier: Apache-2.0
"""Intent preparation: proposed delta claims (propose) and the human review packet (delta_review).

Claims only: nothing here approves, proves or lands. Approval is a human authorization that clears ``deltas-confirmed`` and
nothing else. KNOWN ASSEMBLY DEBT: ``propose`` still reads L2/L3 internals (derive/differential/effect); at assembly it must
move behind their public read APIs (operator views and intent may use public APIs only)."""
