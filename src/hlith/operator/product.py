# SPDX-License-Identifier: Apache-2.0
"""Distribution posture for Hlith Review.

REVIEW_ONLY is the shipped product posture: Hlith independently reviews a
supplied change; it does not apply the change to the engineer's original
repository.  Disposable rehearsals remain available.  The original Apply
implementation is preserved in source history but is not offered by this
distribution.
"""
REVIEW_ONLY = True
REVIEW_LABEL = "Hlith Review — independent behavioural review; merge authority remains with the engineer"
