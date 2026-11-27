# SPDX-License-Identifier: Apache-2.0
import os

import pytest


@pytest.fixture(autouse=True)
def _thread_store(tmp_path_factory, monkeypatch):
    """Layer 1 persists its LangGraph thread under the state dir; tests never write the real home."""
    monkeypatch.setenv("HLITH_THREAD_STORE", str(tmp_path_factory.mktemp("threads")))
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path_factory.mktemp("state")))  # the verdict MAC key lives here, outside every store


# case: positives LOST to the inert-import-closure rule (closure_gate rule A). They stay in the suite as strict xfails with their reasons; none is deleted.
# A stricter or narrower rule that recovers them must turn each into an XPASS(strict) failure so the expectation is changed deliberately.
_LOST_POSITIVES = {
    "tests/certificate/test_equiv_cert_domain.py::test_an_in_tree_str_subclass_unchanged_does_not_hurt_identity": "class with a base in an import-closure module is not inert",
    "tests/certificate/test_equiv_cert_domain.py::test_a_module_level_conditional_def_does_not_make_identity_unavailable": "a module-level if runs at import",
    "tests/certificate/test_equiv_cert_domain.py::test_a_module_level_try_import_fallback_is_admitted_when_identical_and_refused_when_edited": "a module-level try runs at import",
    "tests/certificate/test_equiv_nogo_classes.py::test_an_unchanged_odd_header_outside_the_cone_is_not_a_problem": "a non-literal default (g()) runs at import",
    "tests/certificate/test_symeq_soundness_regressions.py::test_frozenset_string_digits_and_split_and_normal_form_are_universal": "a module-level frozenset(...) call is not an allowlisted statement",
    "tests/certificate/test_equiv_cert_integration.py::test_r1_substantial_both_functions_are_held_with_their_rule[is_test_path-R3]": "counterpatch R1: class GitError(...) with a base; R1 NOT claimable",
    "tests/certificate/test_equiv_cert_integration.py::test_r1_substantial_both_functions_are_held_with_their_rule[literal_calls_in_tests-R4]": "counterpatch R1: class GitError(...) with a base; R1 NOT claimable",
}


@pytest.hookimpl(tryfirst=True)  # before `-m` deselection, so `-m "not confinement"` sees the census marker
def pytest_collection_modifyitems(config, items):
    from confinement_census import CONFINEMENT
    from obsolete_census import OBSOLETE, REASONS

    for item in items:
        why = _LOST_POSITIVES.get(item.nodeid)
        if why:
            item.add_marker(pytest.mark.xfail(strict=True, reason="lost positive (closure gate rule A, case): " + why))
        obsolete = OBSOLETE.get(item.nodeid)
        if obsolete:  # explicit per-test census (tests/obsolete_census.py), never a pattern
            item.add_marker(pytest.mark.skip(reason="OBSOLETE in Hlith Review (tests/obsolete_census.py): " + REASONS[obsolete]))
        if item.nodeid.split("::", 1)[0] in CONFINEMENT:
            item.add_marker(pytest.mark.confinement)
            _HOST_GATE["marked"] += 1


# ------------------------------------------------------------------ supported-host gate (review test posture; tests/host_gate.py)
# Tests listed in tests/confinement_census.py reach Hlith's confined execution and carry the `confinement` marker. Nothing is skipped:
# on a host without Landlock ABI >= 6 and unprivileged user namespaces the session stops unless the group is deselected explicitly
# (-m "not real and not confinement": a host-independent run, NOT a full-suite result) or HLITH_TEST_UNSUPPORTED_HOST=run is set.
_HOST_GATE = {"marked": 0, "selected": 0}


def pytest_configure(config):
    config.addinivalue_line("markers", "confinement: reaches Hlith's confined execution (needs Landlock ABI >= 6 and unprivileged user "
                                       "namespaces); listed with its reason in tests/confinement_census.py")


def pytest_collection_finish(session):
    selected = sum(1 for item in session.items if item.get_closest_marker("confinement"))
    _HOST_GATE["selected"] = selected
    if not selected or session.config.option.collectonly:
        return
    from host_gate import host_facts

    facts = host_facts()
    if facts["supported"] or os.environ.get("HLITH_TEST_UNSUPPORTED_HOST") == "run":
        return
    raise pytest.UsageError(
        "hlith supported-host gate: this host cannot run Hlith's confined execution ("
        + "; ".join(facts["reasons"]) + f"). {selected} selected test(s) need it and would fail for that reason alone.\n"
        "  Host-independent run (NOT a full-suite result):  pytest -m \"not real and not confinement\"\n"
        "  Observe the host failures anyway:                HLITH_TEST_UNSUPPORTED_HOST=run pytest")


def pytest_report_header(config):
    from host_gate import host_facts

    facts = host_facts()
    state = "SUPPORTED" if facts["supported"] else "UNSUPPORTED (" + "; ".join(facts["reasons"]) + ")"
    return f"hlith host gate: {state}; landlock {facts['landlock']}; {facts['userns_detail']}"


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    from host_gate import host_facts

    facts = host_facts()
    marked, selected = _HOST_GATE["marked"], _HOST_GATE["selected"]
    line = (f"hlith host gate: host {'SUPPORTED' if facts['supported'] else 'UNSUPPORTED'}; confinement tests collected {marked}, "
            f"selected {selected}, deselected {marked - selected}")
    if marked - selected:
        line += " -> this run is NOT a full-suite result"
    if selected and not facts["supported"]:
        line += " -> confinement failures on this host are host failures, not Hlith results"
    terminalreporter.write_line(line)
