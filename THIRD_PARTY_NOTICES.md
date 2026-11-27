# Third-Party Notices

Hlith itself is original software licensed under the **Apache License 2.0** (see [LICENSE](LICENSE)).
The package ships the Hlith namespace, two JSON schemas, and the companion `hlith-agent-hook` shell script.

Hlith's default Review distribution (`pyproject.toml` `[project.dependencies]`) installs a lean verification runtime
(**14 packages** in `uv.lock`: 6 direct dependencies and 8 transitive dependencies; **12 install on Linux Python 3.13.9**,
while `colorama` is Windows-only and `pyyaml` is selected only when `python_full_version != '3.13.*'`, with `pyyaml-ft`
selected on Python 3.13).

The Layer 1 LangGraph agent-execution stack is declared as an optional extra (`[project.optional-dependencies].agent`,
installed via `uv sync --frozen --extra agent` or `pip install "hlith[agent]"`). Across the default distribution and the
optional `agent` extra combined, `uv.lock` resolves **54 third-party Python packages** from PyPI (6 default direct + 8
default transitive + 3 optional `agent` direct + 37 optional `agent`-only transitive; **52 install on Linux Python 3.13.9**
when `--extra agent` is selected, while `colorama` is Windows-only and `httpx2-jsfetch` is Emscripten-only). All 54
packages are unmodified external dependencies installed from PyPI via `uv sync --frozen`.

## Mozilla Public License 2.0 (MPL-2.0) Notices

In the **default Review distribution**, **1** external dependency carries the weak, file-level copyleft **MPL-2.0** license:

1. **hypothesis `6.170.15`** — direct dependency declared in `pyproject.toml` (`MPL-2.0`).
   Upstream source: https://github.com/HypothesisWorks/hypothesis

When the **optional `[agent]` extra** is installed (`uv sync --frozen --extra agent`), **2** additional transitive
dependencies carry **MPL-2.0**:

2. **certifi `2026.10.23`** — transitive dependency of optional `[agent]` via `httpcore`, `httpx`, and `requests` (`MPL-2.0`).
   Upstream source: https://github.com/certifi/python-certifi
3. **orjson `3.13.0`** — transitive dependency of optional `[agent]` via `langgraph-sdk` and `langsmith` (`MPL-2.0 AND (Apache-2.0 OR MIT)`).
   Upstream source: https://github.com/ijl/orjson

Under **MPL-2.0 Section 3.3 (Distribution of a Larger Work)**, combining Hlith's own Apache-2.0 source
with unmodified external MPL-2.0 packages does not impose MPL-2.0 terms on Hlith's source code. Hlith's
source repository, wheel (`hlith-*.whl`), and sdist (`hlith-*.tar.gz`) do not bundle, copy, or modify
any MPL-2.0 files. If you redistribute a standalone bundle or container containing third-party wheels,
preserve all applicable licenses and notices and tell recipients how to obtain the corresponding MPL-covered source for the exact versions shipped. LibCST also carries PSF and Apache-2.0 file-level terms. Review native components and runtime licenses separately for bundles.

## Default Review Distribution Inventory (14 locked packages; 12 installed on Linux Python 3.13.9)

| Package | Version | Scope | License (SPDX) | Upstream |
|---|---|---|---|---|
| `colorama` | `0.4.6` | win32 only (via pytest) | `BSD-3-Clause` | https://github.com/tartley/colorama |
| `hypothesis` | `6.170.15` | direct | `MPL-2.0` | https://github.com/HypothesisWorks/hypothesis |
| `iniconfig` | `2.3.1` | transitive (pytest) | `MIT` | https://github.com/pytest-dev/iniconfig |
| `libcst` | `1.9.0` | direct | `MIT AND PSF-2.0 AND Apache-2.0` | https://github.com/Instagram/LibCST |
| `packaging` | `26.3` | transitive (pytest) | `Apache-2.0 OR BSD-2-Clause` | https://github.com/pypa/packaging |
| `pluggy` | `1.7.0` | transitive (pytest) | `MIT` | https://github.com/pytest-dev/pluggy |
| `pygments` | `2.21.0` | transitive (pytest) | `BSD-2-Clause` | https://pygments.org |
| `pytest` | `9.2.0` | direct | `MIT` | https://docs.pytest.org/en/latest/ |
| `pyyaml` | `6.0.3` | transitive (libcst, `python != 3.13.*`) | `MIT` | https://pyyaml.org/ |
| `pyyaml-ft` | `8.0.0` | transitive (libcst, `python == 3.13.*`) | `MIT` | https://github.com/Quansight-Labs/pyyaml-ft/ |
| `sortedcontainers` | `2.4.0` | transitive (hypothesis) | `Apache-2.0` | http://www.grantjenks.com/docs/sortedcontainers/ |
| `tree-sitter` | `0.25.2` | direct | `MIT` | https://tree-sitter.github.io/tree-sitter/ |
| `tree-sitter-python` | `0.25.0` | direct | `MIT` | https://github.com/tree-sitter/tree-sitter-python |
| `z3-solver` | `5.3.2.0` | direct | `MIT` | https://github.com/Z3Prover/z3 |

## Optional `[agent]` Extra Inventory (40 additional locked packages; not installed by default)

Installing with `--extra agent` / `hlith[agent]` adds the 40 packages below (39 installed on Linux Python 3.13.9, plus `pyyaml` promoted to unconditional via `langchain-core`, for 52 total Linux third-party packages; `httpx2-jsfetch` is Emscripten-only).

| Package | Version | Scope | License (SPDX) | Upstream |
|---|---|---|---|---|
| `aiosqlite` | `0.22.1` | optional `[agent]` transitive | `MIT` | https://github.com/omnilib/aiosqlite |
| `annotated-types` | `0.8.0` | optional `[agent]` transitive | `MIT` | https://github.com/annotated-types/annotated-types |
| `anyio` | `4.15.1` | optional `[agent]` transitive | `MIT` | https://github.com/agronholm/anyio |
| `certifi` | `2026.10.23` | optional `[agent]` transitive | `MPL-2.0` | https://github.com/certifi/python-certifi |
| `charset-normalizer` | `3.5.2` | optional `[agent]` transitive | `MIT` | https://github.com/jawah/charset_normalizer |
| `distro` | `1.9.0` | optional `[agent]` transitive | `Apache-2.0` | https://github.com/python-distro/distro |
| `h11` | `0.16.0` | optional `[agent]` transitive | `MIT` | https://github.com/python-hyper/h11 |
| `httpcore` | `1.0.9` | optional `[agent]` transitive | `BSD-3-Clause` | https://www.encode.io/httpcore/ |
| `httpcore2` | `2.16.0` | optional `[agent]` transitive | `BSD-3-Clause` | https://github.com/pydantic/httpx2 |
| `httpx` | `0.28.1` | optional `[agent]` transitive | `BSD-3-Clause` | https://github.com/encode/httpx |
| `httpx2` | `2.16.0` | optional `[agent]` transitive | `BSD-3-Clause` | https://github.com/pydantic/httpx2 |
| `httpx2-jsfetch` | `1.0` | optional `[agent]` emscripten only (via httpx2) | `BSD-3-Clause` | https://github.com/pydantic/httpx2 |
| `idna` | `3.20` | optional `[agent]` transitive | `BSD-3-Clause` | https://github.com/kjd/idna |
| `jsonpatch` | `1.38` | optional `[agent]` transitive | `BSD-3-Clause` | https://github.com/stefankoegl/python-json-patch |
| `jsonpointer` | `3.6` | optional `[agent]` transitive | `BSD-3-Clause` | https://github.com/stefankoegl/python-json-pointer |
| `langchain-core` | `1.7.1` | optional `[agent]` transitive | `MIT` | https://docs.langchain.com/ |
| `langchain-protocol` | `0.0.20` | optional `[agent]` transitive | `MIT` | https://github.com/langchain-ai/agent-protocol/tree/main/streaming |
| `langgraph` | `1.2.18` | optional `[agent]` direct | `MIT` | https://docs.langchain.com/oss/python/langgraph/overview |
| `langgraph-checkpoint` | `4.3.1` | optional `[agent]` direct | `MIT` | https://github.com/langchain-ai/langgraph/tree/main/libs/checkpoint |
| `langgraph-checkpoint-sqlite` | `3.1.2` | optional `[agent]` direct | `MIT` | https://github.com/langchain-ai/langgraph/tree/main/libs/checkpoint-sqlite |
| `langgraph-prebuilt` | `1.1.1` | optional `[agent]` transitive | `MIT` | https://github.com/langchain-ai/langgraph/tree/main/libs/prebuilt |
| `langgraph-sdk` | `0.4.10` | optional `[agent]` transitive | `MIT` | https://github.com/langchain-ai/langgraph/tree/main/libs/sdk-py |
| `langsmith` | `0.14.14` | optional `[agent]` transitive | `MIT` | https://github.com/langchain-ai/langsmith-python |
| `orjson` | `3.13.0` | optional `[agent]` transitive | `MPL-2.0 AND (Apache-2.0 OR MIT)` | https://github.com/ijl/orjson |
| `ormsgpack` | `1.13.0` | optional `[agent]` transitive | `Apache-2.0 OR MIT` | https://github.com/ormsgpack/ormsgpack |
| `pydantic` | `2.14.1` | optional `[agent]` transitive | `MIT` | https://github.com/pydantic/pydantic |
| `pydantic-core` | `2.50.1` | optional `[agent]` transitive | `MIT` | https://github.com/pydantic/pydantic |
| `requests` | `2.34.2` | optional `[agent]` transitive | `Apache-2.0` | https://github.com/psf/requests |
| `requests-toolbelt` | `1.0.0` | optional `[agent]` transitive | `Apache-2.0` | https://toolbelt.readthedocs.io/ |
| `sniffio` | `1.3.1` | optional `[agent]` transitive | `MIT OR Apache-2.0` | https://github.com/python-trio/sniffio |
| `sqlite-vec` | `0.1.9` | optional `[agent]` transitive | `MIT OR Apache-2.0` | https://github.com/asg017/sqlite-vec |
| `tenacity` | `9.2.1` | optional `[agent]` transitive | `Apache-2.0` | https://github.com/jd/tenacity |
| `truststore` | `0.10.5` | optional `[agent]` transitive | `MIT` | https://github.com/sethmlarson/truststore |
| `typing-extensions` | `4.16.0` | optional `[agent]` transitive | `PSF-2.0` | https://github.com/python/typing_extensions |
| `typing-inspection` | `0.4.4` | optional `[agent]` transitive | `MIT` | https://github.com/pydantic/typing-inspection |
| `urllib3` | `2.8.0` | optional `[agent]` transitive | `MIT` | https://github.com/urllib3/urllib3 |
| `uuid-utils` | `0.19.0` | optional `[agent]` transitive | `BSD-3-Clause` | https://github.com/aminalaee/uuid-utils |
| `websockets` | `17.3` | optional `[agent]` transitive | `BSD-3-Clause` | https://github.com/python-websockets/websockets |
| `xxhash` | `4.0.2` | optional `[agent]` transitive | `BSD-2-Clause` | https://github.com/ifduyue/python-xxhash |
| `zstandard` | `0.25.0` | optional `[agent]` transitive | `BSD-3-Clause` | https://github.com/indygreg/python-zstandard |

## Test-Only Third-Party Excerpts (source repository only; not in the wheel or sdist)

The wheel and sdist do not include `tests/` (see `[tool.hatch.build.targets.sdist]` in `pyproject.toml`). The source repository's test
fixtures contain one short verbatim excerpt of third-party code, recorded as data inside a real Hlith run artifact:

- **`tests/fixtures/r1_triple_refactor_7b65a798_out.json.gz`** (used by a source-repository-only TUI fixture): the artifact's
  `effect.unified_diff` and obligation text quote about ten context and changed lines of `src/humanize/lists.py` (`natural_list`)
  from **humanize** (blob `36e8ab7`, upstream release `4.17.0`), the repository an acceptance refactor was checked against.
  humanize is licensed under the **MIT License** — Copyright (c) 2010-2020 Jason Moiron and Contributors.
  Upstream source: https://github.com/python-humanize/humanize. The upstream `LICENCE` text is reproduced below.

<details><summary>humanize LICENCE (MIT)</summary>

```text
Copyright (c) 2010-2020 Jason Moiron and Contributors

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

</details>

`tests/test_drive_inputs.py` also contains two short reduced function shapes modelled on humanize's `naturaldelta` control flow
(rewritten, not copied) as input-derivation test cases.
