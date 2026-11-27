# Dependency Provenance and Licensing

This document records the inspected package boundary and license evidence for the locked Python environment.

## 1. Hlith Source Provenance

- **License:** Apache License 2.0 (`LICENSE` at repository root; `license = "Apache-2.0"` in `pyproject.toml`).
- **SPDX coverage:** 100% of Python source modules under `src/hlith/` carry `# SPDX-License-Identifier: Apache-2.0`.
- **Third-party source audit:** The shipping tree contains the Hlith Python modules, its two JSON schemas, and the companion agent-hook shell script (`scripts/agent-hook/hlith-agent-hook.sh`, installed as `hlith-agent-hook`). The parser layer uses LibCST as an external parser. The certificate layer reuses a parser helper. The CrossHair study is cited as a design reference. Source attribution review identified no vendored external package in that tree.
- **Test-only fixtures:** Test suites under `tests/` (including `tests/caller_oracle2.py` and synthetic security fixtures) stay in the source repository and are excluded from both distribution formats. Wheel package selection uses `[tool.hatch.build.targets.wheel] packages = ["src/hlith"]` plus `[tool.hatch.build.targets.wheel.shared-scripts]` for `hlith-agent-hook`.

## 2. Locked Dependency Graph Summary

- **Lockfile:** `uv.lock` (registry: `https://pypi.org/simple` only; every package carries full SHA-256 artifact hashes).
- **Qualified runtime:** Python 3.13.9 (`uv sync --frozen --python 3.13.9`).
- **Third-party packages in `uv.lock`:** **54 in the union**. The default Review distribution is **14 locked packages** (6 direct + 8 transitive; **12 installed on Linux Python 3.13.9**, with `colorama` win32-only and `pyyaml`/`pyyaml-ft` selected by Python version). The optional `[agent]` extra adds **40 locked packages** (3 direct + 37 transitive), for 54 total and **52 installed on Linux** when installed. See `THIRD_PARTY_NOTICES.md` for the complete split.
- **Machine-readable CycloneDX SBOM:** Reproduce deterministically offline with `python scripts/sbom_draft.py --lock uv.lock` (verified by `tests/standards/test_sbom_draft.py`).
- **Cutoffs & transitive pins:** `pyproject.toml` pins `[tool.uv.exclude-newer-package]` (`z3-solver`, `tree-sitter`, `tree-sitter-python` at `2026-10-29T00:00:00Z`) and `[tool.uv].constraint-dependencies` matching `uv.lock` without mutating the lock.

### License distribution (default Review and the optional `[agent]` union)

| Category | Count | Packages |
|---|---:|---|
| Permissive (`MIT`, `Apache-2.0`, `BSD-3-Clause`, `BSD-2-Clause`, `PSF-2.0`, permissive dual) | 51 | 13 default + 38 optional-`[agent]` packages; all packages other than the three MPL-2.0 packages below |
| Weak file-level copyleft (`MPL-2.0`) | 3 | `hypothesis==6.170.15` (default direct), `certifi==2026.10.23` (optional `[agent]`), `orjson==3.13.0` (optional `[agent]`; `MPL-2.0 AND (Apache-2.0 OR MIT)`) |
| Strong copyleft (`GPL`, `AGPL`, `LGPL`, `SSPL`) or proprietary | 0 | None |

## 3. Resolution of MPL-2.0 Dependencies for Public Distribution

Three locked dependencies carry MPL-2.0: `hypothesis` (default direct), `certifi` (optional `[agent]` transitive), and `orjson` (optional `[agent]` transitive). The default Review distribution carries only `hypothesis` under MPL-2.0.

The wheel ships Hlith, its schemas, the `hlith-agent-hook` script, and notices. The sdist adds the frozen lock,
SBOM generator, Landlock capability probe, agent-hook source script, self-contained `examples/first-use/` fixture, and operator documentation. The source snapshot retains the test fixtures; engineering evidence is not in the public snapshot.

The lock table was checked against all 54 versions, artifact counts and primary hashes. License metadata
and shipped notices were inspected for the default 12 Linux packages and the optional `[agent]` addition
(52 Linux packages when installed), and both conditional wheels verified against their lock hashes. LibCST explicitly identifies PSF-derived parser files and an Apache-2.0
dataclasses-derived file alongside its MIT contributions. The sqlite-vec Linux wheel declares MIT and Apache
but supplies no separate license text. A binary redistribution would need its corresponding upstream notices.

MPL-2.0 applies to covered files. Hlith declares the three packages as external dependencies.
For distribution of executables containing covered files, make their corresponding source available
under MPL-2.0, give recipients the retrieval location and preserve required notices (sections 3.1–3.3).
A general project homepage alone does not establish source availability for the shipped version.
The source-only Hlith artifacts do not include a Python runtime, third-party wheels or a container.
Bundling any of those requires a separate review of their contents, native components and license files.

## 4. Complete 54-Package Provenance Table (default Review plus optional `[agent]`)

All SHA-256 hashes below come directly from `uv.lock` (the sdist SHA-256 and artifact count are shown;
run `python scripts/sbom_draft.py --lock uv.lock` for every platform wheel hash in CycloneDX JSON).
The default Review set is the 14-package table in `THIRD_PARTY_NOTICES.md`; rows introduced only by the optional `[agent]` extra are not installed by default.

| Package | Version | Direct / Required by | License (SPDX) | Artifacts | Primary SHA-256 (`uv.lock`) | Upstream |
|---|---|---|---|---:|---|---|
| `aiosqlite` | `0.22.1` | transitive (langgraph-checkpoint-sqlite) | `MIT` | 2 | `043e0bd78d32888c0a9ca90fc788b38796843360c855a7262a532813133a0650` | https://github.com/omnilib/aiosqlite |
| `annotated-types` | `0.8.0` | transitive (pydantic) | `MIT` | 2 | `13b2beaad985e05e2d6407ee4c4f35590b11f8d693a258a561055cac8f64cab7` | https://github.com/annotated-types/annotated-types |
| `anyio` | `4.15.1` | transitive (httpx, httpx2, langsmith) | `MIT` | 2 | `9f28306018cbd6d329e64a36d58256edff76dd996fe423bc957326e578b82a94` | https://github.com/agronholm/anyio |
| `certifi` | `2026.10.23` | transitive (httpcore, httpx, requests) | `MPL-2.0` | 2 | `a9895e6e2758b371e0545e321a3a8fd1fcfd9829ada8824a936dfb16aaaf36cd` | https://github.com/certifi/python-certifi |
| `charset-normalizer` | `3.5.2` | transitive (requests) | `MIT` | 124 | `39de2a259fc954455c57274dc94c79d5842774e1247a016aff30bc0efed0f4ef` | https://github.com/jawah/charset_normalizer |
| `colorama` | `0.4.6` | transitive (win32 only (via pytest)) | `BSD-3-Clause` | 2 | `08695f5cb7ed6e0531a20572697297273c47b8cae5a63ffc6d6ed5c201be6e44` | https://github.com/tartley/colorama |
| `distro` | `1.9.0` | transitive (langsmith) | `Apache-2.0` | 2 | `2fa77c6fd8940f116ee1d6b94a2f90b13b5ea8d019b98bc8bafdcabcdd9bdbed` | https://github.com/python-distro/distro |
| `h11` | `0.16.0` | transitive (httpcore, httpcore2) | `MIT` | 2 | `4e35b956cf45792e4caa5885e69fba00bdbc6ffafbfa020300e549b208ee5ff1` | https://github.com/python-hyper/h11 |
| `httpcore` | `1.0.9` | transitive (httpx) | `BSD-3-Clause` | 2 | `6e34463af53fd2ab5d807f399a9b45ea31c3dfa2276f15a2c3f00afff6e176e8` | https://www.encode.io/httpcore/ |
| `httpcore2` | `2.16.0` | transitive (httpx2) | `BSD-3-Clause` | 2 | `c72cd0413563b17e1cd8354677dff887466f8ec2551679759e93126534428643` | https://github.com/pydantic/httpx2 |
| `httpx` | `0.28.1` | transitive (langchain-core, langgraph-sdk) | `BSD-3-Clause` | 2 | `75e98c5f16b0f35b567856f597f06ff2270a374470a5c2392242528e3e3e42fc` | https://github.com/encode/httpx |
| `httpx2` | `2.16.0` | transitive (langsmith) | `BSD-3-Clause` | 2 | `0d54c98128e8f2ff7fbbde0fca8c359e5f032edeaaaac443cdb7f31f685bcd7f` | https://github.com/pydantic/httpx2 |
| `httpx2-jsfetch` | `1.0` | transitive (emscripten only (via httpx2)) | `BSD-3-Clause` | 2 | `70a0e3eabfef7cce5ad9c629f7d01ca05e418f586646f4ddf14782e4c1454c60` | https://github.com/pydantic/httpx2 |
| `hypothesis` | `6.170.15` | **direct** | `MPL-2.0` | 71 | `a4a57e5fb106ecb29cad37e22e411d957e20d933bfb9fb029e1999b1deb8a0b6` | https://github.com/HypothesisWorks/hypothesis |
| `idna` | `3.20` | transitive (anyio, httpx, httpx2, requests) | `BSD-3-Clause` | 2 | `a7db850025b95ded1eae8a46181a1a6c56c92c96f0e2b005d9ff8dc0210cab44` | https://github.com/kjd/idna |
| `iniconfig` | `2.3.1` | transitive (pytest) | `MIT` | 2 | `67f4b9c50da0dedf52af349e7749a80a9057a5031199791b906c3bb3ae878960` | https://github.com/pytest-dev/iniconfig |
| `jsonpatch` | `1.38` | transitive (langchain-core) | `BSD-3-Clause` | 2 | `debc3e7bdc3d446468d64987f51a0e7a9deea42987ff90a6d1005a489b471c19` | https://github.com/stefankoegl/python-json-patch |
| `jsonpointer` | `3.6` | transitive (jsonpatch) | `BSD-3-Clause` | 2 | `82e839a3ba3a9e2b54394fda8b3d276c2459d80408d06ef9a6fbc369d7544ffc` | https://github.com/stefankoegl/python-json-pointer |
| `langchain-core` | `1.7.1` | transitive (langgraph, langgraph-checkpoint, langgraph-prebuilt, langgraph-sdk) | `MIT` | 2 | `5dc2a357e1aa40e84c7f29755182121b3acf04410e55fa3723915f645033fede` | https://docs.langchain.com/ |
| `langchain-protocol` | `0.0.20` | transitive (langchain-core, langgraph-sdk) | `MIT` | 2 | `0f5bd002474265648e91161771a9e0438fe9480bd55a416e51af0f60070637ec` | https://github.com/langchain-ai/agent-protocol/tree/main/streaming |
| `langgraph` | `1.2.18` | **direct** | `MIT` | 2 | `4c3e4289043ed0f99625a09990a012d7b16bb576301d8616810de7db01725f9e` | https://docs.langchain.com/oss/python/langgraph/overview |
| `langgraph-checkpoint` | `4.3.1` | **direct** | `MIT` | 2 | `625e7c78a72b33e7c47f7e87ca051060fb90aa66f5fd551c472c08376fb669cb` | https://github.com/langchain-ai/langgraph/tree/main/libs/checkpoint |
| `langgraph-checkpoint-sqlite` | `3.1.2` | **direct** | `MIT` | 2 | `4e3f376fa6f192d6ad2a1a4643b039986f1593552ef870e9e45281575de6fbf2` | https://github.com/langchain-ai/langgraph/tree/main/libs/checkpoint-sqlite |
| `langgraph-prebuilt` | `1.1.1` | transitive (langgraph) | `MIT` | 2 | `f1b1a4772e7f9f15ba736411aad3877183ad40cd9349748df76bd2b9f58a83c7` | https://github.com/langchain-ai/langgraph/tree/main/libs/prebuilt |
| `langgraph-sdk` | `0.4.10` | transitive (langgraph) | `MIT` | 2 | `d8d7afd326b4df42ddc0878b7fbf53f03c3237c664c236bf5bac4ab16fc38ed9` | https://github.com/langchain-ai/langgraph/tree/main/libs/sdk-py |
| `langsmith` | `0.14.14` | transitive (langchain-core) | `MIT` | 2 | `fc28d1981656918f145d8d8089ed924dbf93d95e4959d0c1882cb5aec1563a0d` | https://github.com/langchain-ai/langsmith-python |
| `libcst` | `1.9.0` | **direct** | `MIT AND PSF-2.0 AND Apache-2.0` | 43 | `087b58a9afe076bb08e2d726478e1f16cb928d67ffa9092817e033c335de522a` | https://github.com/Instagram/LibCST |
| `orjson` | `3.13.0` | transitive (langgraph-sdk, langsmith) | `MPL-2.0 AND (Apache-2.0 OR MIT)` | 41 | `d1de5eb04485110c5da4c657e49168995d55e076b1ce60f1a042e254f4186c4f` | https://github.com/ijl/orjson |
| `ormsgpack` | `1.13.0` | transitive (langgraph-checkpoint) | `Apache-2.0 OR MIT` | 41 | `4127e84b07816e1f36d557e95b5642041692df22bf77f2c2f563a2039ab8144e` | https://github.com/ormsgpack/ormsgpack |
| `packaging` | `26.3` | transitive (langchain-core, langsmith, pytest) | `Apache-2.0 OR BSD-2-Clause` | 2 | `94edc256424af38762eb31306eed28beb9f0efc50a8837492c9d6fd6004aed79` | https://github.com/pypa/packaging |
| `pluggy` | `1.7.0` | transitive (pytest) | `MIT` | 2 | `d1eaa46ebb595891b860ab086b4d09c8588af65ebd4361b8e8f4bb8920b90ba8` | https://github.com/pytest-dev/pluggy |
| `pydantic` | `2.14.1` | transitive (langchain-core, langgraph, langsmith) | `MIT` | 2 | `94f478203dd03404682a1ada216965651dd74b1d2d5ffd62e00e0837caab5c26` | https://github.com/pydantic/pydantic |
| `pydantic-core` | `2.50.1` | transitive (pydantic) | `MIT` | 96 | `e50d7b94baac6c7d09927fa5ca5800a0c7ee5015c7fcff65beb3a1931b5a6e09` | https://github.com/pydantic/pydantic |
| `pygments` | `2.21.0` | transitive (pytest) | `BSD-2-Clause` | 2 | `610ca751c9bc2492b38eb9a38a7fbc93edbbb2d7182edaf34e66ae493dee5c8c` | https://pygments.org |
| `pytest` | `9.2.0` | **direct** | `MIT` | 2 | `97c4f3b1f3c7414aa36465e09b8220f1d03627993bd51b1282e193753c80557b` | https://docs.pytest.org/en/latest/ |
| `pyyaml` | `6.0.3` | transitive (langchain-core, libcst) | `MIT` | 39 | `d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f` | https://pyyaml.org/ |
| `pyyaml-ft` | `8.0.0` | transitive (libcst) | `MIT` | 17 | `0c947dce03954c7b5d38869ed4878b2e6ff1d44b08a0d84dc83fdad205ae39ab` | https://github.com/Quansight-Labs/pyyaml-ft/ |
| `requests` | `2.34.2` | transitive (langsmith, requests-toolbelt) | `Apache-2.0` | 2 | `f288924cae4e29463698d6d60bc6a4da69c89185ad1e0bcc4104f584e960b9ed` | https://github.com/psf/requests |
| `requests-toolbelt` | `1.0.0` | transitive (langsmith) | `Apache-2.0` | 2 | `7681a0a3d047012b5bdc0ee37d7f8f07ebe76ab08caeccfc3921ce23c88d5bc6` | https://toolbelt.readthedocs.io/ |
| `sniffio` | `1.3.1` | transitive (langsmith) | `MIT OR Apache-2.0` | 2 | `f4324edc670a0f49750a81b895f35c3adb843cca46f0530f79fc1babb23789dc` | https://github.com/python-trio/sniffio |
| `sortedcontainers` | `2.4.0` | transitive (hypothesis) | `Apache-2.0` | 2 | `25caa5a06cc30b6b83d11423433f65d1f9d76c4c6a0c90e3379eaa43b9bfdb88` | http://www.grantjenks.com/docs/sortedcontainers/ |
| `sqlite-vec` | `0.1.9` | transitive (langgraph-checkpoint-sqlite) | `MIT OR Apache-2.0` | 5 | `1b62a7f0a060d9475575d4e599bbf94a13d85af896bc1ce86ee80d1b5b48e5fb` | https://github.com/asg017/sqlite-vec |
| `tenacity` | `9.2.1` | transitive (langchain-core) | `Apache-2.0` | 2 | `a606b5c808d0cded4a359d5b9932d867ff2a6a6b64d37350260fd01bbdf83839` | https://github.com/jd/tenacity |
| `tree-sitter` | `0.25.2` | **direct** | `MIT` | 22 | `fe43c158555da46723b28b52e058ad444195afd1db3ca7720c59a254544e9c20` | https://tree-sitter.github.io/tree-sitter/ |
| `tree-sitter-python` | `0.25.0` | **direct** | `MIT` | 9 | `b13e090f725f5b9c86aa455a268553c65cadf325471ad5b65cd29cac8a1a68ac` | https://github.com/tree-sitter/tree-sitter-python |
| `truststore` | `0.10.5` | transitive (httpcore2, httpx2) | `MIT` | 2 | `30d36967ccaded5cbb38d602c433f53600036c79d502f4533a49b60a03bbefcd` | https://github.com/sethmlarson/truststore |
| `typing-extensions` | `4.16.0` | transitive (anyio, httpx2, langchain-core, langchain-protocol, …) | `PSF-2.0` | 2 | `dc983d19a509c94dba722ee6abd33940f7c05a89e243c47e907eb4db6f1a43e5` | https://github.com/python/typing_extensions |
| `typing-inspection` | `0.4.4` | transitive (pydantic) | `MIT` | 2 | `547274fa6b0a561ccf549cc9524b999a578e737d015d8709d021f9d0d13bea47` | https://github.com/pydantic/typing-inspection |
| `urllib3` | `2.8.0` | transitive (requests) | `MIT` | 2 | `63bf2ead4c879426ebf22ef2a781eeb4aa3b4ae798a0435506f8687fd5bb9b63` | https://github.com/urllib3/urllib3 |
| `uuid-utils` | `0.19.0` | transitive (langchain-core, langsmith) | `BSD-3-Clause` | 45 | `4b2996bb9d12da9b62f6f4c64a066b26926fa75dbe47b4f8e309e24e187abf1d` | https://github.com/aminalaee/uuid-utils |
| `websockets` | `17.3` | transitive (langgraph-sdk, langsmith) | `BSD-3-Clause` | 128 | `1c7dd93a1c9f89297471493674b1fc1d9467cafd45374f2172213046bdb3a329` | https://github.com/python-websockets/websockets |
| `xxhash` | `4.0.2` | transitive (langgraph, langsmith) | `BSD-2-Clause` | 149 | `af3d1b3cfa5280e84d8968e9f30c9eca75781db4915eb6d6acb0dd4fc93e0f47` | https://github.com/ifduyue/python-xxhash |
| `z3-solver` | `5.3.2.0` | **direct** | `MIT` | 10 | `91b0028697082c3e48e7fb36dd13d642aee33a74a610c8c90b6d83f82e9f7fcc` | https://github.com/Z3Prover/z3 |
| `zstandard` | `0.25.0` | transitive (langsmith) | `BSD-3-Clause` | 50 | `7713e1179d162cf5c7906da876ec2ccb9c3a9dcbdffef0cc7f70c3667a205f0b` | https://github.com/indygreg/python-zstandard |
