# SPDX-License-Identifier: Apache-2.0
"""Independent caller-completeness oracle.

Pure ``ast`` enumerator of every site in a repository that can reach a named function/method. It imports
nothing from hlith (no libcst, no tree-sitter, no effect.py), so it shares no program model with the
effect account it audits. Each site gets a construct label and a class:

  resolvable  the oracle attributes the site to the target by a syntactic rule (direct name, import-as,
              unbound ``Class.m(x)``, ``self.m()`` in the class, constructor-assigned receiver, ...)
  dynamic     the site may reach the target but no static rule decides it (unknown receiver, getattr,
              callback reference, ...)

Over-approximation by short name is deliberate: a MISS is a site the account neither lists nor flags.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

_SKIP = {".git", ".hlith", "__pycache__", ".venv", "venv", "node_modules", ".tox", "build", "dist"}


@dataclass(frozen=True)
class Site:
    file: str
    line: int
    construct: str
    klass: str  # resolvable | dynamic
    caller: str


def module_name(rel: str) -> str:
    parts = Path(rel).with_suffix("").parts
    if len(parts) > 1 and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def iter_py(root: Path) -> Iterator[Path]:
    for p in sorted(root.rglob("*.py")):
        if not any(x in _SKIP for x in p.relative_to(root).parts):
            yield p


def locate(root: Path, mod: str) -> Path | None:
    """Source file of dotted module ``mod`` (flat or ``src/`` layout)."""
    for base in (root, root / "src"):
        rel = base / Path(*mod.split("."))
        if rel.with_suffix(".py").exists():
            return rel.with_suffix(".py")
        if (rel / "__init__.py").exists():
            return rel / "__init__.py"
    return None


def split_target(qualified: str, root: Path) -> tuple[str, str | None, str]:
    """pkg.mod.Class.meth -> (module, Class, meth); pkg.mod.func -> (module, None, func)."""
    parts = qualified.split(".")
    for i in range(len(parts) - 1, 0, -1):
        mod = ".".join(parts[:i])
        if locate(root, mod) is not None:
            rest = parts[i:]
            return mod, (rest[0] if len(rest) == 2 else None), rest[-1]
    raise ValueError(f"cannot locate module of {qualified}")


class _V(ast.NodeVisitor):
    def __init__(self, rel: str, mod: str, tmod: str, tcls: str | None, short: str):
        self.rel, self.mod, self.tmod, self.tcls, self.short = rel, mod, tmod, tcls, short
        self.sites: list[Site] = []
        self.imp: dict[str, str] = {}      # local name -> dotted origin
        self.star: set[str] = set()
        self.cls_stack: list[ast.ClassDef] = []
        self.fn_stack: list[ast.AST] = []
        self.local_inst: list[dict[str, str]] = [{}]   # per-function: var -> "instance"|"alias"
        self.self_attr_inst: dict[str, set[str]] = {}  # class -> attrs assigned Cls(...)
        self.parent: dict[int, ast.AST] = {}

    # ---- helpers
    def caller(self) -> str:
        names = [c.name for c in self.cls_stack] + [f.name for f in self.fn_stack if hasattr(f, "name")]
        return ".".join([self.mod, *names]) if names else self.mod

    def add(self, node: ast.AST, construct: str, klass: str) -> None:
        self.sites.append(Site(self.rel, node.lineno, construct, klass, self.caller()))

    def is_target_class_name(self, n: ast.AST) -> bool:
        if self.tcls is None:
            return False
        if isinstance(n, ast.Name):
            if n.id == self.tcls and self.mod == self.tmod:
                return True
            return self.imp.get(n.id) == f"{self.tmod}.{self.tcls}"
        if isinstance(n, ast.Attribute) and n.attr == self.tcls:
            d = self._dotted(n.value)
            return d is not None and self._mod_of(d) == self.tmod
        return False

    def _dotted(self, n: ast.AST) -> str | None:
        if isinstance(n, ast.Name):
            return n.id
        if isinstance(n, ast.Attribute):
            b = self._dotted(n.value)
            return None if b is None else f"{b}.{n.attr}"
        return None

    def _mod_of(self, dotted: str) -> str:
        head, _, rest = dotted.partition(".")
        base = self.imp.get(head, head)
        return f"{base}.{rest}" if rest else base

    def _ctor_of_target(self, n: ast.AST) -> bool:
        return isinstance(n, ast.Call) and self.is_target_class_name(n.func)

    def _is_ref(self, n: ast.AST) -> bool:
        """n (Name/Attribute, not being called) names the target."""
        if self.tcls is None:
            if isinstance(n, ast.Name):
                return n.id == self.short and self.mod == self.tmod and not self._shadow(n.id) or \
                    self.imp.get(n.id) == f"{self.tmod}.{self.short}"
            if isinstance(n, ast.Attribute) and n.attr == self.short:
                d = self._dotted(n.value)
                return d is not None and self._mod_of(d) == self.tmod
            return False
        return isinstance(n, ast.Attribute) and n.attr == self.short

    def _shadow(self, name: str) -> bool:
        return False

    # ---- imports
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.imp[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = node.module or ""
        if node.level:
            pkg = self.mod.split(".")
            if not self.rel.endswith("__init__.py"):
                pkg = pkg[:-1]
            pkg = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
            base = ".".join([*pkg, base]).strip(".")
        for a in node.names:
            if a.name == "*":
                self.star.add(base)
            else:
                self.imp[a.asname or a.name] = f"{base}.{a.name}"

    # ---- scopes
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for d in node.decorator_list:
            self.visit(d)
        self.cls_stack.append(node)
        for st in node.body:
            if isinstance(st, ast.Assign) and self._is_ref(st.value) and any(isinstance(t, ast.Name) for t in st.targets):
                self.add(st, "class_attr_callable", "dynamic")
            elif isinstance(st, ast.Assign) and isinstance(st.value, ast.Name) and st.value.id == self.short \
                    and self.tcls is not None and self.cls_stack[-1].name == self.tcls and self.mod == self.tmod:
                self.add(st, "class_attr_callable", "resolvable")
        for st in node.body:
            self.visit(st)
        self.cls_stack.pop()

    def _fn(self, node) -> None:
        for d in node.decorator_list:
            if self._is_ref(d) or (isinstance(d, ast.Call) and self._is_ref(d.func)):
                self.add(d, "decorator", "dynamic")
            self.visit(d)
        self.fn_stack.append(node)
        env: dict[str, str] = {}
        for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
            if arg.annotation is not None and self.is_target_class_name(
                    ast.parse(ast.unparse(arg.annotation).strip("'\""), mode="eval").body
                    if isinstance(arg.annotation, ast.Constant) and isinstance(arg.annotation.value, str)
                    else arg.annotation):
                env[arg.arg] = "annotated"
        self.local_inst.append(env)
        for st in node.body:
            self.visit(st)
        self.local_inst.pop()
        self.fn_stack.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = _fn

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.local_inst.append(dict(self.local_inst[-1]))
        self.generic_visit(node)
        self.local_inst.pop()

    # ---- assignments feed receiver typing and alias tracking
    def visit_Assign(self, node: ast.Assign) -> None:
        env = self.local_inst[-1]
        for t in node.targets:
            if isinstance(t, ast.Name):
                if self._ctor_of_target(node.value):
                    env[t.id] = "instance"
                elif self._is_ref(node.value):
                    env[t.id] = "alias"
                    self.add(node, "alias_assignment", "dynamic")
                elif (isinstance(node.value, ast.Name) and env.get(node.value.id) == "instance"):
                    env[t.id] = "instance"
                else:
                    env.pop(t.id, None)
            elif isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self" \
                    and self.cls_stack and self._ctor_of_target(node.value):
                self.self_attr_inst.setdefault(self.cls_stack[-1].name, set()).add(t.attr)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and self.is_target_class_name(node.annotation):
            self.local_inst[-1][node.target.id] = "annotated"
        self.generic_visit(node)

    # ---- the sites
    def visit_Call(self, node: ast.Call) -> None:
        f = node.func
        if isinstance(f, ast.Name):
            self._name_call(node, f)
        elif isinstance(f, ast.Attribute) and f.attr == self.short:
            self._attr_call(node, f)
        if isinstance(f, ast.Name) and f.id == "getattr" and len(node.args) >= 2 \
                and isinstance(node.args[1], ast.Constant) and node.args[1].value == self.short:
            self.add(node, "getattr_literal", "dynamic")
        # references passed as arguments (callback / partial / map)
        for a in [*node.args, *(k.value for k in node.keywords)]:
            if self._is_ref(a):
                fn = self._dotted(f) or ""
                self.add(a, "partial" if fn.endswith("partial") else "callback_reference", "dynamic")
        self.generic_visit(node)

    def _name_call(self, node: ast.Call, f: ast.Name) -> None:
        if self.tcls is None:
            if f.id == self.short and self.mod == self.tmod:
                self.add(node, "direct_name", "resolvable")
            elif self.imp.get(f.id) == f"{self.tmod}.{self.short}":
                self.add(node, "direct_name" if f.id == self.short else "import_as", "resolvable")
            elif f.id == self.short and self.tmod in self.star:
                self.add(node, "star_import", "resolvable")
        if self.local_inst[-1].get(f.id) == "alias":
            self.add(node, "alias_call", "dynamic")

    def _attr_call(self, node: ast.Call, f: ast.Attribute) -> None:
        r = f.value
        if self.tcls is None:
            d = self._dotted(r)
            if d is not None and self._mod_of(d) == self.tmod:
                self.add(node, "module_attr", "resolvable")
            else:
                self.add(node, "unknown_receiver", "dynamic")
            return
        if self.is_target_class_name(r):
            self.add(node, "unbound_class_call", "resolvable")
        elif isinstance(r, ast.Name) and r.id in ("self", "cls") and self.cls_stack:
            c = self.cls_stack[-1]
            same = c.name == self.tcls and self.mod == self.tmod
            self.add(node, "self_call" if same else "self_call_other_class", "resolvable" if same else "dynamic")
        elif self._ctor_of_target(r):
            self.add(node, "chained_constructor", "resolvable")
        elif isinstance(r, ast.Name) and self.local_inst[-1].get(r.id) in ("instance", "annotated"):
            self.add(node, "instance_local" if self.local_inst[-1][r.id] == "instance" else "annotated_param", "resolvable")
        elif isinstance(r, ast.Attribute) and isinstance(r.value, ast.Name) and r.value.id == "self" and self.cls_stack \
                and r.attr in self.self_attr_inst.get(self.cls_stack[-1].name, ()):
            self.add(node, "self_attr_instance", "resolvable")
        elif isinstance(r, ast.Call) and isinstance(r.func, ast.Name) and r.func.id == "super":
            c = self.cls_stack[-1] if self.cls_stack else None
            bases = {ast.unparse(b) for b in c.bases} if c else set()
            self.add(node, "super_call", "resolvable" if self.tcls in bases else "dynamic")
        else:
            self.add(node, "unknown_receiver", "dynamic")

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # a bare reference that is not the func of a Call: alias / dict value / return / etc. (Call args handled above)
        self.generic_visit(node)


def enumerate_sites(root: str | Path, qualified: str) -> list[Site]:
    """Every site in ``root`` that can reach ``qualified`` (the target's own definition excluded)."""
    root = Path(root)
    tmod, tcls, short = split_target(qualified, root)
    out: list[Site] = []
    for p in iter_py(root):
        rel = p.relative_to(root).as_posix()
        try:
            tree = ast.parse(p.read_text())
        except (SyntaxError, UnicodeDecodeError, ValueError):
            continue
        v = _V(rel, module_name(rel), tmod, tcls, short)
        # pre-pass 1: imports (receiver typing needs them before the first use); pre-pass 2: ``self.x = Cls(...)``
        for n in ast.walk(tree):
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                v.visit(n)
        for c in ast.walk(tree):
            if isinstance(c, ast.ClassDef):
                for n in ast.walk(c):
                    if isinstance(n, ast.Assign) and v._ctor_of_target(n.value):
                        for t in n.targets:
                            if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self":
                                v.self_attr_inst.setdefault(c.name, set()).add(t.attr)
        v.visit(tree)
        out.extend(v.sites)
    # dedupe (a node can be reported through two routes)
    return sorted(set(out), key=lambda s: (s.file, s.line, s.construct))
