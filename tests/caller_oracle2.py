# SPDX-License-Identifier: Apache-2.0
"""Independent caller oracle, round 2: project-wide pure-``ast`` type inference.

Imports nothing from hlith/libcst/tree-sitter. It indexes every module of a repository (classes, MRO by name,
functions, decorators, properties, registries of classes) and infers, with fixed deterministic rules, the class of
a receiver expression. A call ``recv.m(...)`` is RESOLVED when the receiver's inferred classes all find ``m`` by
MRO; the site is tagged with the most indirect rule the inference used:

  registry        REG[key](...)  /  REG[key].m   (module-level dict/list of classes)
  di_ctor_arg     an unannotated __init__ parameter whose type flows from constructor call sites
  factory         f(...).m() / x = f(); x.m()   (function whose returns are constructors / typed)
  classmethod_ctor Cls.create(...).m()  (classmethod/staticmethod returning cls(...)/Cls(...))
  di_attr         self.dep = dep (annotated __init__ parameter) ... self.dep.m()
  property        obj.prop.m()  /  obj.prop read where prop is a @property
  method_return   obj.get().m()  (instance method returning an object)
  inherited_self  self.m() where m comes from a base class (mixin / inheritance chain)
  subclass_dispatch self.m() in a base class: every override of m in a project subclass (template method)
  super           super().m()
  self_attr       self.x = Cls(...) ... self.x.m()
  param_annot     (w: Cls) ... w.m()
  local_instance  w = Cls(...); w.m()
  chained_ctor    Cls(...).m()
  unbound         Cls.m(w)
  direct          name call / import-as / module.attr call of a function

Anything the rules cannot resolve is not emitted (it is not claimed). Over-approximation is limited to unions.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

_SKIP = {".git", ".hlith", "__pycache__", ".venv", "venv", "node_modules", ".tox", "build", "dist", "third-party"}
RANK = ["subclass_dispatch", "registry", "di_ctor_arg", "factory", "classmethod_ctor", "di_attr", "property", "method_return",
        "inherited_self", "super", "self_attr", "param_annot", "local_instance", "chained_ctor", "unbound", "direct"]


@dataclass(frozen=True)
class Site2:
    file: str
    line: int
    caller: str
    target: str
    tag: str
    attr_col: int = 0
    n_targets: int = 1  # >1: the receiver is a union and several classes resolve


@dataclass
class Fn:
    qname: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    mod: "Mod"
    cls: "Cls | None"
    kind: str  # function | method | classmethod | staticmethod | property


@dataclass
class Cls:
    qname: str
    node: ast.ClassDef
    mod: "Mod"
    bases: list[str] = field(default_factory=list)  # resolved qnames or raw dotted text
    methods: dict[str, Fn] = field(default_factory=dict)
    attr_types: dict[str, tuple[frozenset, str]] = field(default_factory=dict)


@dataclass
class Mod:
    name: str
    rel: str
    tree: ast.Module
    imports: dict[str, str] = field(default_factory=dict)  # local name -> dotted origin ("pkg.mod" or "pkg.mod.Name")
    stars: list[str] = field(default_factory=list)
    classes: dict[str, Cls] = field(default_factory=dict)
    funcs: dict[str, Fn] = field(default_factory=dict)
    registries: dict[str, list[str]] = field(default_factory=dict)
    var_types: dict[str, tuple[frozenset, str]] = field(default_factory=dict)


@dataclass(frozen=True)
class Val:
    kind: str  # inst | cls | fn | mod
    names: frozenset
    tags: frozenset = frozenset()


def module_name(rel: str) -> str:
    parts = Path(rel).with_suffix("").parts
    if len(parts) > 1 and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _dec_names(node) -> set[str]:
    out = set()
    for d in node.decorator_list:
        x = d.func if isinstance(d, ast.Call) else d
        if isinstance(x, ast.Name):
            out.add(x.id)
        elif isinstance(x, ast.Attribute):
            out.add(x.attr)
    return out


class Project:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.mods: dict[str, Mod] = {}
        self.classes: dict[str, Cls] = {}
        self.funcs: dict[str, Fn] = {}
        self.ctor_args: dict[tuple[str, str], tuple[frozenset, str]] = {}
        self._ret_stack: list[str] = []
        self._load()
        self._resolve_bases()
        self._registries()
        for _ in range(2):  # attribute / constructor-argument types depend on each other: two passes
            self._attr_types()
            self._ctor_arg_types()
        self._attr_types()

    # ------------------------------------------------------------ indexing
    def _load(self) -> None:
        for p in sorted(self.root.rglob("*.py")):
            rel = p.relative_to(self.root).as_posix()
            if any(x in _SKIP for x in p.relative_to(self.root).parts):
                continue
            try:
                tree = ast.parse(p.read_text())
            except (SyntaxError, UnicodeDecodeError, ValueError):
                continue
            m = Mod(module_name(rel), rel, tree)
            self.mods[m.name] = m
            self._imports(m, tree)
            for n in ast.walk(tree):
                if isinstance(n, ast.ClassDef):
                    pass
            self._defs(m, tree.body, m.name, None)

    def _imports(self, m: Mod, tree: ast.Module) -> None:
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    m.imports[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(n, ast.ImportFrom):
                base = n.module or ""
                if n.level:
                    pkg = m.name.split(".")
                    if not m.rel.endswith("__init__.py"):
                        pkg = pkg[:-1]
                    if n.level > 1:
                        pkg = pkg[: len(pkg) - (n.level - 1)]
                    base = ".".join([*pkg, base]).strip(".")
                for a in n.names:
                    if a.name == "*":
                        m.stars.append(base)
                    else:
                        m.imports[a.asname or a.name] = f"{base}.{a.name}"

    def _defs(self, m: Mod, body, prefix: str, cls: Cls | None) -> None:
        for st in body:
            if isinstance(st, ast.ClassDef):
                c = Cls(f"{prefix}.{st.name}", st, m)
                (m.classes if cls is None else m.classes)[st.name if cls is None else f"{cls.node.name}.{st.name}"] = c
                self.classes[c.qname] = c
                self._defs(m, st.body, c.qname, c)
            elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decs = _dec_names(st)
                kind = ("classmethod" if "classmethod" in decs else "staticmethod" if "staticmethod" in decs
                        else "property" if decs & {"property", "cached_property"} else "method") if cls else "function"
                f = Fn(f"{prefix}.{st.name}", st, m, cls, kind)
                self.funcs[f.qname] = f
                if cls is not None:
                    cls.methods.setdefault(st.name, f)
                else:
                    m.funcs[st.name] = f
            elif isinstance(st, (ast.If, ast.Try, ast.With)):
                for sub in ([st.body, st.orelse] if isinstance(st, ast.If) else [st.body, *getattr(st, "handlers", [])] if isinstance(st, ast.Try) else [st.body]):
                    self._defs(m, sub if isinstance(sub, list) else sub.body, prefix, cls)

    def _resolve_bases(self) -> None:
        for c in self.classes.values():
            out = []
            for b in c.node.bases:
                v = self.resolve_dotted(c.mod, b)
                out.append(next(iter(v.names)) if v is not None and v.kind == "cls" and len(v.names) == 1 else ast.unparse(b))
            c.bases = out

    def _registries(self) -> None:
        for m in self.mods.values():
            for st in m.tree.body:
                if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                    val = st.value
                    items = (list(val.values) if isinstance(val, ast.Dict) else list(val.elts)
                             if isinstance(val, (ast.List, ast.Tuple, ast.Set)) else [])
                    qs = []
                    for it in items:
                        v = self.resolve_dotted(m, it) if it is not None else None
                        if v is not None and v.kind == "cls":
                            qs += sorted(v.names)
                    if qs and len(qs) == len(items):
                        m.registries[st.targets[0].id] = qs

    # ------------------------------------------------------------ name resolution
    def resolve_dotted(self, m: Mod, node: ast.AST) -> Val | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):  # string annotation
            try:
                return self.resolve_dotted(m, ast.parse(node.value, mode="eval").body)
            except SyntaxError:
                return None
        if isinstance(node, ast.Name):
            return self._lookup(m, node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve_dotted(m, node.value)
            if base is None:
                return None
            if base.kind == "mod":
                (mn,) = base.names
                full = f"{mn}.{node.attr}"
                if full in self.classes:
                    return Val("cls", frozenset([full]))
                if full in self.funcs:
                    return Val("fn", frozenset([full]))
                if full in self.mods:
                    return Val("mod", frozenset([full]))
                tgt = self.mods.get(mn)
                if tgt is not None and node.attr in tgt.imports:  # re-export
                    return self._from_origin(tgt.imports[node.attr])
                return None
            if base.kind == "cls":
                (cn,) = base.names if len(base.names) == 1 else (None,)
                if cn and f"{cn}.{node.attr}" in self.classes:
                    return Val("cls", frozenset([f"{cn}.{node.attr}"]))
            return None
        return None

    def _from_origin(self, origin: str) -> Val | None:
        if origin in self.classes:
            return Val("cls", frozenset([origin]))
        if origin in self.funcs:
            return Val("fn", frozenset([origin]))
        if origin in self.mods:
            return Val("mod", frozenset([origin]))
        head, _, last = origin.rpartition(".")
        if head in self.mods:  # name re-exported by an __init__
            tgt = self.mods[head]
            if last in tgt.imports and tgt.imports[last] != origin:
                return self._from_origin(tgt.imports[last])
        return None

    def _lookup(self, m: Mod, name: str) -> Val | None:
        if name in m.classes:
            return Val("cls", frozenset([m.classes[name].qname]))
        if name in m.funcs:
            return Val("fn", frozenset([m.funcs[name].qname]))
        if name in m.imports:
            return self._from_origin(m.imports[name])
        for s in m.stars:
            if s in self.mods:
                v = self._lookup(self.mods[s], name)
                if v is not None:
                    return v
        return None

    # ------------------------------------------------------------ MRO
    def mro(self, qname: str) -> list[Cls]:
        out: list[Cls] = []
        seen: set[str] = set()

        def go(q: str) -> None:
            c = self.classes.get(q)
            if c is None or q in seen:
                return
            seen.add(q)
            out.append(c)
            for b in c.bases:
                go(b)

        go(qname)
        return out

    def subclasses(self, qname: str) -> list[str]:
        """Strict project subclasses of a class (by resolved MRO), sorted."""
        idx = getattr(self, "_subs", None)
        if idx is None:
            idx = self._subs = {}
            for q in self.classes:
                for b in self.mro(q)[1:]:
                    idx.setdefault(b.qname, []).append(q)
        return sorted(idx.get(qname, ()))

    def find_method(self, qname: str, attr: str) -> tuple[Fn, bool] | None:
        """(method, inherited) by MRO."""
        chain = self.mro(qname)
        for i, c in enumerate(chain):
            if attr in c.methods:
                return c.methods[attr], i > 0
        return None

    # ------------------------------------------------------------ inference
    def _ann_types(self, m: Mod, ann: ast.AST | None) -> frozenset:
        if ann is None:
            return frozenset()
        out: set[str] = set()
        parts = [ann]
        if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
            parts = [x for x in ast.walk(ann) if isinstance(x, (ast.Name, ast.Attribute, ast.Constant, ast.Subscript))]
        elif isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name) and ann.value.id in ("Optional", "Union", "Type", "type"):
            sl = ann.slice
            parts = list(sl.elts) if isinstance(sl, ast.Tuple) else [sl]
        for p in parts:
            v = self.resolve_dotted(m, p)
            if v is not None and v.kind == "cls":
                out |= v.names
        return frozenset(out)

    def _local_env(self, fn: Fn) -> dict[str, tuple[frozenset, str]]:
        """name -> (class qnames, tag) for the parameters and single-valued assignments of ``fn`` (flow-insensitive)."""
        m = fn.mod
        env: dict[str, tuple[frozenset, str]] = {}
        a = fn.node.args
        params = [*a.posonlyargs, *a.args, *a.kwonlyargs]
        for i, arg in enumerate(params):
            if i == 0 and fn.cls is not None and fn.kind in ("method", "property"):
                env[arg.arg] = (frozenset([fn.cls.qname]), "self")
                continue
            if i == 0 and fn.cls is not None and fn.kind == "classmethod":
                env[arg.arg] = (frozenset([fn.cls.qname]), "clsparam")
                continue
            t = self._ann_types(m, arg.annotation)
            if t:
                env[arg.arg] = (t, "param_annot")
            elif fn.cls is not None and fn.node.name == "__init__":
                got = self.ctor_args.get((fn.cls.qname, arg.arg))
                if got:
                    env[arg.arg] = got
        self._assigns(fn, env)
        return env

    def _assigns(self, fn: Fn, env: dict) -> None:
        nodes = [n for n in ast.walk(fn.node) if isinstance(n, (ast.Assign, ast.AnnAssign))]
        for n in sorted(nodes, key=lambda x: (x.lineno, x.col_offset)):
            tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
            val = n.value
            for t in tgts:
                if not isinstance(t, ast.Name):
                    continue
                types: frozenset = frozenset()
                tag = "local_instance"
                if isinstance(n, ast.AnnAssign):
                    types = self._ann_types(fn.mod, n.annotation)
                    tag = "param_annot"
                if not types and val is not None:
                    v = self.infer(val, fn, env)
                    if v is not None and v.kind == "inst":
                        types, tag = v.names, self._best(v.tags) or "local_instance"
                        if tag == "chained_ctor":
                            tag = "local_instance"
                if types:
                    old = env.get(t.id)
                    env[t.id] = (types | (old[0] if old and old[1] not in ("self",) else frozenset()), tag)

    @staticmethod
    def _best(tags: frozenset) -> str | None:
        for r in RANK:
            if r in tags:
                return r
        return None

    def _attr_types(self) -> None:
        for c in self.classes.values():
            # class-level annotations
            for st in c.node.body:
                if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
                    t = self._ann_types(c.mod, st.annotation)
                    if t:
                        c.attr_types[st.target.id] = (t, "di_attr")
            for f in c.methods.values():
                if f.kind == "property":
                    continue
                env = self._local_env(f)
                for n in ast.walk(f.node):
                    if isinstance(n, (ast.Assign, ast.AnnAssign)):
                        tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                        for t in tgts:
                            if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == next(iter(env), "self"):
                                types: frozenset = frozenset()
                                tag = "self_attr"
                                if isinstance(n, ast.AnnAssign):
                                    types = self._ann_types(c.mod, n.annotation)
                                    tag = "di_attr"
                                if not types and n.value is not None:
                                    v = self.infer(n.value, f, env)
                                    if v is not None and v.kind == "inst":
                                        types = v.names
                                        tag = self._best(v.tags) or "self_attr"
                                        if tag in ("chained_ctor", "local_instance"):
                                            tag = "self_attr"
                                        if isinstance(n.value, ast.Name) and n.value.id in env and env[n.value.id][1] in (
                                                "param_annot", "di_ctor_arg"):
                                            tag = "di_ctor_arg" if env[n.value.id][1] == "di_ctor_arg" else "di_attr"
                                if types:
                                    old = c.attr_types.get(t.attr)
                                    c.attr_types[t.attr] = (types | (old[0] if old else frozenset()), tag)

    def _ctor_arg_types(self) -> None:
        """Unannotated __init__ parameters take the types of the arguments at constructor call sites."""
        for fn in list(self.funcs.values()):
            env = self._local_env(fn) if fn.kind != "classmethod" else self._local_env(fn)
            for n in ast.walk(fn.node):
                if not isinstance(n, ast.Call):
                    continue
                v = self.infer(n.func, fn, env, as_callee=True)
                if v is None or v.kind != "cls" or len(v.names) != 1:
                    continue
                (cq,) = v.names
                init = self.find_method(cq, "__init__")
                if init is None:
                    continue
                params = [p.arg for p in [*init[0].node.args.posonlyargs, *init[0].node.args.args]][1:]
                for i, a in enumerate(n.args[: len(params)]):
                    av = self.infer(a, fn, env)
                    if av is not None and av.kind == "inst":
                        key = (init[0].cls.qname if init[0].cls else cq, params[i])
                        old = self.ctor_args.get(key)
                        self.ctor_args[key] = ((old[0] if old else frozenset()) | av.names, "di_ctor_arg")
                for kw in n.keywords:
                    if kw.arg and kw.arg in params:
                        av = self.infer(kw.value, fn, env)
                        if av is not None and av.kind == "inst":
                            key = (init[0].cls.qname if init[0].cls else cq, kw.arg)
                            old = self.ctor_args.get(key)
                            self.ctor_args[key] = ((old[0] if old else frozenset()) | av.names, "di_ctor_arg")

    def returns(self, fn: Fn) -> Val | None:
        """Union of the inferred types of every ``return`` of fn (None if any return is not inferrable)."""
        if fn.qname in self._ret_stack or len(self._ret_stack) > 3:
            return None
        self._ret_stack.append(fn.qname)
        try:
            env = self._local_env(fn)
            names: set[str] = set()
            tags: set[str] = set()
            rets = [n for n in ast.walk(fn.node) if isinstance(n, ast.Return) and n.value is not None]
            if not rets:
                return None
            for r in rets:
                v = self.infer(r.value, fn, env)
                if v is None or v.kind != "inst":
                    names = set()
                    break
                names |= v.names
                tags |= v.tags
            if names:
                return Val("inst", frozenset(names), frozenset(tags))
            ann = getattr(fn.node, "returns", None)
            t = self._ann_types(fn.mod, ann)
            if t:
                return Val("inst", t, frozenset(tags))
            return None
        finally:
            self._ret_stack.pop()

    def infer(self, node: ast.AST, fn: Fn, env: dict, as_callee: bool = False) -> Val | None:
        m = fn.mod
        if isinstance(node, ast.Name):
            if node.id in env:
                t, tag = env[node.id]
                if tag == "self":
                    return Val("inst", t, frozenset())
                if tag == "clsparam":
                    return Val("cls", t, frozenset())
                return Val("inst", t, frozenset([tag]))
            v = self._lookup(m, node.id)
            if v is not None:
                return v
            if node.id in m.registries:
                return Val("cls", frozenset(m.registries[node.id]), frozenset(["registry"]))
            if node.id in m.var_types:
                t, tag = m.var_types[node.id]
                return Val("inst", t, frozenset([tag]))
            return None
        if isinstance(node, ast.Attribute):
            base = self.infer(node.value, fn, env)
            if base is None:
                return None
            if base.kind == "mod":
                return self.resolve_dotted(m, node)
            if base.kind == "cls":
                if len(base.names) == 1:
                    (cn,) = base.names
                    if f"{cn}.{node.attr}" in self.classes:
                        return Val("cls", frozenset([f"{cn}.{node.attr}"]), base.tags)
                fns = {h[0].qname for cn in base.names for h in [self.find_method(cn, node.attr)]
                       if h is not None and h[0].kind != "property"}
                if fns:
                    return Val("fn", frozenset(fns), base.tags)
                return None
            if base.kind == "inst":
                names: set[str] = set()
                tags = set(base.tags)
                for cn in base.names:
                    for c in self.mro(cn):
                        if node.attr in c.attr_types:
                            t, tag = c.attr_types[node.attr]
                            names |= t
                            tags.add(tag if tag in RANK else "self_attr")
                            break
                        pm = c.methods.get(node.attr)
                        if pm is not None and pm.kind == "property":
                            rv = self.returns(pm)
                            if rv is not None:
                                names |= rv.names
                                tags |= rv.tags | {"property"}
                            break
                if names:
                    return Val("inst", frozenset(names), frozenset(tags))
                fns = {h[0].qname for cn in base.names for h in [self.find_method(cn, node.attr)]
                       if h is not None and h[0].kind != "property"}
                if fns:
                    return Val("fn", frozenset(fns), base.tags)
            return None
        if isinstance(node, ast.Subscript):
            base = self.infer(node.value, fn, env)
            if base is not None and "registry" in base.tags and base.kind == "cls":
                return base
            return None
        if isinstance(node, ast.IfExp):
            vs = [self.infer(node.body, fn, env), self.infer(node.orelse, fn, env)]
            return self._union(vs)
        if isinstance(node, ast.BoolOp):
            return self._union([self.infer(v, fn, env) for v in node.values])
        if isinstance(node, ast.Await):
            return self.infer(node.value, fn, env)
        if isinstance(node, ast.Call):
            f = node.func
            # type(self)(...) / self.__class__(...)
            if (isinstance(f, ast.Call) and isinstance(f.func, ast.Name) and f.func.id == "type" and len(f.args) == 1) or \
                    (isinstance(f, ast.Attribute) and f.attr == "__class__"):
                inner = f.args[0] if isinstance(f, ast.Call) else f.value
                iv = self.infer(inner, fn, env)
                if iv is not None and iv.kind == "inst":
                    return Val("inst", iv.names, frozenset(["classmethod_ctor"]))
                return None
            if isinstance(f, ast.Call) and isinstance(f.func, ast.Name) and f.func.id == "super":
                return None
            callee = self.infer(f, fn, env, as_callee=True)
            if callee is None:
                return None
            if callee.kind == "cls":
                tags = set(callee.tags)
                tags.add("registry" if "registry" in callee.tags else "chained_ctor")
                if isinstance(f, ast.Name) and f.id in env and env[f.id][1] == "clsparam":
                    tags.add("classmethod_ctor")
                return Val("inst", callee.names, frozenset(tags))
            if callee.kind == "fn":
                names: set[str] = set()
                tags: set[str] = set(callee.tags)
                for q in callee.names:
                    rv = self.returns(self.funcs[q])
                    if rv is None:
                        return None
                    names |= rv.names
                    tags |= rv.tags
                    kind = self.funcs[q].kind
                    tags.add({"classmethod": "classmethod_ctor", "method": "method_return"}.get(kind, "factory"))
                return Val("inst", frozenset(names), frozenset(tags))
            return None
        return None

    @staticmethod
    def _union(vs: list) -> Val | None:
        vs = [v for v in vs if v is not None]
        if not vs or len({v.kind for v in vs}) != 1:
            return None
        return Val(vs[0].kind, frozenset().union(*[v.names for v in vs]), frozenset().union(*[v.tags for v in vs]))

    # ------------------------------------------------------------ call-site enumeration
    def _callee_of_attr(self, base: Val, attr: str, node: ast.Call, fn: Fn) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for cn in sorted(base.names):
            hit = self.find_method(cn, attr)
            if hit is None:
                continue
            f, inherited = hit
            tag = self._best(base.tags) or ("unbound" if base.kind == "cls" else "local_instance")
            if base.kind == "cls":
                if f.kind == "classmethod":
                    tag = self._best(base.tags) or "classmethod_ctor"
                    if tag in ("chained_ctor", "local_instance"):
                        tag = "unbound"
                else:
                    tag = self._best(base.tags) or "unbound"
            if inherited and tag in ("local_instance", "chained_ctor", "param_annot", "self_attr"):
                pass
            out.append((f.qname, tag))
        return out

    def sites(self) -> list[Site2]:
        res: list[Site2] = []
        for fn in self.funcs.values():
            env = self._local_env(fn)
            for n in ast.walk(fn.node):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                    f = n.func
                    # super().m(...)
                    if isinstance(f.value, ast.Call) and isinstance(f.value.func, ast.Name) and f.value.func.id == "super" \
                            and fn.cls is not None:
                        for b in self.mro(fn.cls.qname)[1:]:
                            if f.attr in b.methods:
                                res.append(Site2(fn.mod.rel, n.lineno, fn.qname, b.methods[f.attr].qname, "super",
                                                 f.end_col_offset - len(f.attr)))
                                break
                        continue
                    base = self.infer(f.value, fn, env)
                    if base is None:
                        continue
                    if base.kind in ("inst", "cls") and isinstance(f.value, ast.Name) and f.value.id in env \
                            and env[f.value.id][1] in ("self", "clsparam") and fn.cls is not None:
                        # template method: self.m() in C also runs every override of m in a subclass of C
                        done = {q for q, _ in self._callee_of_attr(base, f.attr, n, fn)}
                        for sub in self.subclasses(fn.cls.qname):
                            mm = self.classes[sub].methods.get(f.attr)
                            if mm is not None and mm.qname not in done:
                                done.add(mm.qname)
                                res.append(Site2(fn.mod.rel, n.lineno, fn.qname, mm.qname, "subclass_dispatch",
                                                 f.end_col_offset - len(f.attr)))
                    if base.kind == "mod":
                        v = self.resolve_dotted(fn.mod, f)
                        if v is not None and v.kind == "fn":
                            res.append(Site2(fn.mod.rel, n.lineno, fn.qname, next(iter(v.names)), "direct",
                                             f.end_col_offset - len(f.attr)))
                        continue
                    if base.kind not in ("inst", "cls"):
                        continue
                    tg = self._callee_of_attr(base, f.attr, n, fn)
                    for q, tag in tg:
                        t = tag
                        is_self = isinstance(f.value, ast.Name) and f.value.id in env and env[f.value.id][1] in ("self", "clsparam")
                        target_fn = self.funcs[q]
                        if is_self and target_fn.cls is not None and fn.cls is not None and target_fn.cls.qname != fn.cls.qname:
                            t = "inherited_self"
                        elif is_self:
                            t = "self_call"
                        res.append(Site2(fn.mod.rel, n.lineno, fn.qname, q, t, f.end_col_offset - len(f.attr), len(tg)))
                elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                    v = self.infer(n.func, fn, env)
                    if v is not None and v.kind == "fn" and n.func.id not in env:
                        for q in sorted(v.names):
                            res.append(Site2(fn.mod.rel, n.lineno, fn.qname, q, "direct", n.func.col_offset))
                elif isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load):
                    # property read: obj.prop where prop is a @property of the receiver's class
                    base = self.infer(n.value, fn, env)
                    if base is not None and base.kind == "inst":
                        for cn in sorted(base.names):
                            hit = self.find_method(cn, n.attr)
                            if hit is not None and hit[0].kind == "property":
                                res.append(Site2(fn.mod.rel, n.lineno, fn.qname, hit[0].qname, "property_read",
                                                 n.end_col_offset - len(n.attr)))
                                break
        return sorted(set(res), key=lambda s: (s.file, s.line, s.target, s.tag))


# a self-call (self.m() in the defining class) is its own, trivial, class
RANK_FULL = RANK + ["self_call", "property_read"]
