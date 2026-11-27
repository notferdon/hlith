# SPDX-License-Identifier: Apache-2.0
"""One restrict-only binding check applied to EVERY positive certificate (case).

Each prover reads a module name as "the def / constant / import / builtin I can see". That is only true when the name has exactly the binding the prover saw.
A certificate is refused unless every name the proof can resolve has, in BOTH versions of the target module: no binding at all when it is a builtin name, and
otherwise at most exactly one binding, which is a direct statement of the module body; and no other file of the scanned tree writes it from outside.

An attribute store through `self` / `cls` is exempt only inside a method of a class that never escapes (its class object is only called to make instances).

Not covered (disclosed): writes from outside the scanned tree (including the repository's tests), import hooks, mutation through frames or `gc`, a receiver
that is an instance of a non-escaping class made to stand for a module by means this gate does not spell, and code the walker cannot attribute to source."""

from __future__ import annotations

import ast
import builtins
import symtable

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_REWRITE_BUILTINS = frozenset({"sum"})  # builtins a normalization may INTRODUCE into a version that did not spell them
_RECEIVERS = frozenset({"self", "cls"})
_CLASS_REACH = frozenset({"__func__", "__class__", "__self__", "__get__", "__mro__", "__bases__", "__base__", "__subclasses__"})


def _bindings(tree) -> tuple[dict, dict, bool]:
    """({name: set of distinct binding events}, {name: the binding events that are direct module-body statements}, has a star import)."""
    events: dict = {}
    direct: dict = {}
    star = False

    def add(name: str, key, top: bool):
        events.setdefault(name, set()).add(key)
        if top:
            direct.setdefault(name, set()).add(key)

    def visit(node, top: bool):
        nonlocal star
        if isinstance(node, _DEFS):
            add(node.name, id(node), top)
            a = getattr(node, "args", None)
            heads = [*node.decorator_list, *getattr(node, "bases", []), *(k.value for k in getattr(node, "keywords", [])),
                     *([*a.defaults, *(d for d in a.kw_defaults if d is not None)] if a is not None else [])]
            for h in heads:  # these run at module level: a walrus in them binds a module name
                visit(h, False)
            return
        if isinstance(node, ast.Lambda):
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for al in node.names:
                if al.name == "*":
                    star = True
                    continue
                name = al.asname or al.name.split(".")[0]
                # the same name bound twice to the same object (`import os` and `import os.path`) is one binding
                origin = (("module", al.name if al.asname else name) if isinstance(node, ast.Import) else ("from", node.level, node.module, al.name))
                add(name, origin, top)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            add(node.id, id(node), top)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            add(node.name, id(node), False)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            add(node.name, id(node), False)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            add(node.rest, id(node), False)
        # a Name stored by a direct `x = ...` / `x: T = ...` is a direct binding; anything deeper is conditional
        for child in ast.iter_child_nodes(node):
            direct_target = top and ((isinstance(node, ast.Assign) and child in node.targets) or (isinstance(node, ast.AnnAssign) and child is node.target))
            visit(child, direct_target)

    for st in tree.body:
        visit(st, True)
    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            for name in node.names:
                add(name, ("global", id(node)), False)
    return events, direct, star


def _scopes(table):
    yield table
    for child in table.get_children():
        yield from _scopes(child)


def _names_read(source: str, tree, roots: set) -> set:
    """The global (module or builtin) names reachable from the definitions called `roots`, transitively through same-module definitions."""
    defs: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, _DEFS):
            defs.setdefault(node.name, []).append(node)
    tables: dict = {}
    for t in _scopes(symtable.symtable(source, "<certificate>", "exec")):
        tables.setdefault((t.get_name(), t.get_lineno()), []).append(t)
    seen: set = set()
    names: set = set()
    todo = list(roots)
    while todo:
        name = todo.pop()
        for node in defs.get(name, []):
            if id(node) in seen:
                continue
            seen.add(id(node))
            found: set = set()
            lines = {node.lineno, *(d.lineno for d in node.decorator_list)}
            for line in lines:
                for table in tables.get((node.name, line), []):
                    for scope in _scopes(table):
                        found |= {s.get_name() for s in scope.get_symbols() if s.is_global() and (s.is_referenced() or s.is_declared_global())}
            a = getattr(node, "args", None)
            heads = [*node.decorator_list, *getattr(node, "bases", []), *(k.value for k in getattr(node, "keywords", []))]
            if a is not None:  # defaults and annotations are evaluated outside the function's own scope
                params = [*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg]
                heads += [*a.defaults, *(d for d in a.kw_defaults if d is not None), *(p.annotation for p in params if p is not None and p.annotation is not None)]
                if node.returns is not None:
                    heads.append(node.returns)
            for h in heads:
                found |= {n.id for n in ast.walk(h) if isinstance(n, ast.Name)}
            todo.extend(found - names)
            names |= found
    return names


def _module_statement_reads(trees) -> set:
    """Names read by module-level statements whose text differs between the versions (identical statements run identically)."""
    sides = []
    for tree in trees:
        sides.append({ast.dump(st): st for st in tree.body if not isinstance(st, (*_DEFS, ast.Import, ast.ImportFrom))})
    out: set = set()
    for here, there in ((sides[0], sides[1]), (sides[1], sides[0])):
        for key, st in here.items():
            if key not in there:
                out |= {n.id for n in ast.walk(st) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    return out


_READ_ONLY_CALLS = frozenset({"sorted", "list", "dict", "len", "tuple", "set", "frozenset", "iter", "any", "all", "repr", "str"})
_READ_ONLY_METHODS = frozenset({"get", "keys", "values", "items", "copy"})


def _read_only_use(node, parent) -> bool:
    """A namespace handle (`vars(x)` / `x.__dict__`) used only to READ: subscripted for a value, asked `.get/.keys/.values/.items/.copy`, iterated, tested with `in`,
    or handed to a builtin that copies or measures it. Anything else (an assignment, an argument to another function, a return, a container element) lets the
    handle be written through later, in a place this scan does not follow."""
    if isinstance(parent, ast.Subscript) and parent.value is node:
        return isinstance(parent.ctx, ast.Load)
    if isinstance(parent, ast.Attribute) and parent.value is node:
        return parent.attr in _READ_ONLY_METHODS
    if isinstance(parent, ast.Call):
        return isinstance(parent.func, ast.Name) and parent.func.id in _READ_ONLY_CALLS and node in parent.args
    if isinstance(parent, ast.Compare):
        return node in parent.comparators and all(isinstance(op, (ast.In, ast.NotIn)) for op in parent.ops)
    if isinstance(parent, (ast.For, ast.AsyncFor, ast.comprehension)):
        return parent.iter is node
    return False


def _escaping_classes(trees) -> set:
    """Names of classes of the scanned tree whose class object is used in any way other than being called to make an instance or tested with isinstance /
    issubclass: `C.method(obj, ...)`, `C.method.__func__`, an alias, an argument. Such a class can run a method with a receiver that is NOT one of its instances.
    A class escapes when any class derived from it (by a base name) escapes: the method may be inherited."""
    classes: dict = {}
    for _, tree in trees:
        for n in ast.walk(tree):
            if isinstance(n, ast.ClassDef):
                classes.setdefault(n.name, set()).update(b.id for b in n.bases if isinstance(b, ast.Name))
    escaping: set = set()
    for _, tree in trees:
        for n in ast.walk(tree):  # the class object (or the bare function behind a bound method) reached WITHOUT naming the class
            if isinstance(n, ast.Attribute) and n.attr in _CLASS_REACH:
                return set(classes)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                if n.func.id == "super" or (n.func.id == "type" and len(n.args) == 1):
                    return set(classes)
                if n.func.id == "getattr" and (len(n.args) < 2 or not (isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str)) or n.args[1].value.startswith("__")):
                    return set(classes)
    for _, tree in trees:
        parents = {id(c): p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in classes):
                continue
            p = parents.get(id(n))
            if isinstance(p, ast.Call) and p.func is n:
                continue  # C(...): an instance
            if isinstance(p, ast.Call) and isinstance(p.func, ast.Name) and p.func.id in ("isinstance", "issubclass") and n in p.args[1:]:
                continue
            if isinstance(p, ast.ClassDef) and n in p.bases:
                continue  # judged through the subclass
            escaping.add(n.id)
    changed = True
    while changed:  # a method of a base can run under the derived class
        changed = False
        for name in list(escaping):
            for base in classes.get(name, ()):
                if base not in escaping:
                    escaping.add(base)
                    changed = True
    return escaping


def _outside_write(trees, names: set) -> str:
    """A file of the scanned tree writing one of `names` as an attribute, by setattr / delattr, or through a `__dict__` / `vars()` mapping; '' when none.

    An attribute store through `self` / `cls` is exempt ONLY inside a method (a def directly in a class body whose FIRST parameter is that name) of a class that never
    escapes (see `_escaping_classes`); a plain function whose parameter happens to be called `self` is an ordinary receiver. Any store to `__class__` of a receiver
    that is not such a `self` is refused: it can turn a module into an instance of a class that carries a writer."""
    escaping = _escaping_classes(trees)

    def scan(label, node, own, parent):
        """`own`: the receiver name that is exempt here ('' when none); `parent`: the node that contains `node`."""
        def receiver(x) -> bool:
            return isinstance(x, ast.Name) and x.id == own

        def namespace(x) -> bool:
            return (isinstance(x, ast.Attribute) and x.attr == "__dict__" and not receiver(x.value)) or (
                isinstance(x, ast.Call) and isinstance(x.func, ast.Name) and x.func.id == "vars" and bool(x.args) and not receiver(x.args[0]))

        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)) and not receiver(node.value) and (node.attr in names or node.attr == "__class__"):
            return f"{label}: attribute store {node.attr}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("setattr", "delattr") and len(node.args) >= 2 and not receiver(node.args[0]):
            if not isinstance(node.args[1], ast.Constant) or node.args[1].value in names:
                return f"{label}: {node.func.id}"
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)) and namespace(node.value):
            return f"{label}: write through __dict__ / vars()"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("update", "setdefault", "pop", "__setitem__") and namespace(node.func.value):
            return f"{label}: __dict__ / vars() {node.func.attr}"
        if namespace(node) and not _read_only_use(node, parent):
            return f"{label}: a namespace handle (vars() / __dict__) is bound, stored or passed on: what is written through it cannot be followed"
        return ""

    def visit(label, node, own, parent=None):
        why = scan(label, node, own, parent)
        if why:
            return why
        for child in ast.iter_child_nodes(node):
            inner = own
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                inner = ""  # a nested function or lambda: its own parameters are ordinary names
                if isinstance(node, ast.ClassDef) and node.name not in escaping and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    first = [*child.args.posonlyargs, *child.args.args][:1]
                    if first and first[0].arg in _RECEIVERS:
                        inner = first[0].arg
            elif isinstance(child, ast.ClassDef):
                inner = ""
            why = visit(label, child, inner, node)
            if why:
                return why
        return ""

    for label, tree in trees:
        why = visit(label, tree, "")
        if why:
            return why
    return ""


def refusal(base_src: str, post_src: str, function: str, rules: tuple, scan_trees, dynamic_reason) -> str:
    """Why the module's names cannot be taken at face value, or '' when every one of them has a single unconditional binding."""
    try:
        trees = [ast.parse(base_src), ast.parse(post_src)]
        roots = {function.split(".")[0], function.split(".")[-1]}
        read: set = _module_statement_reads(trees)
        for source, tree in zip((base_src, post_src), trees):
            read |= _names_read(source, tree, roots | read)
    except (SyntaxError, ValueError, RecursionError) as e:
        return "the module's names could not be analysed: " + type(e).__name__
    if "NORM" in rules:
        read |= _REWRITE_BUILTINS
    for side, tree in zip(("base", "post"), trees):
        why = dynamic_reason(tree)
        if why:
            return f"{side} module can rebind its own names at run time ({why})"
        events, direct, star = _bindings(tree)
        if star:
            return f"{side} module has a star import: any name may be bound by it"
        for name in sorted(read):
            bound = events.get(name, set())
            if name.startswith("__") and name.endswith("__") and not bound:
                continue
            if bound and hasattr(builtins, name):
                return f"{side} module binds the builtin name `{name}`: a rule may read it as the builtin"
            if bound and not (len(bound) == 1 and bound == direct.get(name)):
                return f"{side} module binds `{name}` more than once or conditionally"
    module_level = {name for tree in trees for name in _bindings(tree)[0]}
    watched = {n for n in read if n in module_level or hasattr(builtins, n)}
    why = _outside_write(scan_trees or (), watched)
    if why:
        return "another file can rebind a name the target reads (" + why + ")"
    return ""
