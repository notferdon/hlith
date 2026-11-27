# SPDX-License-Identifier: Apache-2.0
"""Turn one bounded symbolic countermodel into a candidate concrete call."""
import ast
import tokenize

from . import prove


_SAFE_CALL_BUILTINS = frozenset({"abs", "min", "max", "int", "bool"})
_SAFE_EXC_BUILTINS = frozenset({"ValueError", "TypeError", "ZeroDivisionError", "IndexError", "KeyError", "RuntimeError"})


def _small_function(path, name):
    if path is None or path.stat().st_size > 512 * 1024:
        return None
    with tokenize.open(path) as stream:
        tree = ast.parse(stream.read())
    targets = [st for st in tree.body if isinstance(st, ast.FunctionDef) and st.name == name]
    if len(targets) != 1:
        return None
    fn = targets[0]
    args = fn.args
    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    if not 1 <= len(params) <= 6 or args.vararg or args.kwarg or fn.decorator_list:
        return None
    if not all(isinstance(p.annotation, ast.Name) and p.annotation.id in ("bool", "int") for p in params):
        return None
    # Keep model generation cheap on the host. Names/calls outside this subset
    # remain the ordinary concrete checker's responsibility.
    allowed = (ast.If, ast.Return, ast.Raise, ast.Pass, ast.IfExp, ast.Assign, ast.AugAssign,
               ast.Name, ast.Load, ast.Store, ast.Constant, ast.Call,
               ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Mod, ast.FloorDiv,
               ast.Compare, ast.cmpop, ast.UnaryOp, ast.USub, ast.UAdd, ast.Not,
               ast.BoolOp, ast.And, ast.Or)
    nodes = [node for st in fn.body for node in ast.walk(st)]
    if len(nodes) > 180 or any(not isinstance(n, allowed) for n in nodes):
        return None
    for n in nodes:
        if isinstance(n, ast.Constant):
            if type(n.value) in (int, bool):
                if n.value.bit_length() > 128:
                    return None
            elif type(n.value) is str and len(n.value) <= 64:
                continue  # allow short exception message literals in `raise ValueError("...")`
            else:
                return None
        elif isinstance(n, ast.Call):
            if not (isinstance(n.func, ast.Name) and n.func.id in (_SAFE_CALL_BUILTINS | _SAFE_EXC_BUILTINS) and not n.keywords):
                return None
    return fn


def integer_seed(base_path, post_path, function):
    """Result uses the ordinary differential seed format. No model can decide a verdict."""
    try:
        base = _small_function(base_path, function)
        if base is None:
            return None
        post = _small_function(post_path, function)
        if post is None or ast.dump(base) == ast.dump(post):
            return None
        result = prove(ast.unparse(base), ast.unparse(post), function, modes=("typed",), budget_ms=500)
        if result.status != "different" or not result.hint:
            return None
        args = base.args
        params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        values = result.hint
        if any(p.arg not in values or type(values[p.arg]) not in (int, bool) or values[p.arg].bit_length() > 256 for p in params):
            return None
        return ([values[p.arg] for p in (*args.posonlyargs, *args.args)],
                {p.arg: values[p.arg] for p in args.kwonlyargs}, "symbolic-countermodel")
    except (OSError, SyntaxError, UnicodeError, ValueError, RecursionError):
        return None
