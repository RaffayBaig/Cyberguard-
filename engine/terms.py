# File: engine/terms.py
# Purpose: core building blocks of the reasoning engine. It defines the Rule class,
# variables, unification and the helpers used to print traces.
# Forward and backward chaining both import from this file.

# A fact is a tuple, for example ("role", "ali", "student").
# A variable is a string that starts with "?", for example "?U".
# A condition inside a rule body is one of three things:
#   a normal fact pattern     ("failed_attempts", "?U", "?N")
#   a comparison              (">=", "?N", 3)
#   a negation                ("not", ("trusted", "?D"))

# comparison operators allowed in rule bodies
OPS = {
    ">=": lambda a, b: a >= b,
    ">":  lambda a, b: a > b,
    "<=": lambda a, b: a <= b,
    "<":  lambda a, b: a < b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
}


class Rule:
    # One Horn clause: head :- body
    # stratum is the level at which the rule runs. Rules that use "not" must run
    # after the facts they negate are fully derived, so they get a higher stratum.
    def __init__(self, name, head, body, stratum=0, doc=""):
        self.name = name
        self.head = head
        self.body = body
        self.stratum = stratum
        self.doc = doc

    def is_pure_horn(self):
        # a rule with "not" in the body is Horn plus negation as failure
        return not any(is_not(c) for c in self.body)

    def __repr__(self):
        return f"{self.name}: {fmt(self.head)} :- " + ", ".join(fmt(c) for c in self.body)


def group_by_stratum(rules):
    # split the rule list into groups, lowest stratum first
    levels = sorted({r.stratum for r in rules})
    return [[r for r in rules if r.stratum == level] for level in levels]


def is_var(t):
    return isinstance(t, str) and t.startswith("?")


def has_var(t):
    # True if there is still an unbound variable anywhere inside the term
    if is_var(t):
        return True
    if isinstance(t, tuple):
        return any(has_var(item) for item in t)
    return False


def is_not(cond):
    return cond[0] == "not"


def is_compare(cond):
    return cond[0] in OPS


def walk(t, b):
    # follow a chain of bindings until we reach a real value (?X -> ?Y -> ali)
    while is_var(t) and t in b:
        t = b[t]
    return t


def unify(x, y, b):
    # Try to make two terms equal. Returns the updated bindings, or None if they cannot match.
    # The bindings dict is copied and never changed in place, so backtracking is safe.
    x = walk(x, b)
    y = walk(y, b)
    if x == y:
        return b
    if is_var(x):
        return {**b, x: y}
    if is_var(y):
        return {**b, y: x}
    if isinstance(x, tuple) and isinstance(y, tuple) and len(x) == len(y):
        for a, c in zip(x, y):
            b = unify(a, c, b)
            if b is None:
                return None
        return b
    return None


def substitute(t, b):
    # replace every bound variable in a term with its value
    t = walk(t, b)
    if isinstance(t, tuple):
        return tuple(substitute(item, b) for item in t)
    return t


def eval_compare(cond, b):
    # a comparison can only be checked when both sides already have real values
    op, left, right = cond
    left = substitute(left, b)
    right = substitute(right, b)
    if is_var(left) or is_var(right):
        return False
    return OPS[op](left, right)


def _rename_term(t, n):
    if is_var(t):
        return f"{t}_{n}"
    if isinstance(t, tuple):
        return tuple(_rename_term(item, n) for item in t)
    return t


def rename_rule(rule, n):
    # Backward chaining can use the same rule many times in one proof.
    # Giving every use its own variable names (?U becomes ?U_1) stops the bindings clashing.
    return Rule(rule.name,
                _rename_term(rule.head, n),
                [_rename_term(c, n) for c in rule.body],
                rule.stratum,
                rule.doc)


def fmt(t):
    # make a fact readable for traces: ("role", "ali", "student") -> role(ali, student)
    if isinstance(t, tuple):
        if t and t[0] == "not":
            return "not " + fmt(t[1])
        if t and t[0] in OPS:
            return f"{t[1]} {t[0]} {t[2]}"
        return f"{t[0]}(" + ", ".join(fmt(item) for item in t[1:]) + ")"
    return str(t)