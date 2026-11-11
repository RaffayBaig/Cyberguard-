# File: engine/forward_chaining.py
# Purpose: data-driven reasoning. It starts from the known facts, fires every rule
# whose conditions hold, adds the new facts, and repeats until nothing new appears.
# Every firing is saved in a trace so the demo can print it step by step.

from engine.terms import (unify, substitute, eval_compare, is_not, is_compare,
                          has_var, fmt, group_by_stratum)


def match_conditions(conditions, facts, bindings):
    # Yields every set of bindings that satisfies all conditions, checked left to right.
    # The bindings found by one condition are passed on to the next one.
    if not conditions:
        yield bindings
        return

    first, rest = conditions[0], conditions[1:]

    if is_compare(first):
        # comparison: no new bindings, it only passes or fails
        if eval_compare(first, bindings):
            yield from match_conditions(rest, facts, bindings)
        return

    if is_not(first):
        # negation as failure: passes only when the fact is not known
        target = substitute(first[1], bindings)
        if has_var(target):
            # a variable that is still unbound would give a wrong answer silently
            raise ValueError(f"unsafe negation, unbound variable in: {fmt(target)}")
        if target not in facts:
            yield from match_conditions(rest, facts, bindings)
        return

    # normal condition: try to unify it with every known fact
    for fact in list(facts):
        new_bindings = unify(first, fact, bindings)
        if new_bindings is not None:
            yield from match_conditions(rest, facts, new_bindings)


def forward_chain(rules, initial_facts, strata=None):
    # Runs the rules group by group (strata). A rule with "not" must only run after
    # the facts it negates are completely derived, otherwise the rule order would
    # change the result.
    if strata is None:
        strata = group_by_stratum(rules)

    # a dict keeps insertion order, so the trace is the same on every run
    facts = dict.fromkeys(initial_facts)
    trace = []   # each entry: (rule name, used conditions as text, new fact, used conditions)

    for group in strata:
        changed = True
        while changed:
            changed = False
            for rule in group:
                for bindings in match_conditions(rule.body, facts, {}):
                    new_fact = substitute(rule.head, bindings)
                    if new_fact not in facts:
                        facts[new_fact] = None
                        used = [substitute(c, bindings) for c in rule.body]
                        trace.append((rule.name, [fmt(u) for u in used], new_fact, used))
                        changed = True

    return facts, trace


def print_trace(trace):
    for step, (rule_name, used, new_fact, _) in enumerate(trace, 1):
        print(f"[FORWARD {step:>2}] {rule_name}: {' + '.join(used)}  =>  {fmt(new_fact)}")