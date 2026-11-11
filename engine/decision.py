# File: engine/decision.py
# Purpose: turns the derived facts into one final decision (deny, flag or allow)
# and builds the "why" explanation from the forward chaining trace.
# It also runs backward chaining over the three possible decisions in priority order.

import re

from engine.terms import fmt, is_not, is_compare
from engine.backward_chaining import prove_goal

# if more than one decision is derived, the first one in this list wins
PRIORITY = ["deny", "flag", "allow"]


def final_decision(facts, user, resource):
    # collect every decision derived for this user and resource, then pick by priority
    derived = {f[3] for f in facts
               if f[0] == "decision" and f[1] == user and f[2] == resource}
    for level in PRIORITY:
        if level in derived:
            return level
    return None


def clean_trace(lines):
    # backward chaining renames rule variables (?D becomes ?D_15),
    # this removes the number again so the trace is easy to read
    return [re.sub(r"(\?[A-Za-z]+)_\d+", r"\1", line) for line in lines]


def backward_decide(rules, facts, user, resource):
    # Goal-driven version of the decision: try to prove deny first, then flag, then allow.
    # The first goal that can be proved is the decision.
    # attempts keeps (goal, proved, trace) for every try, so the demo can show them.
    attempts = []
    for level in PRIORITY:
        goal = ("decision", user, resource, level)
        proved, _, trace = prove_goal(rules, facts, goal)
        attempts.append((goal, proved, clean_trace(trace)))
        if proved:
            return level, attempts
    return None, attempts


def explain(fact, trace):
    # Builds the reason chain of a derived fact, using the forward chaining trace.
    # Each derived fact is followed back to the rule and the conditions that created it,
    # until only given facts are left.
    derivations = {entry[2]: (entry[0], entry[3]) for entry in trace}
    lines = []

    def walk_fact(f, depth):
        pad = "  " * depth
        if f not in derivations:
            lines.append(f"{pad}{fmt(f)}   [given fact]")
            return
        rule_name, used = derivations[f]
        lines.append(f"{pad}{fmt(f)}   <= {rule_name}")
        for cond in used:
            if is_compare(cond):
                lines.append(f"{pad}  {fmt(cond)}   [comparison is true]")
            elif is_not(cond):
                lines.append(f"{pad}  {fmt(cond)}   [cannot be proved, so the 'not' holds]")
            else:
                walk_fact(cond, depth + 1)

    walk_fact(fact, 0)
    return lines