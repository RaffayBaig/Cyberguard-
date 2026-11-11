# File: engine/backward_chaining.py
# Purpose: goal-driven reasoning. It starts from a hypothesis (the goal), looks for a
# fact or a rule that proves it, and then tries to prove every condition of that rule.
# Every step is written into a trace so the demo can print the full proof tree.

from engine.terms import (unify, substitute, eval_compare, is_not, is_compare,
                          has_var, rename_rule, fmt)


class BackwardChainer:
    def __init__(self, rules, facts):
        self.rules = rules
        self.facts = list(dict.fromkeys(facts))   # remove duplicates, keep order
        self.rename_count = 0                     # counter used to rename rule variables
        self.trace = []

    def log(self, depth, message):
        # indentation shows how deep we are in the proof
        self.trace.append("  " * depth + message)

    def prove_all(self, goals, bindings, depth):
        # All goals must hold, left to right. The bindings found by one goal
        # are passed on to the next goal.
        if not goals:
            yield bindings
            return
        first, rest = goals[0], goals[1:]
        for new_bindings in self.prove(first, bindings, depth):
            yield from self.prove_all(rest, new_bindings, depth)

    def prove(self, goal, bindings, depth):
        # comparison: no search needed, just check the values
        if is_compare(goal):
            ok = eval_compare(goal, bindings)
            self.log(depth, f"CHECK {fmt(substitute(goal, bindings))} -> {ok}")
            if ok:
                yield bindings
            return

        # negation as failure: "not X" holds when X cannot be proved
        if is_not(goal):
            target = substitute(goal[1], bindings)
            if has_var(target):
                # an unbound variable here would give a wrong answer silently
                raise ValueError(f"unsafe negation, unbound variable in: {fmt(target)}")
            self.log(depth, f"NOT {fmt(target)} ?")
            proved = any(True for _ in self.prove(target, bindings, depth + 1))
            self.log(depth, f"NOT {fmt(target)} -> {not proved}")
            if not proved:
                yield bindings
            return

        self.log(depth, f"GOAL {fmt(substitute(goal, bindings))}")
        found = False

        # step 1: the goal may already be a known fact
        for fact in self.facts:
            new_bindings = unify(goal, fact, bindings)
            if new_bindings is not None:
                self.log(depth + 1, f"FACT {fmt(fact)}  (given)")
                found = True
                yield new_bindings

        # step 2: try every rule whose head matches the goal
        for rule in self.rules:
            self.rename_count += 1
            fresh = rename_rule(rule, self.rename_count)
            new_bindings = unify(goal, fresh.head, bindings)
            if new_bindings is None:
                continue
            self.log(depth + 1, f"RULE {rule.name}")
            # the rule body becomes the new list of sub-goals
            for final_bindings in self.prove_all(fresh.body, new_bindings, depth + 2):
                self.log(depth + 1, f"PROVED {fmt(substitute(goal, final_bindings))} by {rule.name}")
                found = True
                yield final_bindings

        # nothing matched: record the failure so the trace shows the dead end
        if not found:
            self.log(depth + 1, f"FAILED {fmt(substitute(goal, bindings))}")


def prove_goal(rules, facts, goal):
    # returns (proved, bindings, trace). It stops at the first proof found.
    chainer = BackwardChainer(rules, facts)
    result = next(chainer.prove(goal, {}, 0), None)
    return result is not None, result, chainer.trace


def print_trace(trace):
    for line in trace:
        print(line)