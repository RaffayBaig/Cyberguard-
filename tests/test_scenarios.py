# File: tests/test_scenarios.py
# Purpose: automatic checks for CyberGuard. It runs every scenario and compares the decision
# with the expected one, checks that forward and backward chaining agree, and tests the
# frames, the Description Logic reasoner and the engine.
# Run it before the viva, every line must say ok.
#
# Usage (from the CyberGuard folder):
#   python tests/test_scenarios.py

import sys
import unittest
from pathlib import Path

# make "import engine" work when this file is started from anywhere
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.runner import evaluate, load_scenario, scenario_paths
from engine.decision import backward_decide
from engine.forward_chaining import forward_chain
from engine.terms import Rule
from knowledge import frames, logic_formulas
from knowledge.rules import RULES

SCENARIOS = [load_scenario(p) for p in scenario_paths()]


def scenario(number):
    return SCENARIOS[number - 1]


class ScenarioTests(unittest.TestCase):
    def test_there_are_scenarios(self):
        self.assertGreaterEqual(len(SCENARIOS), 6)

    def test_forward_decision_matches_expected(self):
        for sc in SCENARIOS:
            with self.subTest(sc["name"]):
                self.assertEqual(evaluate(sc, RULES)["decision"], sc["expected"])

    def test_backward_decision_matches_forward(self):
        for sc in SCENARIOS:
            with self.subTest(sc["name"]):
                ev = evaluate(sc, RULES)
                decision, _ = backward_decide(RULES, ev["all_facts"], ev["user"], ev["resource"])
                self.assertEqual(decision, ev["decision"])

    def test_every_rule_fires_in_some_scenario(self):
        used = set()
        for sc in SCENARIOS:
            used |= {entry[0] for entry in evaluate(sc, RULES)["trace"]}
        unused = [r.name for r in RULES if r.name not in used]
        self.assertEqual(unused, [], f"rules never used by any scenario: {unused}")


class FrameTests(unittest.TestCase):
    def test_default_reaches_the_engine(self):
        # scenario 2 does not give failed_attempts, the frame default (0) must become a fact
        ev = evaluate(scenario(2), RULES)
        self.assertIn(("failed_attempts", "sara", 0), ev["generated"])
        self.assertIn(("failed_attempts", "sara", 0), ev["all_facts"])

    def test_range_facet_rejects_bad_value(self):
        with self.assertRaises(ValueError):
            frames.make_instance("User", failed_attempts=500)

    def test_values_facet_rejects_bad_role(self):
        with self.assertRaises(ValueError):
            frames.make_instance("User", role="hacker")

    def test_child_frame_inherits_and_overrides(self):
        slots = frames.all_slots("Administrator")
        self.assertIn("failed_attempts", slots)           # inherited from User
        self.assertEqual(slots["role"]["default"], "admin")   # overridden default

    def test_demon_fires_for_many_failures(self):
        inst = frames.make_instance("User", failed_attempts=4)
        self.assertTrue(inst["demons"])
        self.assertFalse(frames.make_instance("User", failed_attempts=1)["demons"])


class LogicTests(unittest.TestCase):
    def test_subsumption_follows_the_chain(self):
        self.assertTrue(logic_formulas.is_subsumed("AdminOnlyResource", "Resource"))
        self.assertFalse(logic_formulas.is_subsumed("Resource", "CriticalResource"))

    def test_disjointness_is_inherited(self):
        self.assertTrue(logic_formulas.are_disjoint("Student", "Administrator"))
        self.assertTrue(logic_formulas.are_disjoint("AdminOnlyResource", "UnknownDevice"))
        self.assertFalse(logic_formulas.are_disjoint("Student", "User"))

    def test_abox_conflict_is_found(self):
        _, conflicts = logic_formulas.check_abox([("x", "Student"), ("x", "Administrator")])
        self.assertTrue(conflicts)
        _, conflicts = logic_formulas.check_abox([("x", "Student")])
        self.assertFalse(conflicts)


class EngineTests(unittest.TestCase):
    def test_trace_is_the_same_on_every_run(self):
        first = [entry[:3] for entry in evaluate(scenario(1), RULES)["trace"]]
        second = [entry[:3] for entry in evaluate(scenario(1), RULES)["trace"]]
        self.assertEqual(first, second)

    def test_unsafe_negation_is_an_error(self):
        bad = Rule("bad", ("p", "?X"), [("not", ("q", "?X")), ("r", "?X")])
        with self.assertRaises(ValueError):
            forward_chain([bad], [("r", "a")])

    def test_what_if_changes_the_decision(self):
        # scenario 1: fewer attempts alone is not enough, the device is still unknown
        sc = dict(scenario(1))
        sc["facts"] = [f for f in sc["facts"] if f[0] != "failed_attempts"] + [("failed_attempts", "ali", 2)]
        self.assertEqual(evaluate(sc, RULES)["decision"], "deny")
        # with a trusted device as well, the request is allowed
        self.assertEqual(evaluate(sc, RULES, [("trusted", "dev7")])["decision"], "allow")


if __name__ == "__main__":
    unittest.main(verbosity=2)