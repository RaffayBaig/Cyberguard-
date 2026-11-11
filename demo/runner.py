# File: demo/runner.py
# Purpose: runs one scenario through the six stages of the demo
# (frames, semantic network, FOL and DL, Horn rules, forward chaining, backward chaining)
# and ends with the final decision and the reason chain.
# It only decides what to show. The reasoning itself is done by the engine/ and knowledge/ files.

import json
from pathlib import Path

from demo import ui
from engine.decision import backward_decide, explain, final_decision
from engine.forward_chaining import forward_chain, print_trace as print_forward
from engine.terms import fmt
from knowledge import frames, logic_formulas, semantic_net
from knowledge.facts import STATIC_FACTS, print_facts
from knowledge.rules import print_rules

ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = ROOT / "scenarios"
TOTAL_STAGES = 6


# ---- loading and preparing a scenario ----

def scenario_paths():
    return sorted(SCENARIO_DIR.glob("*.json"))


def load_scenario(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    # JSON has lists, the engine works with tuples
    data["facts"] = [tuple(fact) for fact in data["facts"]]
    data["goal"] = tuple(data["goal"])
    data["path"] = str(path)
    return data


def evaluate(scenario, rules, extra_static=()):
    # Runs the whole reasoning for a scenario without printing anything.
    # Frames first (defaults become facts), then forward chaining, then the decision.
    static = STATIC_FACTS + list(extra_static)
    instances, generated = frames.instantiate(scenario["facts"], static)
    all_facts = list(dict.fromkeys(static + scenario["facts"] + generated))
    facts, trace = forward_chain(rules, all_facts)
    user, resource = scenario["goal"][1], scenario["goal"][2]
    return {
        "static": static, "instances": instances, "generated": generated,
        "all_facts": all_facts, "facts": facts, "trace": trace,
        "user": user, "resource": resource,
        "decision": final_decision(facts, user, resource),
    }


# ---- the six stages ----

def stage_frames(scenario, ev):
    ui.stage_header(1, TOTAL_STAGES, "FRAMES")
    ui.note("A frame is a class that describes a concept. It has slots (attributes), facets "
            "(rules for a slot such as type, allowed values, range and a default value) and an "
            "is-a parent it inherits from. A script is the usual order of steps in a situation.")
    for name in frames.FRAMES:
        frames.print_frame(name)

    # frame architecture diagram (docs/frame_architecture.png), opened like the network diagram
    if frames.draw_frames():
        print(f"\nFrame architecture diagram saved to {frames.FRAME_DIAGRAM_PATH}")
        if not ui.AUTO:
            frames.open_image()
    else:
        print("\n(frame diagram skipped: run  pip install matplotlib)")
    ui.pause("Press Enter to see the script and the instances of this scenario")

    ui.subheading("Script")
    frames.print_script()

    ui.subheading("Instances built for this scenario (defaults are filled in automatically)")
    for inst in ev["instances"]:
        frames.print_instance(inst)
    if ev["generated"]:
        print()
        for fact in ev["generated"]:
            print(f"  failed_attempts was not given, the frame default gives the fact {fmt(fact)}")
    ui.pause("Press Enter for stage 2 (semantic network)")


def stage_semantic(scenario, ev):
    ui.stage_header(2, TOTAL_STAGES, "SEMANTIC NETWORK")
    ui.note("A semantic network is a graph of concepts joined by labelled links: is-a (a kind of), "
            "has-a (owns a property) and part-of (belongs to a bigger whole). Frames describe one "
            "concept in detail, the network shows how the concepts connect.")
    edges = semantic_net.instance_edges(ev["all_facts"])
    semantic_net.print_network(edges)

    if semantic_net.draw_network(edges):
        print(f"\nDiagram saved to {semantic_net.DIAGRAM_PATH}")
        if not ui.AUTO:
            semantic_net.open_image()
    else:
        print("\n(diagram skipped: run  pip install networkx matplotlib)")
    ui.pause("Press Enter for stage 3 (FOL and Description Logic)")


def stage_logic(scenario, ev):
    ui.stage_header(3, TOTAL_STAGES, "FIRST-ORDER LOGIC AND DESCRIPTION LOGIC")
    ui.note("First-Order Logic states every rule with variables and quantifiers (for all u, for all r). "
            "Description Logic describes the classes: A is subsumed by B means every A is a B, and "
            "disjoint means nothing can be both. The Horn rules in the next stage are these formulas "
            "written in a form the engine can run.")
    logic_formulas.print_fol()
    ui.pause("Press Enter to see the Description Logic axioms")

    edges = semantic_net.instance_edges(ev["all_facts"])
    logic_formulas.print_dl(semantic_net.instance_assertions(edges))
    ui.pause("Press Enter to see the limitations")

    ui.subheading("Limitations")
    logic_formulas.print_limitations()
    ui.pause("Press Enter for stage 4 (Horn clause knowledge base)")


def stage_horn(scenario, ev, rules):
    ui.stage_header(4, TOTAL_STAGES, "HORN CLAUSE KNOWLEDGE BASE")
    ui.note("A Horn clause has at most one positive conclusion: head :- condition1, condition2. "
            "That restriction makes reasoning fast. Rules with 'not' use negation as failure: "
            "something that cannot be proved is treated as false. Stratum is the level at which "
            "a rule runs, so 'not' is checked only after the facts it refers to are complete.")
    ui.subheading("Static facts")
    print_facts()
    ui.subheading("Rules")
    print_rules(rules)
    ui.subheading("Input facts of this scenario")
    for fact in scenario["facts"]:
        print(f"  {fmt(fact)}")
    for fact in ev["generated"]:
        print(f"  {fmt(fact)}   (frame default)")
    ui.pause("Press Enter for stage 5 (forward chaining)")


def stage_forward(scenario, ev):
    ui.stage_header(5, TOTAL_STAGES, "FORWARD CHAINING")
    ui.note("Forward chaining is data driven. It starts from the known facts, fires every rule whose "
            "conditions are true, adds the new fact, and repeats until nothing new can be derived.")
    print(f"Known facts at the start: {len(ev['all_facts'])} "
          f"({len(ev['static'])} static + {len(ev['all_facts']) - len(ev['static'])} from the scenario)\n")
    print_forward(ev["trace"])
    print(f"\nNo new fact can be derived. {len(ev['trace'])} new facts in total.")

    derived = sorted({f[3] for f in ev["facts"]
                      if f[0] == "decision" and f[1] == ev["user"] and f[2] == ev["resource"]})
    print(f"Decisions derived for {ev['user']} / {ev['resource']}: {', '.join(derived) or 'none'}")
    ui.pause("Press Enter for stage 6 (backward chaining)")


def stage_backward(scenario, ev, rules):
    ui.stage_header(6, TOTAL_STAGES, "BACKWARD CHAINING")
    ui.note("Backward chaining is goal driven. It starts from a hypothesis, for example "
            "decision(ali, student_db, deny), finds a rule that could prove it, and then tries to "
            "prove each condition of that rule. It stops when every branch ends in a known fact.")
    decision, attempts = backward_decide(rules, ev["all_facts"], ev["user"], ev["resource"])
    for goal, proved, trace in attempts:
        if proved:
            print(f"Goal: {fmt(goal)}\n")
            for line in trace:
                print(line)
            print()
            ui.good(f"PROVED: {fmt(goal)}")
        else:
            print(f"Goal: {fmt(goal)}  ->  cannot be proved, try the next decision\n")
    return decision


def stage_result(scenario, ev, backward_result):
    ui.subheading("Final result")
    decision = ev["decision"]
    print(f"Forward chaining decision : {decision.upper() if decision else 'NONE'}")
    print(f"Backward chaining decision: {backward_result.upper() if backward_result else 'NONE'}")
    if decision == backward_result:
        ui.good("Both methods agree.")
    else:
        ui.bad("The two methods disagree, check the rules.")

    if decision:
        print("\nWhy this decision (reason chain):")
        for line in explain(("decision", ev["user"], ev["resource"], decision), ev["trace"]):
            print("  " + line)

    expected = scenario.get("expected")
    passed = decision == expected
    print()
    (ui.good if passed else ui.bad)(
        f"FINAL DECISION: {decision.upper() if decision else 'NONE'}   "
        f"(expected {str(expected).upper()}: {'PASS' if passed else 'FAIL'})")
    return passed


# ---- entry point of the demo for one scenario ----

def run_scenario(scenario, rules):
    ui.banner(scenario["name"])
    print(scenario["description"])

    ev = evaluate(scenario, rules)
    stage_frames(scenario, ev)
    stage_semantic(scenario, ev)
    stage_logic(scenario, ev)
    stage_horn(scenario, ev, rules)
    stage_forward(scenario, ev)
    backward_result = stage_backward(scenario, ev, rules)
    return stage_result(scenario, ev, backward_result)