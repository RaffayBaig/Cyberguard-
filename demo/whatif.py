# File: demo/whatif.py
# Purpose: live "what if" mode for the demo. The presenter changes one fact (the number of
# failed attempts, or whether the device is trusted), the reasoning runs again, and the
# decision before and after is shown side by side. It proves the system really reasons
# from the facts and the decision is not hardcoded.

from demo import ui
from demo.runner import evaluate
from engine.decision import explain
from engine.forward_chaining import print_trace as print_forward
from engine.terms import fmt
from knowledge import frames


def find_value(facts, name, user):
    # first value of a fact like failed_attempts(user, N)
    for f in facts:
        if f[0] == name and f[1] == user:
            return f[2]
    return None


def find_device(facts, user):
    for f in facts:
        if f[0] == "login" and f[1] == user:
            return f[2]
    return None


def run(scenario, rules):
    user, resource = scenario["goal"][1], scenario["goal"][2]
    before = evaluate(scenario, rules)
    device = find_device(before["all_facts"], user)
    current = find_value(before["all_facts"], "failed_attempts", user) or 0

    ui.banner("WHAT-IF: change a fact and run the reasoning again")
    ui.note("The rules stay exactly the same. We only change one input fact and the engine "
            "derives the decision again from scratch.")
    print(f"Current situation: {user} asks for {resource} from {device}, "
          f"failed attempts = {current}, decision = {before['decision'].upper()}\n")

    # new number of failed attempts (the range facet of the frame checks the value)
    new_attempts = current
    answer = ui.ask(f"New number of failed attempts (Enter keeps {current}): ", str(current))
    try:
        new_attempts = int(answer)
        frames.make_instance("User", failed_attempts=new_attempts)
    except ValueError as error:
        ui.bad(f"Not accepted ({error}). Keeping {current}.")
        new_attempts = current

    # trusted device, only asked when the device is not trusted yet
    extra_static = []
    if device and ("trusted", device) not in before["static"]:
        answer = ui.ask(f"Make device {device} trusted? y/n (Enter = no): ", "n")
        if answer.lower().startswith("y"):
            extra_static.append(("trusted", device))

    changed = dict(scenario)
    changed["facts"] = [f for f in scenario["facts"]
                        if not (f[0] == "failed_attempts" and f[1] == user)]
    changed["facts"].append(("failed_attempts", user, new_attempts))
    after = evaluate(changed, rules, extra_static)

    ui.subheading("Forward chaining on the changed facts")
    if after["trace"]:
        print_forward(after["trace"])
    else:
        print("No rule fired.")

    ui.subheading("Result")
    print(f"Before: failed attempts = {current}, device trusted = "
          f"{('trusted', device) in before['static']}  ->  {before['decision'].upper()}")
    print(f"After : failed attempts = {new_attempts}, device trusted = "
          f"{('trusted', device) in after['static']}  ->  "
          f"{after['decision'].upper() if after['decision'] else 'NONE'}")
    if after["decision"] != before["decision"]:
        ui.good("The decision changed because the facts changed.")
    else:
        print("The decision is the same. Another rule still supports it.")

    if after["decision"]:
        print("\nWhy:")
        for line in explain(("decision", user, resource, after["decision"]), after["trace"]):
            print("  " + line)