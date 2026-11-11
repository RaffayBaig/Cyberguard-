# File: main.py
# Purpose: entry point of CyberGuard and the menu used during the demo.
# For every scenario it shows: stage 0 (problem and roadmap), the six reasoning stages
# (demo/runner.py), a conclusion screen with a colour coded verdict, and the what-if step.
#
# Usage:
#   python main.py              menu (normal demo)
#   python main.py 2            run scenario 2 directly
#   python main.py all          check all scenarios and print a summary table
#   python main.py 1 --auto     run without pauses (for testing or for the report output)

import argparse
import os
import shutil
import sys

from demo import ui, whatif
from demo.runner import evaluate, load_scenario, run_scenario, scenario_paths
from engine.decision import backward_decide
from knowledge.rules import RULES


TEAM = [
    ("Abrar Shakeel Ghoury", "Frames and Semantic Network"),
    ("Mirza Abdul Raffay Baig", "First-Order Logic and Description Logic"),
    ("Amna Amjad", "Horn clauses and Forward Chaining"),
    ("Umair Hasan", "Backward Chaining and Decision"),
]

# the six stages and the team member (index in TEAM) who explains each of them
ROADMAP = [
    ("Stage 1", "Frames and script", 0),
    ("Stage 2", "Semantic network", 0),
    ("Stage 3", "First-Order Logic and Description Logic", 1),
    ("Stage 4", "Horn clause knowledge base", 2),
    ("Stage 5", "Forward chaining", 2),
    ("Stage 6", "Backward chaining and final decision", 3),
]

# big letters for the title, every glyph is 5 columns wide and 5 rows tall
LETTERS = {
    "C": ["█████", "█    ", "█    ", "█    ", "█████"],
    "Y": ["█   █", "█   █", " ███ ", "  █  ", "  █  "],
    "B": ["████ ", "█   █", "████ ", "█   █", "████ "],
    "E": ["█████", "█    ", "████ ", "█    ", "█████"],
    "R": ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
    "G": ["█████", "█    ", "█  ██", "█   █", "█████"],
    "U": ["█   █", "█   █", "█   █", "█   █", "█████"],
    "A": [" ███ ", "█   █", "█████", "█   █", "█   █"],
    "D": ["████ ", "█   █", "█   █", "█   █", "████ "],
}
ROW_COLORS = ["cyan", "cyan", "cyan", "green", "green"]

DECISION_COLOR = {"deny": "red", "flag": "yellow", "allow": "green"}
BOX_WIDTH = 76


# ---- screen helpers ----

def screen_width():
    return max(shutil.get_terminal_size((100, 30)).columns, 80)


def clear_screen():
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")


def centered(text, color=None):
    text = text.center(screen_width())
    print(ui.paint(text, color) if color else text)


def big_text(word):
    rows = [""] * 5
    for ch in word:
        for i in range(5):
            rows[i] += LETTERS[ch][i] + " "
    return [r.rstrip() for r in rows]


def decision_text(decision, width=0):
    # a decision word in its own colour (red deny, yellow flag, green allow)
    label = decision.upper() if decision else "NONE"
    return ui.paint(label.ljust(width), DECISION_COLOR.get(decision, "grey"))


def boxed(lines, box_width=BOX_WIDTH, color="cyan"):
    # lines are (plain text, painted text). The plain text is used to measure the padding,
    # because colour codes would break the alignment.
    margin = " " * ((screen_width() - box_width) // 2)
    inner = box_width - 4
    print(margin + ui.paint("╔" + "═" * (box_width - 2) + "╗", color))
    for plain, painted in lines:
        pad = " " * max(inner - len(plain), 0)
        print(margin + ui.paint("║", color) + " " + painted + pad + " " + ui.paint("║", color))
    print(margin + ui.paint("╚" + "═" * (box_width - 2) + "╝", color))


def center_line(plain, painted, box_width=BOX_WIDTH):
    # centre one line inside a box
    left = " " * max((box_width - 4 - len(plain)) // 2, 0)
    return left + plain, left + painted


def check_libraries():
    # the two diagrams need matplotlib, the rest of the demo does not
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        centered("Diagram library missing: run  pip install matplotlib", "yellow")
        print()


# ---- title and menu ----

def show_title():
    clear_screen()
    width = screen_width()
    print()
    for row, color in zip(big_text("CYBERGUARD"), ROW_COLORS):
        print(ui.paint(ui.paint(row.center(width), color), "bold"))
    print()
    centered("Cybersecurity Threat Detection & Access Control Reasoning System", "yellow")
    centered("Knowledge Representation & Reasoning  |  CT-351  |  NED University", "grey")
    centered("─" * 66, "cyan")
    print()


def show_menu(scenarios):
    inner = BOX_WIDTH - 4
    title = "SELECT A SCENARIO"
    lines = [center_line(title, ui.paint(title, "bold")), ("", "")]
    for i, sc in enumerate(scenarios, 1):
        expected = sc["expected"].upper()
        name = sc["name"][:inner - len(expected) - 10]
        left = f"[{i}]  {name}"
        gap = " " * max(inner - len(left) - len(expected), 2)
        plain = left + gap + expected
        painted = ui.paint(f"[{i}]", "cyan") + "  " + name + gap + decision_text(sc["expected"])
        lines.append((plain, painted))
    lines.append(("", ""))
    for key, text in [("A", "Check all scenarios (summary table)"),
                      ("T", "Team and who explains what"),
                      ("Q", "Quit")]:
        lines.append((f"[{key}]  {text}", ui.paint(f"[{key}]", "cyan") + "  " + text))
    boxed(lines)
    centered(f"{len(RULES)} rules  |  {len(scenarios)} scenarios  |  6 reasoning stages", "grey")
    centered("Tip: choose 1 for the full walkthrough, A to verify every scenario at once", "grey")


def show_team():
    print()
    centered("TEAM AND ROLES", "yellow")
    for name, part in TEAM:
        centered(f"{name}  -  {part}")
    print()


# ---- stage 0 and conclusion ----

def show_intro(scenario):
    # stage 0: domain, problem, why a normal database is not enough, and who explains what
    clear_screen()
    ui.banner("STAGE 0: PROBLEM AND MOTIVATION", "=")

    ui.subheading("Domain")
    print("  University cybersecurity access control. For every access request the\n"
          "  system must decide ALLOW, FLAG or DENY.")

    ui.subheading("Problem")
    print("  The decision depends on several facts together (failed attempts, device,\n"
          "  resource sensitivity, role), not on one stored value.")

    ui.subheading("Why a normal database is not enough")
    print("  - A database only returns stored data. high_risk or deny is never stored,\n"
          "    it has to be derived by rules.\n"
          "  - Rules are hard-coded in queries or application code, so changing a\n"
          "    rule means changing code.\n"
          "  - A database cannot explain WHY a decision was made. This system\n"
          "    prints the full reason chain.")

    ui.subheading("What we build")
    print("  Frames + Semantic Network (structure), First-Order Logic + Description\n"
          "  Logic (formal meaning), Horn clauses with Forward and Backward Chaining\n"
          "  (reasoning).")

    ui.subheading("Roadmap of this demo")
    for stage, title, who in ROADMAP:
        print(f"  {ui.paint(stage, 'cyan')}  {title:<42} {ui.paint(TEAM[who][0], 'grey')}")

    print(f"\n  Scenario to run: {ui.paint(scenario['name'], 'bold')}")
    ui.pause("Press Enter for stage 1 (frames)")


def other_scenario(scenario, scenarios):
    # a scenario with the opposite outcome (allow against deny), used as a contrast
    wanted = "deny" if scenario["expected"] == "allow" else "allow"
    return next((s for s in scenarios if s["expected"] == wanted), None)


def show_conclusion(scenario, rules, scenarios, passed):
    # closing screen: verdict card, both methods, rules used, contrast and limitation
    ev = evaluate(scenario, rules)
    backward, _ = backward_decide(rules, ev["all_facts"], ev["user"], ev["resource"])
    forward = ev["decision"]
    agree = forward == backward

    print()
    ui.banner("CONCLUSION", "=")

    label = (forward or "NONE").upper()
    verdict = f"FINAL DECISION:  {label}"
    verdict_painted = ui.paint("FINAL DECISION:  " + ui.paint(label, DECISION_COLOR.get(forward, "grey")), "bold")
    result = f"{'PASS' if passed else 'FAIL'}  (expected {scenario['expected'].upper()})"
    result_painted = ui.paint(result, "green" if passed else "red")
    boxed([("", ""),
           center_line(verdict, verdict_painted, 50),
           center_line(result, result_painted, 50),
           ("", "")], box_width=50, color=DECISION_COLOR.get(forward, "cyan"))

    print()
    print(f"  Forward chaining  (data driven) : {decision_text(forward)}")
    print(f"  Backward chaining (goal driven) : {decision_text(backward)}")
    (ui.good if agree else ui.bad)("  Both methods agree." if agree else "  The methods disagree, check the rules.")

    fired = [entry[0].split("_")[0] for entry in ev["trace"]]
    print(f"\n  Rules that fired, in order : {' -> '.join(fired) if fired else 'none'}")
    print(f"  New facts derived          : {len(ev['trace'])}   (none of them was stored, all were derived)")

    other = other_scenario(scenario, scenarios)
    if other is not None:
        got = evaluate(other, rules)["decision"]
        print(f"  Contrast                   : '{other['name']}' gives {decision_text(got)}")

    ui.subheading("Limitation")
    print("  'not' in rules R2, R7, R13 and R14 is negation as failure (closed-world\n"
          "  assumption), so the rule base is Horn clauses plus stratified negation,\n"
          "  not pure Horn.")
    ui.pause("Press Enter to continue")


# ---- running ----

def check_all(scenarios, rules):
    # runs the reasoning for every scenario and prints one summary line each
    ui.subheading("All scenarios")
    print(ui.paint(f"  {'#':<3}{'Scenario':<50}{'Expected':<10}{'Got':<8}{'Result':<8}Facts derived", "grey"))
    passed = 0
    for i, sc in enumerate(scenarios, 1):
        ev = evaluate(sc, rules)
        got = ev["decision"]
        ok = got == sc["expected"]
        passed += ok
        status = ui.paint("PASS", "green") if ok else ui.paint("FAIL", "red")
        name = sc["name"][:48]
        print(f"  {i:<3}{name:<50}{decision_text(sc['expected'], 10)}{decision_text(got, 8)}"
              f"{status}    {len(ev['trace'])}")
    print()
    (ui.good if passed == len(scenarios) else ui.bad)(f"Scenarios passed: {passed}/{len(scenarios)}")
    return passed == len(scenarios)


def extra_menu(scenario, rules):
    # live step that follows a finished scenario
    while True:
        print()
        ui.banner("LIVE STEP", "-")
        print(f"  {ui.paint('[W]', 'cyan')}  What-if: change a fact and reason again")
        print(f"  {ui.paint('[M]', 'cyan')}  Back to the menu")
        print(f"  {ui.paint('[Q]', 'cyan')}  Quit")
        choice = ui.ask("\nChoose: ", "m").lower()
        if choice == "w":
            whatif.run(scenario, rules)
        elif choice == "q":
            raise SystemExit(0)
        else:
            return


def play(scenario, rules, scenarios):
    show_intro(scenario)
    passed = run_scenario(scenario, rules)
    show_conclusion(scenario, rules, scenarios, passed)
    if not ui.AUTO:
        extra_menu(scenario, rules)
    return passed


def menu_loop(scenarios, rules):
    while True:
        show_title()
        check_libraries()
        show_menu(scenarios)
        try:
            choice = input("\n" + ui.paint("Your choice: ", "cyan")).strip().lower()
        except EOFError:
            return
        if choice in ("q", "quit", "exit"):
            return
        if choice == "a":
            check_all(scenarios, rules)
            ui.pause("Press Enter to go back to the menu")
        elif choice == "t":
            show_team()
            ui.pause("Press Enter to go back to the menu")
        elif choice.isdigit() and 1 <= int(choice) <= len(scenarios):
            play(scenarios[int(choice) - 1], rules, scenarios)
        else:
            print(ui.paint("Not a valid choice.", "red"))
            ui.pause("Press Enter to try again")


def main():
    # box drawing and logic symbols (█ ╔ ∀ ⊑ ⊓) crash some Windows terminals
    # that use a legacy code page, so force UTF-8 output
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="CyberGuard: rule-based security reasoning demo")
    parser.add_argument("scenario", nargs="?", help="scenario number, or 'all'")
    parser.add_argument("--auto", action="store_true", help="run without pauses")
    args = parser.parse_args()

    ui.init(auto=args.auto)
    scenarios = [load_scenario(p) for p in scenario_paths()]
    if not scenarios:
        print("No scenario files found in the scenarios folder.")
        return 1
    rules = list(RULES)

    if args.scenario is None:
        menu_loop(scenarios, rules)
        return 0
    if args.scenario.lower() == "all":
        return 0 if check_all(scenarios, rules) else 1
    if args.scenario.isdigit() and 1 <= int(args.scenario) <= len(scenarios):
        return 0 if play(scenarios[int(args.scenario) - 1], rules, scenarios) else 1
    parser.error(f"scenario must be 1 to {len(scenarios)} or 'all'")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nDemo stopped.")
        sys.exit(130)