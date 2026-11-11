# File: knowledge/frames.py
# Purpose: frame-based knowledge of CyberGuard. A frame is a class with slots (attributes),
# facets (rules about a slot: type, allowed values, range, default, demon) and an is-a parent.
# This file also holds the Login script and the code that builds frame instances
# from a scenario, so the defaults really feed the reasoning engine.
# It can also draw the frame architecture diagram (docs/frame_architecture.png).

# Slot facets used here:
#   type      string, integer, boolean, or the name of another frame
#   values    the only values the slot may take
#   default   value used when nothing is given
#   range     (low, high) limits for a number
#   multiple  the slot can hold more than one value
#   if_added  name of a demon (a small procedure) that runs when a value is stored

import os
import subprocess
import sys
from pathlib import Path

FRAMES = {
    "User": {
        "is_a": None,
        "slots": {
            "name":            {"type": "string"},
            "role":            {"type": "string",
                                "values": ["student", "faculty", "admin", "it_staff"],
                                "default": "student"},
            "failed_attempts": {"type": "integer", "default": 0, "range": (0, 100),
                                "if_added": "warn_many_failures"},
            "uses":            {"type": "Device", "multiple": True},
            "requests":        {"type": "Resource", "multiple": True},
        },
    },
    # child frames inherit every slot of User and only override the role default
    "Student":       {"is_a": "User", "slots": {"role": {"default": "student"}}},
    "Faculty":       {"is_a": "User", "slots": {"role": {"default": "faculty"}}},
    "Administrator": {"is_a": "User", "slots": {"role": {"default": "admin"}}},
    "ITStaff":       {"is_a": "User", "slots": {"role": {"default": "it_staff"}}},

    "Device": {
        "is_a": None,
        "slots": {
            "device_id":  {"type": "string"},
            "trust":      {"type": "string", "values": ["trusted", "unknown"], "default": "unknown"},
            "management": {"type": "string", "values": ["managed", "unmanaged"], "default": "unmanaged"},
        },
    },
    "Resource": {
        "is_a": None,
        "slots": {
            "resource_id": {"type": "string"},
            "sensitivity": {"type": "string",
                            "values": ["public", "internal", "sensitive", "critical"],
                            "default": "internal"},
            "admin_only":  {"type": "boolean", "default": False},
        },
    },
    "LoginEvent": {
        "is_a": None,
        "slots": {
            "user":       {"type": "User"},
            "device":     {"type": "Device"},
            "location":   {"type": "string", "default": "campus"},
            "suspicious": {"type": "boolean", "default": False},
        },
    },
    "Threat": {
        "is_a": None,
        "slots": {
            "kind":     {"type": "string",
                         "values": ["brute_force", "unauthorized", "account_compromise",
                                    "privilege_escalation"]},
            "target":   {"type": "User"},
            "severity": {"type": "string", "values": ["low", "medium", "high"], "default": "medium"},
        },
    },
}

# which frame to use for each role value
ROLE_FRAME = {
    "student":  "Student",
    "faculty":  "Faculty",
    "admin":    "Administrator",
    "it_staff": "ITStaff",
}

# A script is an ordered list of steps for a typical situation.
LOGIN_SCRIPT = {
    "name": "Login and Access Request",
    "steps": [
        {"step": 1, "action": "User enters credentials",
         "check": "count failed_attempts, rule R1 (3 or more)"},
        {"step": 2, "action": "System identifies the device",
         "check": "trusted list lookup, rules R2 and R3"},
        {"step": 3, "action": "User requests a resource",
         "check": "requests(U, R) and sensitivity(R, S)"},
        {"step": 4, "action": "System assesses risk and threats",
         "check": "rules R4 to R9"},
        {"step": 5, "action": "System decides deny, flag or allow",
         "check": "rules R10 to R14"},
    ],
}


# ---- demons (if-added procedures) ----

def warn_many_failures(value):
    if value >= 3:
        return f"demon: failed_attempts = {value}, rule R1 (brute force) will match"
    return None


DEMONS = {"warn_many_failures": warn_many_failures}


# ---- reading the frame hierarchy ----

def get_slot(frame_name, slot_name):
    # walk up the is-a chain: the child's facets override the parent's facets
    frame = FRAMES[frame_name]
    slot = dict(frame["slots"].get(slot_name, {}))
    if frame["is_a"]:
        inherited = get_slot(frame["is_a"], slot_name)
        inherited.update(slot)
        return inherited
    return slot


def all_slots(frame_name):
    # every slot of a frame, parent slots first, including inherited ones
    frame = FRAMES[frame_name]
    names = {}
    if frame["is_a"]:
        names.update(all_slots(frame["is_a"]))
    for slot_name in frame["slots"]:
        names[slot_name] = get_slot(frame_name, slot_name)
    return names


def describe_slot(spec):
    parts = []
    for key in ("type", "values", "default", "range", "multiple", "if_added"):
        if key in spec:
            value = spec[key]
            if key == "range":
                value = f"{value[0]}..{value[1]}"
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def print_frame(frame_name):
    frame = FRAMES[frame_name]
    parent = frame["is_a"]
    print(f"Frame: {frame_name}" + (f"  (is-a {parent})" if parent else ""))
    for slot_name, spec in frame["slots"].items():
        note = "   <- overrides inherited default" if parent and slot_name in all_slots(parent) else ""
        print(f"  {slot_name}: {describe_slot(spec)}{note}")
    if parent:
        inherited = [s for s in all_slots(parent) if s not in frame["slots"]]
        if inherited:
            print("  inherits: " + ", ".join(inherited))


def print_script():
    print(f"Script: {LOGIN_SCRIPT['name']}")
    for s in LOGIN_SCRIPT["steps"]:
        print(f"  {s['step']}. {s['action']}  ->  {s['check']}")


# ---- instances ----

def check_value(slot_name, spec, value):
    # enforce the facets of a slot, raise ValueError when a value breaks them
    kind = spec.get("type")
    if kind == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
        raise ValueError(f"{slot_name} must be an integer, got {value!r}")
    if kind == "boolean" and not isinstance(value, bool):
        raise ValueError(f"{slot_name} must be True or False, got {value!r}")
    if "values" in spec and value not in spec["values"]:
        raise ValueError(f"{slot_name} must be one of {spec['values']}, got {value!r}")
    if "range" in spec:
        low, high = spec["range"]
        if not low <= value <= high:
            raise ValueError(f"{slot_name} must be between {low} and {high}, got {value}")


def make_instance(frame_name, **given):
    # Builds one instance of a frame. Slots that are not given take their default value.
    slots = all_slots(frame_name)
    for name in given:
        if name not in slots:
            raise ValueError(f"frame {frame_name} has no slot {name}")

    values, defaults_used, demons = {}, [], []
    for slot_name, spec in slots.items():
        if slot_name in given:
            value = given[slot_name]
            check_value(slot_name, spec, value)
            demon = DEMONS.get(spec.get("if_added"))
            message = demon(value) if demon else None
            if message:
                demons.append(message)
        elif "default" in spec:
            value = spec["default"]
            defaults_used.append(slot_name)
        else:
            continue
        values[slot_name] = value
    return {"frame": frame_name, "values": values,
            "defaults_used": defaults_used, "demons": demons}


def print_instance(inst):
    print(f"Instance of {inst['frame']}")
    for slot_name, value in inst["values"].items():
        mark = "   (default)" if slot_name in inst["defaults_used"] else ""
        print(f"  {slot_name} = {value}{mark}")
    for message in inst["demons"]:
        print(f"  {message}")


def instantiate(scenario_facts, static_facts):
    # Builds frame instances for the users, devices and resources of a scenario.
    # If a scenario does not state failed_attempts, the frame default (0) is used
    # and returned as a generated fact, so the default really reaches the engine.
    instances, generated, seen = [], [], set()

    def role_of(user):
        for f in static_facts:
            if f[0] == "role" and f[1] == user:
                return f[2]
        return "student"

    def add(key, frame, **slots):
        if key not in seen:
            seen.add(key)
            inst = make_instance(frame, **slots)
            instances.append(inst)
            return inst

    for f in scenario_facts:
        if f[0] == "login":
            user, device = f[1], f[2]
            role = role_of(user)
            given = {"name": user, "role": role}
            stated = [x[2] for x in scenario_facts if x[0] == "failed_attempts" and x[1] == user]
            if stated:
                given["failed_attempts"] = stated[0]
            inst = add(("user", user), ROLE_FRAME.get(role, "User"), **given)
            if inst and not stated:
                generated.append(("failed_attempts", user, inst["values"]["failed_attempts"]))

            trust = "trusted" if ("trusted", device) in static_facts else "unknown"
            add(("device", device), "Device", device_id=device, trust=trust)
            add(("login", user, device), "LoginEvent", user=user, device=device)

        elif f[0] == "requests":
            resource = f[2]
            level = next((x[2] for x in static_facts
                          if x[0] == "sensitivity" and x[1] == resource), "internal")
            admin_only = ("admin_only", resource) in static_facts
            add(("resource", resource), "Resource", resource_id=resource,
                sensitivity=level, admin_only=admin_only)

    return instances, generated


# ---- frame architecture diagram ----

FRAME_DIAGRAM_PATH = Path(__file__).resolve().parents[1] / "docs" / "frame_architecture.png"

HEADER_COLORS = {
    "User": "#1f77b4", "Student": "#5b9bd5", "Faculty": "#5b9bd5",
    "Administrator": "#5b9bd5", "ITStaff": "#5b9bd5",
    "Device": "#2ca02c", "Resource": "#d98a1c",
    "LoginEvent": "#8c564b", "Threat": "#c0392b",
}
IS_A_COLOR = "#1f77b4"
LINK_COLOR = "#e07b00"


def slot_line(slot_name, spec):
    # one short text line for a slot inside a frame box, e.g.  role: string = student
    text = f"{slot_name}: {spec.get('type', '?')}"
    if "values" in spec:
        joined = "|".join(spec["values"])
        text += " {" + joined + "}" if len(spec["values"]) <= 2 and len(joined) <= 16 else f" {{{len(spec['values'])} values}}"
    if "range" in spec:
        text += f" [{spec['range'][0]}..{spec['range'][1]}]"
    if "multiple" in spec:
        text += " *"
    if "default" in spec:
        text += f" = {spec['default']}"
    if "if_added" in spec:
        text += "  [demon]"
    return text


def draw_frames(path=FRAME_DIAGRAM_PATH):
    # Draws every frame as a box (name, slots, facets, defaults), the is-a links
    # and the slot links between frames. Returns True on success.
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.patches import FancyBboxPatch, Rectangle
    except ImportError:
        return False

    line_h, head_h = 0.62, 0.9
    fig, ax = plt.subplots(figsize=(18.5, 12))
    ax.set_xlim(-1.2, 32)
    ax.set_ylim(-0.5, 21)
    ax.axis("off")
    boxes = {}

    def draw_box(name, x, top, width, lines, note=None):
        rows = list(lines) + ([note] if note else [])
        height = head_h + line_h * max(len(rows), 1) + 0.25
        bottom = top - height
        ax.add_patch(FancyBboxPatch((x, bottom), width, height, boxstyle="round,pad=0,rounding_size=0.25",
                                    fc="white", ec="#444444", lw=1.5, zorder=3))
        ax.add_patch(Rectangle((x, top - head_h), width, head_h, fc=HEADER_COLORS[name], ec="#444444",
                               lw=1.5, zorder=4))
        parent = FRAMES[name]["is_a"]
        title = name + (" (is-a User)" if parent else "")
        ax.text(x + width / 2, top - head_h / 2, title, ha="center", va="center", color="white",
                fontsize=11, fontweight="bold", zorder=5)
        y = top - head_h - line_h * 0.6
        for i, row in enumerate(rows):
            italic = note is not None and i == len(rows) - 1
            ax.text(x + 0.25, y, row, ha="left", va="center", fontsize=9.2, family="DejaVu Sans Mono",
                    style="italic" if italic else "normal", color="#444444" if italic else "black", zorder=5)
            y -= line_h
        boxes[name] = {"l": x, "r": x + width, "t": top, "b": bottom, "cx": x + width / 2,
                       "cy": (top + bottom) / 2}

    def own_lines(name):
        return [slot_line(s, spec) for s, spec in FRAMES[name]["slots"].items()]

    # top row: the User frame, Device and Resource
    draw_box("User", 1.8, 20.3, 11.4, own_lines("User"))
    draw_box("Device", 15.2, 20.3, 7.6, own_lines("Device"))
    draw_box("Resource", 23.4, 15.4, 7.8, own_lines("Resource"))

    # second row: the four children of User (only the overridden slot is listed)
    child_x = 1.8
    for child in ("Student", "Faculty", "Administrator", "ITStaff"):
        lines = [f"role = {FRAMES[child]['slots']['role']['default']}  (override)"]
        draw_box(child, child_x, 13.4, 5.05, lines, note="inherits all User slots")
        child_x += 5.15

    # third row: LoginEvent and Threat
    draw_box("LoginEvent", 1.8, 8.9, 9.6, own_lines("LoginEvent"))
    draw_box("Threat", 1.8, 4.6, 9.6, own_lines("Threat"))

    # script box (Frames and Scripts)
    sx, stop, sw = 14.2, 5.9, 17.0
    steps = [f"{s['step']}. {s['action']}" for s in LOGIN_SCRIPT["steps"]]
    sheight = head_h + line_h * len(steps) + 0.3
    ax.add_patch(FancyBboxPatch((sx, stop - sheight), sw, sheight, boxstyle="round,pad=0,rounding_size=0.25",
                                fc="#fff8e1", ec="#444444", lw=1.5, zorder=3))
    ax.text(sx + sw / 2, stop - head_h / 2, f"Script: {LOGIN_SCRIPT['name']}", ha="center", va="center",
            fontsize=11, fontweight="bold", zorder=5)
    for i, row in enumerate(steps):
        ax.text(sx + 0.3, stop - head_h - line_h * (i + 0.6), row, ha="left", va="center", fontsize=9.5,
                zorder=5)

    def arrow(points, color, hollow=False, label=None, label_at=None):
        for a, b in zip(points[:-2], points[1:-1]):
            ax.plot([a[0], b[0]], [a[1], b[1]], color=color, lw=1.8, zorder=2, solid_capstyle="butt")
        ax.annotate("", xy=points[-1], xytext=points[-2], zorder=2, arrowprops=dict(
            arrowstyle="-|>" if not hollow else "-|>", color=color, lw=1.8, shrinkA=0, shrinkB=0,
            mutation_scale=22, fc="white" if hollow else color))
        if label:
            lx, ly = label_at
            ax.text(lx, ly, label, fontsize=9, style="italic", ha="center", va="center", zorder=6,
                    bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none"), color=color)

    # is-a arrows: every child to the bottom of User
    user = boxes["User"]
    for child in ("Student", "Faculty", "Administrator", "ITStaff"):
        c = boxes[child]
        end_x = min(max(c["cx"], user["l"] + 1.0), user["r"] - 1.0)
        arrow([(c["cx"], c["t"]), (c["cx"], c["t"] + 0.9), (end_x, c["t"] + 0.9), (end_x, user["b"])],
              IS_A_COLOR, hollow=True)
    ax.text(user["cx"], 14.55, "is-a", fontsize=9, style="italic", ha="center", va="center", zorder=6,
            color=IS_A_COLOR, bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none"))

    # slot links between frames
    dev, res, login, threat = boxes["Device"], boxes["Resource"], boxes["LoginEvent"], boxes["Threat"]
    arrow([(user["r"], 18.9), (dev["l"], 18.9)], LINK_COLOR, label="uses", label_at=(14.2, 19.3))
    arrow([(user["r"], 16.9), (res["cx"], 16.9), (res["cx"], res["t"])], LINK_COLOR,
          label="requests", label_at=(19.0, 16.5))
    # LoginEvent.user and Threat.target go up the left margin to User
    arrow([(login["l"], 7.4), (0.6, 7.4), (0.6, 17.6), (user["l"], 17.6)], LINK_COLOR,
          label="user", label_at=(0.6, 10.0))
    arrow([(threat["l"], 2.6), (-0.4, 2.6), (-0.4, 19.0), (user["l"], 19.0)], LINK_COLOR,
          label="target", label_at=(-0.4, 6.0))
    # LoginEvent.device goes right, then up between the children row and Resource to Device
    arrow([(login["r"], 6.6), (22.9, 6.6), (22.9, 18.0), (dev["r"], 18.0)], LINK_COLOR,
          label="device", label_at=(22.9, 11.5))

    ax.set_title("CyberGuard frame architecture     "
                 "blue arrow = is-a (inheritance),  orange arrow = slot that points to another frame",
                 fontsize=14, pad=14)
    ax.text(15.2, 0.2, "slot notation:  name: type {allowed values} [range]   * = many values   "
            "= x means default x   [demon] = if-added procedure", fontsize=10, color="#444444")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return True


def open_image(path=FRAME_DIAGRAM_PATH):
    # open the PNG in the default viewer so the diagram appears during the demo
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception:
        print(f"(could not open the viewer, open the file by hand: {path})")


if __name__ == "__main__":
    for name in FRAMES:
        print_frame(name)
        print()
    print_script()
    print()
    ok = draw_frames()
    print("frame diagram saved:" if ok else "diagram libraries missing (pip install matplotlib)",
          FRAME_DIAGRAM_PATH if ok else "")
    if ok and "--open" in sys.argv:
        open_image()