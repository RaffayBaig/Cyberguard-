# File: knowledge/semantic_net.py
# Purpose: the semantic network of CyberGuard. It stores the relations between concepts
# (is-a, has-a, part-of and a few domain links), adds the individuals of the running
# scenario, prints the relations and draws the network as a diagram (docs/semantic_network.png).
# The is-a links come from the Description Logic axioms, so both views always agree.
#
# The diagram always shows the whole schema (all concepts). Only the green individuals
# (ali, dev7, student_db ...) and their links change with the scenario that is running.

import os
import subprocess
import sys
from pathlib import Path

from knowledge.frames import ROLE_FRAME
from knowledge.logic_formulas import SUBSUMPTIONS

DIAGRAM_PATH = Path(__file__).resolve().parents[1] / "docs" / "semantic_network.png"

# every edge is (from, relation, to)
IS_A = [(a, "is-a", b) for _, a, b in SUBSUMPTIONS]

HAS_A = [
    ("User",       "has-a", "Role"),
    ("User",       "has-a", "FailedAttempts"),
    ("Device",     "has-a", "TrustLevel"),
    ("Resource",   "has-a", "Sensitivity"),
    ("LoginEvent", "has-a", "Location"),
    ("Threat",     "has-a", "Severity"),
]

PART_OF = [
    ("Device",        "part-of", "CampusNetwork"),
    ("Resource",      "part-of", "CampusNetwork"),
    ("LoginEvent",    "part-of", "AccessRequest"),
    ("AccessRequest", "part-of", "CampusNetwork"),
]

# other links between the main concepts
LINKS = [
    ("LoginEvent", "by",       "User"),
    ("LoginEvent", "from",     "Device"),
    ("User",       "requests", "Resource"),
    ("User",       "uses",     "Device"),
    ("Threat",     "targets",  "User"),
]

SCHEMA_EDGES = IS_A + HAS_A + PART_OF + LINKS

RELATION_COLORS = {
    "is-a": "#1f77b4",
    "has-a": "#2ca02c",
    "part-of": "#ff7f0e",
    "instance-of": "#9467bd",
}
DEFAULT_COLOR = "#7f7f7f"


# ---- individuals of a scenario ----

def resource_class(resource, facts):
    # decide the most specific resource class from the static facts
    if ("admin_only", resource) in facts:
        return "AdminOnlyResource"
    level = next((f[2] for f in facts if f[0] == "sensitivity" and f[1] == resource), "internal")
    return {"critical": "CriticalResource", "sensitive": "SensitiveResource"}.get(level, "Resource")


def instance_edges(facts):
    # builds the individual-level edges of a scenario from the facts:
    # ali instance-of Student, ali uses dev7, dev7 instance-of UnknownDevice, ...
    edges = []

    def add(edge):
        if edge not in edges:
            edges.append(edge)

    for f in facts:
        if f[0] == "login":
            user, device = f[1], f[2]
            role = next((x[2] for x in facts if x[0] == "role" and x[1] == user), None)
            add((user, "instance-of", ROLE_FRAME.get(role, "User")))
            add((user, "uses", device))
            kind = "TrustedDevice" if ("trusted", device) in facts else "UnknownDevice"
            add((device, "instance-of", kind))
        elif f[0] == "requests":
            add((f[1], "requests", f[2]))
            add((f[2], "instance-of", resource_class(f[2], facts)))
    return edges


def instance_assertions(edges):
    # (individual, class) pairs, used by the Description Logic consistency check
    return [(a, c) for a, rel, c in edges if rel == "instance-of"]


# ---- printing ----

def print_network(inst_edges=None):
    groups = [("is-a (a kind of)", IS_A), ("has-a (owns a property)", HAS_A),
              ("part-of (belongs to a bigger whole)", PART_OF), ("other links", LINKS)]
    for title, edges in groups:
        print(f"{title}:")
        for a, rel, b in edges:
            print(f"  {a} --{rel}--> {b}")
        print()
    if inst_edges:
        print("individuals of this scenario:")
        for a, rel, b in inst_edges:
            print(f"  {a} --{rel}--> {b}")


# ---- drawing ----
# Layout idea: User is in the middle. Devices are on its left, resources on its right,
# threats below it and login events below the devices, so the main links are short
# straight lines. Inside a lane the more specific concept is drawn above the general one,
# so every is-a arrow points down. Two long links (part-of CampusNetwork) run along
# the bottom edge of the picture.

LANES = {
    "DEVICES":      (0.3, 5.8, 9.7, 17.6),
    "USERS":        (10.3, 5.8, 19.7, 17.6),
    "RESOURCES":    (20.3, 5.8, 29.7, 17.6),
    "LOGIN EVENTS": (0.3, 0.3, 9.7, 4.6),
    "THREATS":      (10.3, 0.3, 19.7, 4.6),
    "NETWORK":      (20.3, 0.3, 29.7, 4.6),
}

POSITIONS = {
    # users (centre)
    "User": (15.0, 9.2), "Student": (11.4, 12.4), "Faculty": (13.7, 12.4),
    "Administrator": (16.3, 12.4), "ITStaff": (18.6, 12.4),
    "Role": (12.6, 6.9), "FailedAttempts": (17.6, 6.9),
    # devices (left)
    "Device": (5.2, 9.2), "TrustedDevice": (2.4, 12.4), "UnknownDevice": (7.6, 12.4),
    "TrustLevel": (2.6, 7.0),
    # resources (right, a vertical chain, the most specific on top)
    "Resource": (25.0, 8.8), "SensitiveResource": (25.0, 10.8),
    "CriticalResource": (25.0, 12.8), "AdminOnlyResource": (25.0, 14.8),
    "Sensitivity": (22.0, 7.0),
    # threats (below the users, arrows of the children point up)
    "Threat": (15.0, 3.5), "BruteForce": (11.9, 1.2), "AccountCompromise": (15.0, 1.2),
    "PrivilegeEscalation": (18.2, 1.2), "Severity": (18.3, 3.5),
    # login events (below the devices)
    "LoginEvent": (5.2, 3.5), "SuspiciousLogin": (2.0, 3.5), "Location": (8.2, 3.5),
    "AccessRequest": (5.2, 1.2),
    # network (below the resources)
    "CampusNetwork": (25.0, 2.0),
}

# individuals sit in one row above their class (users and devices) and in one column
# at the right edge (resources)
INDIVIDUAL_ROW = 16.6
RESOURCE_COLUMN = 28.3

# two long links run along the bottom edge instead of crossing the whole picture
BOTTOM = -0.6
ROUTES = {
    ("Device", "part-of", "CampusNetwork"):
        [(-0.3, POSITIONS["Device"][1]), (-0.3, BOTTOM), (POSITIONS["CampusNetwork"][0], BOTTOM)],
    ("AccessRequest", "part-of", "CampusNetwork"):
        [(POSITIONS["AccessRequest"][0], BOTTOM), (POSITIONS["CampusNetwork"][0], BOTTOM)],
}


def individual_kind(cls):
    if cls in ("User", "Student", "Faculty", "Administrator", "ITStaff"):
        return "user"
    if cls in ("Device", "TrustedDevice", "UnknownDevice"):
        return "device"
    return "resource"


def place_individuals(inst_edges):
    pos = dict(POSITIONS)
    for individual, cls in instance_assertions(inst_edges):
        if individual_kind(cls) == "resource":
            pos[individual] = (RESOURCE_COLUMN, pos[cls][1])
        else:
            pos[individual] = (pos[cls][0], INDIVIDUAL_ROW)
    return pos


def draw_network(inst_edges=None, path=DIAGRAM_PATH):
    # Draws the schema plus the scenario individuals and saves a PNG. Returns True on success.
    try:
        import matplotlib
        matplotlib.use("Agg")           # draw to a file, no window needed
        import matplotlib.pyplot as plt
        from matplotlib.lines import Line2D
        from matplotlib.patches import FancyBboxPatch
    except ImportError:
        return False

    inst_edges = inst_edges or []
    edges = SCHEMA_EDGES + inst_edges
    pos = place_individuals(inst_edges)
    individuals = {a for a, _ in instance_assertions(inst_edges)}
    properties = {b for _, _, b in HAS_A}

    fig, ax = plt.subplots(figsize=(24, 14.5))
    ax.set_xlim(-0.8, 30)
    ax.set_ylim(-1.2, 19)
    ax.axis("off")

    for name, (x0, y0, x1, y1) in LANES.items():
        ax.add_patch(FancyBboxPatch((x0, y0), x1 - x0, y1 - y0, zorder=0, fc="#f6f8fa", ec="#c9d1d9",
                                    lw=1.2, boxstyle="round,pad=0,rounding_size=0.4"))
        ax.text(x0 + 0.3, y1 + 0.2, name, fontsize=11, fontweight="bold", color="#57606a", va="bottom")

    # draw the boxes first and measure them, so every arrow can stop exactly at a box border
    texts = {}
    for node in {n for a, _, b in edges for n in (a, b)}:
        color = "#b7e4c7" if node in individuals else "#e6e6e6" if node in properties else "#cfe2f3"
        texts[node] = ax.text(pos[node][0], pos[node][1], node, ha="center", va="center", fontsize=10,
                              zorder=5, bbox=dict(boxstyle="round,pad=0.35", fc=color, ec="#555555"))
    renderer = fig.canvas.get_renderer()
    half = {}
    for node, text in texts.items():
        box = text.get_window_extent(renderer).padded(5).transformed(ax.transData.inverted())
        half[node] = (box.width / 2, box.height / 2)

    def border_toward(node, target):
        # the point where the line from this box towards a target point leaves the box
        (x, y), (tx, ty) = pos[node], target
        dx, dy = tx - x, ty - y
        steps = [half[node][0] / abs(dx) if dx else float("inf"),
                 half[node][1] / abs(dy) if dy else float("inf")]
        t = min(steps)
        return x + dx * t, y + dy * t

    def arrow(start, end, color, dashed=False):
        ax.annotate("", xy=end, xytext=start, zorder=2, arrowprops=dict(
            arrowstyle="-|>", color=color, lw=1.8, linestyle="--" if dashed else "-",
            shrinkA=0, shrinkB=0, mutation_scale=22))

    def segments(points, color):
        # straight pieces of a bent line, the last piece carries the arrow head
        for p, q in zip(points[:-2], points[1:-1]):
            ax.plot([p[0], q[0]], [p[1], q[1]], color=color, lw=1.8, zorder=2, solid_capstyle="butt")
        arrow(points[-2], points[-1], color)

    for a, rel, b in edges:
        color = RELATION_COLORS.get(rel, DEFAULT_COLOR)
        labelled = rel not in ("is-a", "has-a", "part-of", "instance-of")
        if (a, rel, b) in ROUTES:
            way = ROUTES[(a, rel, b)]
            segments([border_toward(a, way[0])] + way + [border_toward(b, way[-1])], color)
            continue
        if (a, rel, b) in inst_edges and rel == "requests":
            # a scenario "requests" arrow runs along the top row and then down to the resource
            (x1, y1), (x2, y2) = pos[a], pos[b]
            start_x = x1 + half[a][0]
            ax.plot([start_x, x2], [y1, y1], color=color, lw=1.8, zorder=2, solid_capstyle="butt")
            arrow((x2, y1), (x2, y2 + half[b][1]), color)
            label_at = ((start_x + x2) / 2, y1)
        else:
            start, end = border_toward(a, pos[b]), border_toward(b, pos[a])
            arrow(start, end, color, dashed=(rel == "instance-of"))
            label_at = ((start[0] + end[0]) / 2, (start[1] + end[1]) / 2)
        if labelled:
            ax.text(*label_at, rel, fontsize=9, style="italic", ha="center", va="center", zorder=4,
                    bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none"))

    legend = [Line2D([0], [0], color=c, lw=2, label=r) for r, c in RELATION_COLORS.items()]
    legend.append(Line2D([0], [0], color=DEFAULT_COLOR, lw=2, label="other link (labelled)"))
    ax.legend(handles=legend, loc="lower center", ncol=5, fontsize=11, frameon=False,
              bbox_to_anchor=(0.5, -0.04))
    ax.set_title("CyberGuard semantic network     blue = concepts,  green = individuals,  grey = properties",
                 fontsize=14, pad=14)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=100, bbox_inches="tight")
    plt.close(fig)
    return True


def open_image(path=DIAGRAM_PATH):
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
    from knowledge.facts import STATIC_FACTS
    sample = STATIC_FACTS + [("login", "ali", "dev7"), ("requests", "ali", "student_db")]
    edges = instance_edges(sample)
    print_network(edges)
    print("diagram saved:", draw_network(edges), DIAGRAM_PATH)