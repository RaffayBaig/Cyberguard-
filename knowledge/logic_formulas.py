# File: knowledge/logic_formulas.py
# Purpose: the formal logic layer of CyberGuard. It holds the First-Order Logic (FOL)
# formulas of the rules, the Description Logic (DL) axioms (subsumption and disjointness),
# the formulas that are not Horn, and the expressivity vs tractability limitations.
# It also has a small DL reasoner that answers subsumption and disjointness questions
# and checks a set of individuals for contradictions.

import itertools
import sys

# ---------------------------------------------------------------------------
# First-Order Logic: one formula for every Horn rule in rules.py
# ---------------------------------------------------------------------------

# (rule id, FOL formula, meaning in plain English)
FOL_FORMULAS = [
    ("R1",  "∀u ∀n (FailedAttempts(u,n) ∧ n ≥ 3 → BruteForce(u))",
            "three or more failed attempts means brute force"),
    ("R2",  "∀u ∀d (Login(u,d) ∧ ¬Trusted(d) → UnknownDevice(d))",
            "a login from a device that is not trusted marks it unknown"),
    ("R3",  "∀u ∀d (Login(u,d) ∧ UnknownDevice(d) → SuspiciousLogin(u))",
            "login from an unknown device is suspicious"),
    ("R4",  "∀u (BruteForce(u) → SuspiciousLogin(u))",
            "a brute force user is suspicious"),
    ("R5",  "∀u ∀r (SuspiciousLogin(u) ∧ Requests(u,r) ∧ Sensitivity(r,sensitive) → HighRisk(u,r))",
            "suspicious user asking for a sensitive resource"),
    ("R6",  "∀u ∀r (SuspiciousLogin(u) ∧ Requests(u,r) ∧ Sensitivity(r,critical) → HighRisk(u,r))",
            "suspicious user asking for a critical resource"),
    ("R7",  "∀u ∀r (Requests(u,r) ∧ AdminOnly(r) ∧ ¬Role(u,admin) → Unauthorized(u,r))",
            "a non-admin asking for an admin-only resource"),
    ("R8",  "∀u ∀d (BruteForce(u) ∧ Login(u,d) ∧ UnknownDevice(d) → AccountCompromise(u))",
            "brute force followed by a login from an unknown device"),
    ("R9",  "∀u ∀r (Unauthorized(u,r) ∧ RoleChangeAttempt(u) → PrivilegeEscalation(u))",
            "unauthorized access together with a role change attempt"),
    ("R10", "∀u ∀r (HighRisk(u,r) → Decision(u,r,deny))",
            "deny a high risk request"),
    ("R11", "∀u ∀r (Unauthorized(u,r) → Decision(u,r,deny))",
            "deny an unauthorized request"),
    ("R12", "∀u ∀r (AccountCompromise(u) ∧ Requests(u,r) → Decision(u,r,deny))",
            "deny every request of a compromised account"),
    ("R13", "∀u ∀r (SuspiciousLogin(u) ∧ Requests(u,r) ∧ ¬Decision(u,r,deny) → Decision(u,r,flag))",
            "suspicious but not denied: flag the event"),
    ("R14", "∀u ∀r (Requests(u,r) ∧ ¬SuspiciousLogin(u) ∧ ¬Unauthorized(u,r) → Decision(u,r,allow))",
            "nothing suspicious and authorized: allow"),
]

# Some formulas cannot be written as a Horn clause.
# (formula, why it is not Horn, how CyberGuard handles it)
BEYOND_HORN = [
    ("∀u (User(u) → Student(u) ∨ Faculty(u) ∨ Administrator(u) ∨ ITStaff(u))",
     "the head is a disjunction (more than one positive literal)",
     "every user gets exactly one role fact, so no disjunction is needed"),
    ("∃u ∃r Unauthorized(u,r)",
     "as a knowledge base axiom it needs Skolem constants, an existential cannot be a Horn clause",
     "as a query it is fine: backward chaining treats u and r as variables and searches for values"),
    ("∀u (Student(u) → ¬Administrator(u))",
     "a negative conclusion is not allowed in a Horn head",
     "written as a DL disjointness axiom and checked by the DL reasoner"),
]

# ---------------------------------------------------------------------------
# Description Logic: TBox (concept axioms)
# ---------------------------------------------------------------------------

USER_TYPES = ["Student", "Faculty", "Administrator", "ITStaff"]
DEVICE_TYPES = ["TrustedDevice", "UnknownDevice"]

# subsumption axioms: ("sub", A, B) means A ⊑ B (every A is also a B)
SUBSUMPTIONS = [("sub", t, "User") for t in USER_TYPES] + [
    ("sub", "TrustedDevice", "Device"),
    ("sub", "UnknownDevice", "Device"),
    ("sub", "SensitiveResource", "Resource"),
    ("sub", "CriticalResource", "SensitiveResource"),
    ("sub", "AdminOnlyResource", "CriticalResource"),
    ("sub", "BruteForce", "Threat"),
    ("sub", "AccountCompromise", "Threat"),
    ("sub", "PrivilegeEscalation", "Threat"),
    ("sub", "SuspiciousLogin", "LoginEvent"),
]

# disjointness axioms: ("disjoint", A, B) means A ⊓ B ⊑ ⊥ (nothing is both)
DISJOINTS = (
    [("disjoint", a, b) for a, b in itertools.combinations(USER_TYPES, 2)]
    + [("disjoint", "TrustedDevice", "UnknownDevice"),
       ("disjoint", "User", "Device"),
       ("disjoint", "User", "Resource"),
       ("disjoint", "Device", "Resource")]
)

TBOX = SUBSUMPTIONS + DISJOINTS

# Definitions and property axioms. They are shown in the demo but the small reasoner
# below only uses subsumption and disjointness.
EXTRA_AXIOMS = [
    "BruteForceUser ≡ User ⊓ ∃hasFailedAttempts.AtLeastThree",
    "SuspiciousUser ≡ User ⊓ (∃uses.UnknownDevice ⊔ BruteForceUser)",
    "UnauthorizedUser ≡ User ⊓ ¬Administrator ⊓ ∃requests.AdminOnlyResource",
    "∃uses.⊤ ⊑ User        (domain of uses)",
    "⊤ ⊑ ∀uses.Device      (range of uses)",
    "⊤ ⊑ ∀requests.Resource (range of requests)",
]

# ---------------------------------------------------------------------------
# Limitations of Propositional Logic, FOL and Horn clauses in this domain
# ---------------------------------------------------------------------------

LIMITATIONS = [
    ("Propositional logic",
     "It has no variables. We would need one rule per user and resource "
     "(brute_force_ali, brute_force_sara, ...). It cannot say 'for every user'."),
    ("First-Order Logic",
     "It is expressive (variables, quantifiers, relations) but entailment is only "
     "semi-decidable: a proof may never finish for a false goal."),
    ("Description Logic",
     "It is decidable and good for classes (subsumption, disjointness), "
     "but it cannot express rules that join several facts, like R5 (user + resource + risk)."),
    ("Horn clauses",
     "Only one positive literal per rule. It is fast (forward chaining is polynomial "
     "for rules without function symbols) but it cannot express disjunction or "
     "classical negation. We use negation as failure, which assumes what is not known is false."),
]

# ---------------------------------------------------------------------------
# A small Description Logic reasoner
# ---------------------------------------------------------------------------

_PARENTS = {}
for _, _child, _parent in SUBSUMPTIONS:
    _PARENTS.setdefault(_child, []).append(_parent)

_DISJOINT_PAIRS = set()
for _, _a, _b in DISJOINTS:
    _DISJOINT_PAIRS.add((_a, _b))
    _DISJOINT_PAIRS.add((_b, _a))


def superclasses(cls):
    # the class itself plus every class above it (transitive closure of is-a)
    found = [cls]
    for parent in _PARENTS.get(cls, []):
        for c in superclasses(parent):
            if c not in found:
                found.append(c)
    return found


def is_subsumed(a, b):
    # True if A ⊑ B can be derived from the TBox
    return b in superclasses(a)


def are_disjoint(a, b):
    # two classes are disjoint if any class above A is declared disjoint with any class above B
    for x in superclasses(a):
        for y in superclasses(b):
            if (x, y) in _DISJOINT_PAIRS:
                return True
    return False


def check_abox(assertions):
    # assertions: list of (individual, class). Returns (types, conflicts).
    # types: every class an individual belongs to, including inherited ones.
    # conflicts: individuals that belong to two disjoint classes (the ABox is inconsistent).
    asserted = {}
    for individual, cls in assertions:
        asserted.setdefault(individual, []).append(cls)

    types, conflicts = {}, []
    for individual, classes in asserted.items():
        all_types = []
        for cls in classes:
            for c in superclasses(cls):
                if c not in all_types:
                    all_types.append(c)
        types[individual] = all_types
        for a, b in itertools.combinations(classes, 2):
            if are_disjoint(a, b):
                conflicts.append((individual, a, b))
    return types, conflicts


# ---------------------------------------------------------------------------
# Printing for the demo
# ---------------------------------------------------------------------------

def axiom_text(axiom):
    kind, a, b = axiom
    if kind == "sub":
        return f"{a} ⊑ {b}"
    return f"{a} ⊓ {b} ⊑ ⊥"


def print_fol():
    print("First-Order Logic formulas (one for each Horn rule):")
    for rule_id, formula, meaning in FOL_FORMULAS:
        print(f"  {rule_id:<4}{formula}")
        print(f"      {meaning}")
    print()
    print("Note: R2, R7, R13 and R14 have ¬ in the body. Classical Horn clauses allow no negation,")
    print("so the engine reads ¬ as negation as failure (stratified), see stage 4.")
    print()
    print("Formulas that are NOT Horn:")
    for formula, why, handled in BEYOND_HORN:
        print(f"  {formula}")
        print(f"      why: {why}")
        print(f"      handled: {handled}")


def print_dl(assertions=None):
    print("Description Logic TBox:")
    print("  Subsumption (A ⊑ B, every A is a B):")
    for axiom in SUBSUMPTIONS:
        print(f"    {axiom_text(axiom)}")
    print("  Disjointness (A ⊓ B ⊑ ⊥, nothing is both):")
    for axiom in DISJOINTS:
        print(f"    {axiom_text(axiom)}")
    print("  Definitions and properties:")
    for text in EXTRA_AXIOMS:
        print(f"    {text}")

    print()
    print("DL reasoning (answered by the small reasoner in this file):")
    for a, b in [("CriticalResource", "Resource"), ("AdminOnlyResource", "SensitiveResource"),
                 ("Resource", "CriticalResource")]:
        print(f"  Is {a} ⊑ {b}?  {'YES' if is_subsumed(a, b) else 'NO'}")
    for a, b in [("Student", "Administrator"), ("TrustedDevice", "UnknownDevice"),
                 ("Student", "User")]:
        print(f"  Are {a} and {b} disjoint?  {'YES' if are_disjoint(a, b) else 'NO'}")

    if assertions:
        types, conflicts = check_abox(assertions)
        print()
        print("ABox (individuals of this scenario):")
        for individual, all_types in types.items():
            print(f"  {individual} : {', '.join(all_types)}")
        print("  Consistency check: " + ("OK, no individual is in two disjoint classes"
                                         if not conflicts else "CONFLICT"))
        for individual, a, b in conflicts:
            print(f"    {individual} is both {a} and {b}")


def print_limitations():
    print("Expressivity vs tractability in this domain:")
    for name, text in LIMITATIONS:
        print(f"  {name}: {text}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    print_fol()
    print()
    print_dl([("ali", "Student"), ("dev7", "UnknownDevice"), ("student_db", "SensitiveResource")])
    print()
    print_limitations()