# File: knowledge/facts.py
# Purpose: the static facts of the university network. These are things the system
# always knows, no matter which scenario is running: who has which role, how sensitive
# each resource is, and which devices are trusted.
# The facts that change from case to case (login, failed attempts, requests)
# live in the scenarios/*.json files.

# A fact is a tuple: (predicate, argument1, argument2, ...)

# user roles
ROLE_FACTS = [
    ("role", "ali",   "student"),
    ("role", "sara",  "faculty"),
    ("role", "hamza", "admin"),
    ("role", "zain",  "it_staff"),
]

# how sensitive each resource is (public, internal, sensitive, critical)
RESOURCE_FACTS = [
    ("sensitivity", "course_page", "public"),
    ("sensitivity", "student_db",  "sensitive"),
    ("sensitivity", "grades_db",   "critical"),
    ("sensitivity", "admin_panel", "critical"),

    # resources that only administrators should open
    ("admin_only", "admin_panel"),
]

# devices registered with the university. Any device not listed here is unknown,
# and rule R2 derives unknown_device(D) for it using negation as failure.
DEVICE_FACTS = [
    ("trusted", "dev1"),
    ("trusted", "dev2"),
]

STATIC_FACTS = ROLE_FACTS + RESOURCE_FACTS + DEVICE_FACTS


def print_facts():
    # used by the demo to show the knowledge base facts
    groups = [("Roles", ROLE_FACTS), ("Resources", RESOURCE_FACTS), ("Trusted devices", DEVICE_FACTS)]
    for title, facts in groups:
        print(f"{title}:")
        for fact in facts:
            args = ", ".join(str(a) for a in fact[1:])
            print(f"  {fact[0]}({args})")


if __name__ == "__main__":
    print_facts()