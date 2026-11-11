# File: knowledge/rules.py
# Purpose: the Horn clause rule base of CyberGuard (14 rules).
# Each rule is written as  head :- body  and has a stratum, which is the level at
# which the forward chaining engine runs it:
#   stratum 0: classification, risk and threat rules
#   stratum 1: deny rules
#   stratum 2: flag and allow rules (they use "not" on facts from the earlier levels)
# The facts that come from the scenario (login, failed_attempts, requests,
# role_change_attempt) are not here, they are loaded from scenarios/*.json.

from engine.terms import Rule

RULES = [
    # ---- Level 1: classification ----
    Rule("R1_brute_force",
         ("brute_force", "?U"),
         [("failed_attempts", "?U", "?N"), (">=", "?N", 3)],
         stratum=0,
         doc="3 or more failed attempts means brute force"),

    # a device that is not in the trusted list is unknown (negation as failure)
    Rule("R2_unknown_device",
         ("unknown_device", "?D"),
         [("login", "?U", "?D"), ("not", ("trusted", "?D"))],
         stratum=0,
         doc="a login from a device that is not trusted marks the device unknown"),

    Rule("R3_suspicious_unknown_device",
         ("suspicious_login", "?U"),
         [("login", "?U", "?D"), ("unknown_device", "?D")],
         stratum=0,
         doc="login from an unknown device is suspicious"),

    # same head as R3: two rules with one head mean "or"
    Rule("R4_suspicious_brute_force",
         ("suspicious_login", "?U"),
         [("brute_force", "?U")],
         stratum=0,
         doc="a brute force user is suspicious"),

    # ---- Level 2: risk ----
    Rule("R5_high_risk_sensitive",
         ("high_risk", "?U", "?R"),
         [("suspicious_login", "?U"), ("requests", "?U", "?R"),
          ("sensitivity", "?R", "sensitive")],
         stratum=0,
         doc="suspicious user asking for a sensitive resource"),

    Rule("R6_high_risk_critical",
         ("high_risk", "?U", "?R"),
         [("suspicious_login", "?U"), ("requests", "?U", "?R"),
          ("sensitivity", "?R", "critical")],
         stratum=0,
         doc="suspicious user asking for a critical resource"),

    Rule("R7_unauthorized",
         ("unauthorized", "?U", "?R"),
         [("requests", "?U", "?R"), ("admin_only", "?R"), ("not", ("role", "?U", "admin"))],
         stratum=0,
         doc="a non-admin asking for an admin-only resource"),

    # ---- Level 3: threats ----
    Rule("R8_account_compromise",
         ("account_compromise", "?U"),
         [("brute_force", "?U"), ("login", "?U", "?D"), ("unknown_device", "?D")],
         stratum=0,
         doc="brute force followed by a login from an unknown device"),

    Rule("R9_privilege_escalation",
         ("privilege_escalation", "?U"),
         [("unauthorized", "?U", "?R"), ("role_change_attempt", "?U")],
         stratum=0,
         doc="unauthorized access together with an attempt to change the role"),

    # ---- Level 4: decision ----
    Rule("R10_deny_high_risk",
         ("decision", "?U", "?R", "deny"),
         [("high_risk", "?U", "?R")],
         stratum=1,
         doc="deny a high risk request"),

    Rule("R11_deny_unauthorized",
         ("decision", "?U", "?R", "deny"),
         [("unauthorized", "?U", "?R")],
         stratum=1,
         doc="deny an unauthorized request"),

    Rule("R12_deny_compromised",
         ("decision", "?U", "?R", "deny"),
         [("account_compromise", "?U"), ("requests", "?U", "?R")],
         stratum=1,
         doc="deny every request of a compromised account"),

    # flag and allow run after deny, because they need to know if deny was derived
    Rule("R13_flag",
         ("decision", "?U", "?R", "flag"),
         [("suspicious_login", "?U"), ("requests", "?U", "?R"),
          ("not", ("decision", "?U", "?R", "deny"))],
         stratum=2,
         doc="suspicious but not denied: let the user in and flag the event"),

    Rule("R14_allow",
         ("decision", "?U", "?R", "allow"),
         [("requests", "?U", "?R"),
          ("not", ("suspicious_login", "?U")),
          ("not", ("unauthorized", "?U", "?R"))],
         stratum=2,
         doc="nothing suspicious and the user is authorized"),
]

STRATUM_NAMES = {
    0: "classification, risk and threats",
    1: "deny decisions",
    2: "flag and allow decisions",
}


def print_rules(rules=RULES):
    # prints the rule base grouped by stratum, and marks which rules are pure Horn
    for level in sorted({r.stratum for r in rules}):
        print(f"Stratum {level}: {STRATUM_NAMES.get(level, 'extra rules')}")
        for rule in rules:
            if rule.stratum == level:
                kind = "Horn" if rule.is_pure_horn() else "Horn + not"
                print(f"  {rule}   [{kind}]")
        print()


if __name__ == "__main__":
    print_rules()