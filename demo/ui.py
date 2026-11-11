# File: demo/ui.py
# Purpose: small printing helpers for the live demo: stage headers, short "what is this"
# notes, colours, and the "press Enter" pauses. Keeping them here means runner.py only
# has to describe what to show, not how to format it.

import os
import sys
import textwrap

WIDTH = 78
AUTO = False          # True when the demo runs without pauses (--auto)
USE_COLOR = False

COLORS = {"cyan": "36", "green": "32", "red": "31", "yellow": "33", "bold": "1", "grey": "90"}


def init(auto=False):
    # call once at start: sets the pause mode, UTF-8 output and colour support
    global AUTO, USE_COLOR
    AUTO = auto
    try:
        sys.stdout.reconfigure(encoding="utf-8")   # needed for the logic symbols on Windows
    except Exception:
        pass
    os.system("")                                   # turns on ANSI colours in the Windows console
    USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def paint(text, color):
    if not USE_COLOR:
        return text
    return f"\033[{COLORS[color]}m{text}\033[0m"


def banner(text, char="="):
    print(paint(char * WIDTH, "cyan"))
    print(paint(text, "bold"))
    print(paint(char * WIDTH, "cyan"))


def stage_header(number, total, title):
    print()
    banner(f"STAGE {number} of {total}: {title}")


def subheading(text):
    print()
    print(paint(f"--- {text} ---", "yellow"))


def note(text):
    # a short explanation of the concept, written to be read aloud during the demo
    wrapped = textwrap.fill(text, width=WIDTH - 4, initial_indent="  ", subsequent_indent="  ")
    print(paint("What is this?", "yellow"))
    print(paint(wrapped, "grey"))
    print()


def good(text):
    print(paint(text, "green"))


def bad(text):
    print(paint(text, "red"))


def pause(message="Press Enter to continue..."):
    # the presenter controls the speed, so every stage can be explained before moving on
    if AUTO:
        return
    try:
        input(paint(f"\n[{message}] ", "cyan"))
    except EOFError:
        pass


def ask(prompt, default=""):
    # read one line of input, an empty answer returns the default
    if AUTO:
        return default
    try:
        answer = input(prompt).strip()
    except EOFError:
        return default
    return answer or default