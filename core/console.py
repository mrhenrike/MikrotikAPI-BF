#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Terminal colors, section headers, and colored argparse help."""

from __future__ import annotations

import argparse
import re
import sys
from typing import Optional

try:
    from colorama import Fore, Style, init as _colorama_init

    _colorama_init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False

    class _Dummy:
        def __getattr__(self, _: str) -> str:
            return ""

    Fore = _Dummy()  # type: ignore[assignment]
    Style = _Dummy()  # type: ignore[assignment]


def _c(text: str, color: str) -> str:
    if not _HAS_COLOR or not sys.stdout.isatty():
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def bold(text: str) -> str:
    return _c(text, Style.BRIGHT)


def dim(text: str) -> str:
    return _c(text, Style.DIM)


def ok(text: str) -> str:
    return _c(text, Fore.GREEN)


def warn(text: str) -> str:
    return _c(text, Fore.YELLOW)


def err(text: str) -> str:
    return _c(text, Fore.RED)


def info(text: str) -> str:
    return _c(text, Fore.CYAN)


def highlight(text: str) -> str:
    return _c(text, Fore.LIGHTCYAN_EX)


def proto_api(text: str) -> str:
    return _c(text, Fore.LIGHTBLUE_EX)


def proto_rest(text: str) -> str:
    return _c(text, Fore.LIGHTMAGENTA_EX)


def proto_ssh(text: str) -> str:
    return _c(text, Fore.LIGHTGREEN_EX)


def colorize_protocol_tag(message: str) -> str:
    """Color [API], [REST], [SSH], etc. inside a log line."""
    if not _HAS_COLOR:
        return message

    def _repl(m: re.Match) -> str:
        tag = m.group(1).upper()
        body = m.group(0)
        palette = {
            "API": proto_api,
            "REST": proto_rest,
            "RESTAPI": proto_rest,
            "SSH": proto_ssh,
            "FTP": warn,
            "TELNET": dim,
            "HTTP": info,
            "HTTPS": info,
        }
        fn = palette.get(tag, highlight)
        return fn(body)

    return re.sub(r"\[(API|REST|RESTAPI|SSH|FTP|TELNET|HTTP|HTTPS)\]", _repl, message, flags=re.I)


def section(title: str, *, width: int = 60) -> None:
    line = "═" * width
    print(f"\n{info(line)}")
    print(f"  {bold(title)}")
    print(info(line))


def section_end(width: int = 60) -> None:
    print(info("═" * width))


def kv(key: str, value, *, key_width: int = 16) -> None:
    print(f"  {dim(f'{key:<{key_width}}')}: {highlight(str(value))}")


def kv_onoff(key: str, enabled: bool, *, key_width: int = 16) -> None:
    state = ok("ON") if enabled else err("OFF")
    print(f"  {dim(f'{key:<{key_width}}')}: {state}")


def port_state(opened: bool) -> str:
    return ok("✓ OPEN") if opened else err("✗ CLOSED")


class ColoredHelpFormatter(argparse.RawTextHelpFormatter):
    """Help with colored short/long options and group titles."""

    def _format_usage(self, usage, actions, groups, prefix):
        text = super()._format_usage(usage, actions, groups, prefix)
        return _c(text, Fore.WHITE)

    def start_section(self, heading: Optional[str]) -> None:
        if heading:
            super().start_section(bold(warn(heading)) if heading else heading)
        else:
            super().start_section(heading)

    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            return super()._format_action_invocation(action)

        shorts = [o for o in action.option_strings if o.startswith("-") and not o.startswith("--")]
        longs = [o for o in action.option_strings if o.startswith("--")]

        parts = []
        if shorts:
            parts.append(info(", ".join(shorts)))
        if longs:
            parts.append(highlight(", ".join(longs)))

        opt = ", ".join(parts) if parts else action.option_strings[0]

        if action.nargs != 0:
            metavar = self._get_default_metavar_for_optional(action)
            if action.metavar:
                metavar = action.metavar
            opt += f" {ok(str(metavar))}"
        return opt

    def _format_action(self, action: argparse.Action) -> str:
        line = super()._format_action(action)
        if action.help and action.help is not argparse.SUPPRESS:
            line = line.replace(action.help, dim(action.help), 1)
        return line

    def format_help(self) -> str:
        help_text = super().format_help()
        help_text = help_text.replace("usage:", warn("usage:"), 1)
        help_text = help_text.replace("options:", bold(warn("options:")), 1)
        return help_text
