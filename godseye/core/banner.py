"""Cross-platform Eye of Horus (Olho de Hórus - Udjat 𓂀) Banner for CMD, PowerShell & Linux."""

import contextlib
import ctypes
import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

EYE_OF_HORUS_GLYPH = "𓂀"

# Iconic Eye of Horus (Udjat) geometry rendered with Unicode / ASCII art so it displays
# crisply in Windows CMD, Windows PowerShell, and any Linux terminal.
EYE_OF_HORUS_ART = r"""
               _.o888888888888888888888888888o._
          _.o888888888888888888888888888888888888o._
       .o888P"   ____...---=======---...____   "Y888o.
     .888P"  _.-"                           "-._  "Y888.
    d88P   .-"       _..---=======---.._       "-.   Y88b
   ""    ."      _.-"    .d8888888b.    "-._      ".    ""
        /     .-"       d8888(𓂀)8888b       "-.     \
       (=====(          8888888888888          )=====)
        \     "-._      Y88888888888P      _.-"     /
         ".       "-._   "Y8888888P"   _.-"       ."
           "-._       "---...___...---"       _.-"
               "---...____   |||   ____...---"
                          |  |||  \
                          |  |||   \      _.._
                          |  |||    \   ."    ".
                          |  |||     \  |  ()  |
                         d8b |||      "._".__."
                        d888b|||
                         "Y8P"|
"""


def configure_terminal_utf8() -> None:
    """Configure UTF-8 output and ANSI virtual terminal sequences on Windows CMD/PowerShell & Linux."""
    if sys.platform == "win32":
        try:
            # Set Windows console code page to UTF-8 (65001)
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
            # Enable Virtual Terminal Processing (ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004)
            std_out_handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(std_out_handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(std_out_handle, mode.value | 0x0004)
        except Exception:
            pass

    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            with contextlib.suppress(Exception):
                stream.reconfigure(encoding="utf-8", errors="replace")

    os.environ.setdefault("PYTHONIOENCODING", "utf-8")


def get_eye_of_horus_banner(version: str = "1.0.0") -> str:
    """Return the plain string representation of the God's Eye banner with the Eye of Horus."""
    return (
        f"{EYE_OF_HORUS_ART}\n"
        f"  {EYE_OF_HORUS_GLYPH}  G O D ' S   E Y E   [ v{version} ]  {EYE_OF_HORUS_GLYPH}\n"
        f"  All-Seeing OSINT Aggregation, Correlation & Threat Intelligence Platform\n"
        f"  Compatible: Windows CMD | PowerShell | Linux  •  LGPD & Provenance Enforced"
    )


def render_banner(console: Console | None = None, version: str = "1.0.0") -> None:
    """Render the stylized Eye of Horus banner to the terminal using Rich."""
    configure_terminal_utf8()
    target_console = console or Console()

    art_text = Text(EYE_OF_HORUS_ART.strip("\n"), style="bold gold1")
    art_text.highlight_words([EYE_OF_HORUS_GLYPH, "(𓂀)", "()"], style="bold cyan")

    title_line = Text(
        f"\n  {EYE_OF_HORUS_GLYPH}  G O D ' S   E Y E   ( O L H O   D E   H Ó R U S )  v{version}  {EYE_OF_HORUS_GLYPH}\n",
        style="bold bright_cyan",
    )
    subtitle_line = Text(
        "  Multi-Source OSINT Hub • Cascading Correlation • Provenance & SHA-256 Evidence Store\n"
        "  100+ Global & Brazilian OSINT Sources • CMD / PowerShell / Linux • LGPD Compliant",
        style="italic bright_white",
    )

    combined = Text.assemble(art_text, "\n", title_line, subtitle_line)
    panel = Panel(
        combined,
        border_style="gold1",
        title=f"[bold bright_cyan]{EYE_OF_HORUS_GLYPH} GOD'S EYE CYBERSECURITY OSINT {EYE_OF_HORUS_GLYPH}[/bold bright_cyan]",
        subtitle="[dim]Type 'godseye --help' or 'godseye shell' for interactive console[/dim]",
        expand=False,
    )
    target_console.print(panel)
