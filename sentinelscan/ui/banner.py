from rich.console import Console
from rich.align import Align
from rich.text import Text

from sentinelscan.config import VERSION

BANNER = r"""
   _____            _   _            _  _____
  / ____|          | | (_)          | |/ ____|
 | (___   ___ _ __ | |_ _ _ __   ___| | (___   ___ __ _ _ __
  \___ \ / _ \ '_ \| __| | '_ \ / _ \ |\___ \ / __/ _` | '_ \
  ____) |  __/ | | | |_| | | | |  __/ |____) | (_| (_| | | | |
 |_____/ \___|_| |_|\__|_|_| |_|\___|_|_____/ \___\__,_|_| |_|
"""


def print_banner(console: Console, no_color: bool = False) -> None:
    style = "bold cyan" if not no_color else None
    console.print(Align.center(Text(BANNER, style=style)))
    console.print(Align.center(
        Text(f"  Interactive Security Audit • v{VERSION}  ", style="dim"),
    ))
    console.print()