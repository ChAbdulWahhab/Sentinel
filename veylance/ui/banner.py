from rich.console import Console
from rich.align import Align
from rich.text import Text

from veylance.config import VERSION

BANNER = r"""
 __      __         _                            
 \ \    / /        | |                           
  \ \  / /___ _   _| | __ _ _ __   ___ ___       
   \ \/ // _ \ | | | |/ _` | '_ \ / __/ _ \      
    \  /|  __/ |_| | | (_| | | | | (_|  __/      
     \/  \___|\__, |_|\__,_|_| |_|\___\___|      
               __/ |                             
              |___/                              
"""


def print_banner(console: Console, no_color: bool = False) -> None:
    style = "bold cyan" if not no_color else None
    console.print(Align.center(Text(BANNER, style=style)))
    console.print(Align.center(
        Text(f"  Interactive Security Audit • v{VERSION}  ", style="dim"),
    ))
    console.print()