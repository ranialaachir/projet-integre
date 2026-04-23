# services/printing.py

from rich.text import Text

from .console import console
from entities.node import Node
from .formatting import format_node

from references.privilege_levels import PrivilegeLevel

def _print_element(symbol:chr, text:str, color:str="white") -> None:
    content = Text()
    content.append(f"\n[{symbol}] {text}", style=color)
    console.print(content)

def print_title(title:str) -> None:
    console.print("\n")
    console.rule(f"[bold blue]\n[*] {title}...[/]")
    console.print("\n")

def print_error(error:str) -> None:
    _print_element('-',error,'bold red')

def print_warning(warning:str) -> None:
    _print_element('-',warning,'yellow')

def print_check(check:str) -> None:
    _print_element('+',check,'green')

def print_done(done:str) -> None:
    _print_element('✓',done,'green')

def print_node(node:Node, tag:str="") -> None:
    console.print(format_node(node, tag))

def print_level(node:Node, level:PrivilegeLevel) -> None: # Add color by severity
    levels_colors = [
        "#00FF00",
        "#33FF00",
        "#66FF00",
        "#99FF00",
        "#CCFF00",
        "#FFCC00",
        "#FF9900",
        "#FF6600",
        "#FF3300",
        "#FF0000"
    ]
    _print_element(level.name, " : ", levels_colors[level])
    print_node(node)

def print_dict_node(nodes:dict[str, Node]) -> None:
    for node in nodes.values():
        print_node(node)