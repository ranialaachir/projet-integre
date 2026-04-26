# services/printing.py

from rich.text import Text

from .console import console
from entities.node import Node
from entities.path import Path
from .formatting import format_node, format_path

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

def print_info(info:str) -> None:
    _print_element('!',info,'#87CEEB')

def print_node(node:Node, tag:str="") -> None:
    console.print(format_node(node, tag))

def print_path(path:Path, index:int=1) -> None: # , tag:str=""
    console.print(format_path(path=path, index=index))

def print_dict_node(nodes:dict[str, Node]) -> None:
    for node in nodes.values():
        print_node(node)

def print_level(level:PrivilegeLevel) -> None: # Add color by severity
    levels_colors = [
        "#FF0000",
        "#FF3300",
        "#FF6600",
        "#FF9900",
        "#FFCC00",
        "#CCFF00",
        "#99FF00",
        "#66FF00",
        "#33FF00",
        "#00FF00",
    ]
    content = Text()
    content.append(f"\n_____[{level.name}]_____", style=levels_colors[level])
    console.print(content)