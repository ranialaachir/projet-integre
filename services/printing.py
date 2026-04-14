# services/printing.py
from rich.console import Console
from rich.text import Text

from entities.node import Node
from .reporting import format_node

console = Console()
def _print_element(symbol:chr, text:str, color:str="white") -> None:
    content = Text()
    content.append(f"\n[{symbol}] {text}", style=color)
    console.print(content)

def print_title(title:str) -> None:
    print("\n")
    console.rule(f"[bold blue]\n[*] {title}...[/]")
    print("\n")

def print_error(error:str) -> None:
    _print_element('-',error,'bold red')

def print_warning(warning:str) -> None:
    _print_element('-',warning,'yellow')

def print_check(check:str) -> None:
    _print_element('+',check,'green')

def print_done(done:str) -> None:
    _print_element('✓',done,'green')

def print_node(node:Node) -> None:
    console.print(format_node(node))