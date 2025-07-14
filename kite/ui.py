from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt


console = Console(emoji=False)


def prompt(prompt):
    return Prompt.ask(prompt)


def confirm(prompt, default):
    return Confirm.ask(prompt, default=default)


def print(message):
    console.print(message)


def print_panel(message, title, border_style="blue"):
    console.print(Panel(message, title=title, border_style=border_style))
