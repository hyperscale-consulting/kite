from prompt_toolkit import PromptSession
from prompt_toolkit.validation import Validator
from rich.console import Console
from rich.panel import Panel

console = Console(emoji=False)
prompt_session = PromptSession()
confirm_session = PromptSession()


def prompt(prompt, default=None):
    kwargs = default and dict(default=default) or {}
    return prompt_session.prompt(f"{prompt}: ", **kwargs)


def _is_yes_no(text):
    return text.lower() in ("yes", "y", "no", "n")


def confirm(prompt, default=None):
    answer = confirm_session.prompt(
        f"{prompt} [y/n]: ",
        validator=Validator.from_callable(
            _is_yes_no,
            error_message="Please enter 'yes' or 'no'.",
            move_cursor_to_end=True,
        ),
        validate_while_typing=True,
    )
    return answer.lower() in ("yes", "y")


def print(message):
    console.print(message)


def print_panel(message, title, border_style="blue"):
    console.print(Panel(message, title=title, border_style=border_style))
