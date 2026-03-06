"""
CLI entry point for envault.
Commands: lock, unlock, view, share, pull
"""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from . import __version__
from .vault import lock, unlock, view, parse_env, mask_value
from .share import export_string, import_string, export_file, string_size_kb

console = Console(force_terminal=True)

BANNER = r"""
  _____  _   _  __   __  ___   _   _  _  _____
 | ____|| \ | | \ \ / / /   \ | | | || ||_   _|
 |  _|  |  \| |  \ V / | (=) || |_| || |  | |
 |_____||_|\__|   \_/   \___/ |_____||_|  |_|
"""


def _print_banner():
    console.print(BANNER, style="bold cyan")
    console.print(f"  v{__version__} - AES-256 .env encryption & secure sharing\n", style="dim")


def _prompt_password(confirm: bool = False, label: str = "Password") -> str:
    password = click.prompt(label, hide_input=True)
    if confirm:
        password2 = click.prompt("Confirm password", hide_input=True)
        if password != password2:
            console.print("[red]Passwords do not match.[/red]")
            sys.exit(1)
    if len(password) < 8:
        console.print("[yellow]Warning: password is shorter than 8 characters.[/yellow]")
    return password


@click.group()
@click.version_option(__version__, prog_name="envault")
def cli():
    """envault — Encrypt and securely share .env files using AES-256-GCM."""
    pass


@cli.command()
@click.argument("env_file", default=".env", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", default=None, type=click.Path(path_type=Path), help="Output vault file path")
@click.option("--password", "-p", default=None, envvar="ENVAULT_PASSWORD", help="Encryption password")
@click.option("--overwrite", is_flag=True, help="Overwrite existing vault file")
@click.option("--no-banner", is_flag=True, help="Suppress banner")
def lock(env_file, output, password, overwrite, no_banner):
    """Encrypt ENV_FILE into a .vault file.

    Example:
      envault lock .env
      envault lock .env --output secrets.vault
    """
    if not no_banner:
        _print_banner()

    if not password:
        password = _prompt_password(confirm=True)

    try:
        from .vault import lock as _lock
        vault_path = _lock(env_file, password, output=output, overwrite=overwrite)
    except FileExistsError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    console.print(f"[green]Locked:[/green] [cyan]{env_file}[/cyan] -> [bold]{vault_path}[/bold]")
    console.print(f"[dim]Encryption: AES-256-GCM | KDF: PBKDF2-SHA256 (600,000 iterations)[/dim]")
    console.print()
    console.print("[yellow]Tip:[/yellow] Add [bold].env.vault[/bold] to version control, keep [bold].env[/bold] in .gitignore")


@cli.command()
@click.argument("vault_file", default=".env.vault", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", default=None, type=click.Path(path_type=Path), help="Output .env file path")
@click.option("--password", "-p", default=None, envvar="ENVAULT_PASSWORD", help="Decryption password")
@click.option("--overwrite", is_flag=True, help="Overwrite existing .env file")
@click.option("--no-banner", is_flag=True, help="Suppress banner")
def unlock(vault_file, output, password, overwrite, no_banner):
    """Decrypt VAULT_FILE back to a .env file.

    Example:
      envault unlock .env.vault
      envault unlock secrets.vault --output .env.production
    """
    if not no_banner:
        _print_banner()

    if not password:
        password = _prompt_password(confirm=False)

    try:
        from .vault import unlock as _unlock
        out_path = _unlock(vault_file, password, output=output, overwrite=overwrite)
    except FileExistsError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    console.print(f"[green]Unlocked:[/green] [cyan]{vault_file}[/cyan] -> [bold]{out_path}[/bold]")


@cli.command()
@click.argument("vault_file", default=".env.vault", type=click.Path(exists=True, path_type=Path))
@click.option("--password", "-p", default=None, envvar="ENVAULT_PASSWORD", help="Decryption password")
@click.option("--show-values", is_flag=True, help="Show actual values (default: masked)")
@click.option("--no-banner", is_flag=True, help="Suppress banner")
def view(vault_file, password, show_values, no_banner):
    """View decrypted contents of a vault file without writing to disk.

    Example:
      envault view .env.vault
      envault view .env.vault --show-values
    """
    if not no_banner:
        _print_banner()

    if not password:
        password = _prompt_password(confirm=False)

    try:
        from .vault import view as _view, parse_env, mask_value
        content = _view(vault_file, password)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    env_vars = parse_env(content)

    table = Table(
        title=f"[cyan]{vault_file}[/cyan] ({len(env_vars)} variables)",
        box=box.ASCII,
        show_lines=False,
    )
    table.add_column("Variable", style="bold cyan", no_wrap=True)
    table.add_column("Value", style="yellow" if show_values else "dim")

    for key, value in sorted(env_vars.items()):
        display_value = value if show_values else mask_value(value)
        table.add_row(key, display_value)

    console.print(table)

    if not show_values:
        console.print("\n[dim]Use --show-values to reveal actual values[/dim]")


@cli.command()
@click.argument("env_file", default=".env", type=click.Path(exists=True, path_type=Path))
@click.option("--password", "-p", default=None, envvar="ENVAULT_PASSWORD", help="Encryption password")
@click.option("--string", "as_string", is_flag=True, help="Output as copy-paste string instead of file")
@click.option("--output", "-o", default=None, type=click.Path(path_type=Path), help="Output file path (.envshare)")
@click.option("--no-banner", is_flag=True, help="Suppress banner")
def share(env_file, password, as_string, output, no_banner):
    """Encrypt ENV_FILE into a shareable format.

    File mode (default): creates a .envshare binary file.
    String mode: outputs a base64 string you can copy-paste anywhere.

    Examples:
      envault share .env
      envault share .env --string
      envault share .env --output team-secrets.envshare
    """
    if not no_banner:
        _print_banner()

    if not password:
        password = _prompt_password(confirm=True)

    try:
        if as_string:
            share_str = export_string(env_file, password)
            size_kb = string_size_kb(share_str)
            console.print()
            console.print(Panel(
                f"[bold green]{share_str}[/bold green]",
                title="[yellow]Share String[/yellow]",
                subtitle=f"[dim]{size_kb:.1f} KB — copy and send to teammate[/dim]",
                border_style="cyan",
            ))
            console.print()
            console.print("[dim]Recipient runs:[/dim] [bold]envault pull --string[/bold]")
        else:
            out_path = export_file(env_file, password, output=output)
            console.print(f"[green]Share file created:[/green] [bold]{out_path}[/bold]")
            console.print(f"[dim]Send this file to your teammate. They run:[/dim]")
            console.print(f"  [bold]envault pull {out_path}[/bold]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("source", default=None, required=False, type=click.Path(path_type=Path))
@click.option("--password", "-p", default=None, envvar="ENVAULT_PASSWORD", help="Decryption password")
@click.option("--string", "as_string", is_flag=True, help="Import from a share string (paste interactively)")
@click.option("--output", "-o", default=None, type=click.Path(path_type=Path), help="Output .env file path")
@click.option("--overwrite", is_flag=True, help="Overwrite existing .env file")
@click.option("--no-banner", is_flag=True, help="Suppress banner")
def pull(source, password, as_string, output, overwrite, no_banner):
    """Import an env file from a share string or .envshare file.

    Examples:
      envault pull team-secrets.envshare
      envault pull --string
    """
    if not no_banner:
        _print_banner()

    if not password:
        password = _prompt_password(confirm=False)

    out_path = output or Path(".env")
    if out_path.exists() and not overwrite:
        console.print(f"[red]{out_path} already exists. Use --overwrite to replace it.[/red]")
        sys.exit(1)

    try:
        if as_string:
            console.print("[dim]Paste the share string and press Enter:[/dim]")
            share_str = click.prompt("", hide_input=False, prompt_suffix="")
            _, out = import_string(share_str.strip(), password, output=out_path)
            console.print(f"\n[green]Imported:[/green] [bold]{out}[/bold]")
        elif source:
            if not source.exists():
                console.print(f"[red]File not found: {source}[/red]")
                sys.exit(1)
            # .envshare is a raw vault binary — just unlock it
            from .vault import unlock as _unlock
            out = _unlock(source, password, output=out_path, overwrite=overwrite)
            console.print(f"[green]Imported:[/green] [bold]{out}[/bold]")
        else:
            console.print("[red]Provide a SOURCE file or use --string[/red]")
            sys.exit(1)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
