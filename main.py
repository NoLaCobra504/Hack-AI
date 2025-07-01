import click

"""
AI-Powered Ethical Hacking Automation Tool

This is the main entry point for the command-line interface. Use `python main.py --help` for available commands.
"""

@click.group()
def cli():
    """AI-Powered Ethical Hacking Automation Tool CLI"""
    pass

@cli.command()
def version():
    """Show the tool version."""
    click.echo("AI Ethical Hacking Tool v0.1.0")

if __name__ == "__main__":
    cli() 