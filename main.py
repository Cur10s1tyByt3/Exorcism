import os
import time
import logging
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from rich.progress import track
from rich.table import Table
from utils.handlers.injection_handler import inject_dll, launch_cmd_and_get_pid
from utils.monitors.monitor import CmdLogMonitor
from utils.ui.ui import console


def launch_cmd_and_inject(dll_path: str) -> bool:

    logging.info(f"Launching cmd.exe...")

    try:
        process, pid = launch_cmd_and_get_pid()

        if process is None or pid is None:
            logging.error("Failed to launch cmd.exe")
            return False

        logging.info(f"CMD started with PID: {pid}")

        logging.info("Injecting DLL...")
        if inject_dll(dll_path, process_id=pid):
            logging.info("DLL injection successful!")
            time.sleep(1)
            return True
        else:
            logging.error("DLL injection failed!")
            process.terminate()
            return False

    except Exception as e:
        logging.error(f"Error launching cmd: {e}")
        return False


def main():
    """
    Main application entry point.
    """
    # Header panel
    header_text = Text("CMD Hook & Monitor", style="bold cyan")
    subtitle_text = Text("DLL Injection and Command Monitoring Tool", style="dim")

    console.print()
    console.print(
        Panel(f"{header_text}\n{subtitle_text}", style="cyan", padding=(1, 2))
    )

    # Description
    console.print(
        "\n[dim]This tool will inject a DLL into cmd.exe and monitor command activity.[/dim]"
    )
    console.print(
        "[dim]The DLL should write command logs to 'cmd_hook.json' in the current directory.[/dim]\n"
    )

    # Configuration table
    config_table = Table(show_header=False, box=None, padding=(0, 1))
    config_table.add_column("Icon", style="bold")
    config_table.add_column("Setting", style="cyan")
    config_table.add_column("Value", style="white")

    config_table.add_row("🎯", "Target:", "cmd.exe processes")
    config_table.add_row("📁", "Log File:", os.path.join(os.getcwd(), "cmd_hook.json"))
    config_table.add_row("⚡", "Mode:", "Real-time command monitoring")

    console.print(
        Panel(config_table, title="[bold]📋 Configuration[/bold]", style="blue")
    )
    console.print()

    while True:
        dll_path = Prompt.ask(
            "[bold yellow]Enter the full path to the hook DLL[/bold yellow]"
        ).strip('"')

        if not dll_path:
            console.print("[warning]Please enter a valid path.[/warning]")
            continue

        if not os.path.exists(dll_path):
            console.print(f"[danger]DLL file not found: {dll_path}[/danger]")
            console.print("[dim]Please check the path and try again.[/dim]")
            continue

        if not dll_path.lower().endswith(".dll"):
            console.print(f"[danger]File must be a .dll file: {dll_path}[/danger]")
            continue

        # DLL validation info
        dll_table = Table(show_header=False, box=None, padding=(0, 1))
        dll_table.add_column("Label", style="cyan")
        dll_table.add_column("Value", style="white")

        dll_table.add_row("File:", os.path.basename(dll_path))
        dll_table.add_row("Size:", f"{os.path.getsize(dll_path):,} bytes")
        dll_table.add_row("Path:", dll_path)

        console.print(
            Panel(
                dll_table,
                title="[bold green]✅ DLL Validated[/bold green]",
                style="green",
            )
        )
        console.print()
        break

    success = False

    log_file_path = os.path.join(os.getcwd(), "cmd_hook.json")
    try:
        if os.path.exists(log_file_path):
            os.remove(log_file_path)
            logging.info("Cleaned up previous log file")
    except Exception as e:
        logging.warning(f"Could not clean up previous log file: {e}")

    console.print()
    success = launch_cmd_and_inject(dll_path)

    if success:
        console.print()
        logging.info("Starting log monitor...")
        logging.info(f"   Log file: {log_file_path}")
        console.print("[dim]   Press Ctrl+C to stop monitoring...[/dim]")
        console.print()

        monitor = CmdLogMonitor(log_file_path)
        try:
            monitor.start_monitoring()
        except KeyboardInterrupt:
            console.print()
            logging.info("Monitoring stopped by user")
            monitor.stop_monitoring()
    else:
        console.print()
        logging.error("Failed to launch and inject DLL")
        console.print("[danger]Please check the DLL file and try again.[/danger]")


if __name__ == "__main__":
    main()
