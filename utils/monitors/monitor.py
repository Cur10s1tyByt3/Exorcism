import time
import os
import json
import logging
from datetime import datetime
from utils.ui.ui import console


class CmdLogMonitor:
    # all built in cmd commands
    # https://blog.brainasoft.com/all-internal-commands-of-cmd/
    BUILTIN_COMMANDS = {
        "assoc",
        "call",
        "cd",
        "cls",
        "color",
        "copy",
        "date",
        "del",
        "dir",
        "echo",
        "endlocal",
        "erase",
        "exit",
        "for",
        "ftype",
        "goto",
        "if",
        "md",
        "mklink",
        "move",
        "path",
        "pause",
        "popd",
        "prompt",
        "pushd",
        "rem",
        "ren",
        "rd",
        "set",
        "setlocal",
        "shift",
        "start",
        "time",
        "title",
        "type",
        "ver",
        "verify",
        "vol",
    }

    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        self.last_position = 0
        self.should_stop = False
        self.command_count = 0
        self.hook_status = "Unknown"

    def _read_new_content(self):
        """Read only new content from the log file."""
        if not os.path.exists(self.log_file_path):
            return []

        try:
            with open(self.log_file_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.last_position)
                new_content = f.read()
                # update position after reading
                self.last_position = f.tell()

                if new_content:
                    # split into lines and get rid of any empty ones
                    lines = [
                        line.strip()
                        for line in new_content.splitlines()
                        if line.strip()
                    ]
                    return lines
                return []

        except Exception as e:
            logging.error(f"Error reading log file: {e}")
            return []

    def _is_builtin_command(self, command: str) -> bool:
        """Check if a command is a built-in CMD command."""
        if not command:
            return False

        cmd_name = command.lower().strip()

        if cmd_name.startswith("echo") or cmd_name.startswith("rem"):
            return True

        return cmd_name in self.BUILTIN_COMMANDS

    def _colorize_command(self, command: str) -> str:
        if self._is_builtin_command(command):
            return f"[success]{command}[/success]"
        else:
            return f"[danger]{command}[/danger]"

    def _format_and_print_entry(self, line: str):
        try:
            entry = json.loads(line)
            timestamp = datetime.now().strftime("%H:%M:%S")
            event_type = entry.get("event_type", "unknown")

            if event_type == "hook_status":
                message = entry.get("message", "")
                if "initialized successfully" in message:
                    self.hook_status = "Active"
                    console.print(
                        f"[{timestamp}] [success]Hook initialized successfully[/success]"
                    )
                elif "being removed" in message:
                    self.hook_status = "Removed"
                    console.print(
                        f"[{timestamp}] [warning]Hook being removed[/warning]"
                    )
                    self.should_stop = True
                else:
                    console.print(f"[{timestamp}] Hook status: {message}")

            elif event_type == "command_execution":
                command = entry.get("command", "")
                arguments = entry.get("arguments", "")

                args_display = arguments.strip() if arguments else ""

                colored_command = self._colorize_command(command)

                if args_display:
                    full_command_display = f"{colored_command} {args_display}"
                else:
                    full_command_display = colored_command

                self.command_count += 1

                if not self._is_builtin_command(command):
                    indicator = " [highlight]\\[CUSTOM][/highlight]"
                    console.print(
                        f"[{timestamp}] Command: {full_command_display}{indicator}"
                    )
                else:
                    console.print(f"[{timestamp}] Command: {full_command_display}")

            else:
                console.print(f"[{timestamp}] [info]{event_type}[/info]: {str(entry)}")

        except json.JSONDecodeError:
            timestamp = datetime.now().strftime("%H:%M:%S")
            console.print(f"[{timestamp}] [warning]Raw[/warning]: {line}")

    def start_monitoring(self):
        if not os.path.exists(self.log_file_path):
            open(self.log_file_path, "a").close()
            logging.info("Created log file (DLL may not be injected yet)")

        logging.info(f"Monitoring: {self.log_file_path}")
        print("Watching for commands... (Press Ctrl+C to stop)")
        console.print(
            "[success]Green[/success] = Built-in commands, [danger]Red[/danger] = Custom/External commands"
        )
        print()

        if os.path.exists(self.log_file_path):
            try:
                with open(
                    self.log_file_path, "r", encoding="utf-8", errors="ignore"
                ) as f:
                    existing_content = f.read()
                    self.last_position = f.tell()

                    if existing_content:
                        existing_lines = [
                            line.strip()
                            for line in existing_content.splitlines()
                            if line.strip()
                        ]
                        if existing_lines:
                            logging.info(
                                f"Found {len(existing_lines)} existing entries:"
                            )
                            for line in existing_lines:
                                self._format_and_print_entry(line)
            except Exception as e:
                logging.error(f"Error reading existing content: {e}")

        try:
            while not self.should_stop:
                new_lines = self._read_new_content()
                for line in new_lines:
                    self._format_and_print_entry(line)
                    if self.should_stop:
                        break

                time.sleep(0.5)

        except KeyboardInterrupt:
            print()
            logging.info("Monitoring stopped by user")
        except Exception as e:
            logging.error(f"Error during monitoring: {e}")
        finally:
            self.stop_monitoring()

    def stop_monitoring(self):
        """Stop monitoring the log file."""
        self.should_stop = True

        print()
        logging.info("Final Summary:")
        logging.info(f"  Hook Status: {self.hook_status}")
        logging.info(f"  Total Commands: {self.command_count}")
        logging.info(f"  Log File: {self.log_file_path}")
        logging.info("Monitoring stopped.")
