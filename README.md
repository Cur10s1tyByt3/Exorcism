# Exorcism - Runtime Windows Batch Deobfuscator

"When there are little demons running around with .bat crypters, you get an exorcism."

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![Language](https://img.shields.io/badge/language-C%2B%2B%2FPython-orange.svg)

**Exorcism** is the first open-source runtime Windows batch deobfuscator that uses DLL injection and function hooking to monitor and log batch file commands as they are executed by `cmd.exe`.

> [!WARNING]
> **🚨 THE BATCH FILE STILL GETS EXECUTED! 🚨**
> 
> This tool **DOES NOT** prevent malicious batch files from executing. It only logs the commands as they run. **DO NOT** use this tool on untrusted or malicious batch files unless you are in a completely isolated environment (sandboxed VM, air-gapped system, etc.).
> 
> **Use at your own risk. This tool is intended for security research, malware analysis, and educational purposes only.**

## 🎯 What is Exorcism?

Exorcism hooks into the Windows Command Processor (`cmd.exe`) at runtime to intercept and log batch commands before they are executed. Unlike static analysis tools that can be fooled by obfuscation techniques, Exorcism captures the actual commands as they are processed by the Windows command interpreter.

### Key Features

- **Runtime Analysis**: Captures commands as they are actually executed, bypassing most obfuscation techniques
- **DLL Injection**: Uses Microsoft Detours library for reliable function hooking
- **Real-time Monitoring**: Live command logging with JSON output format
- **Safe Memory Access**: Robust pointer validation and memory safety checks
- **Cross-Architecture**: Supports both x86 and x64 processes

## 🏗️ Architecture

The tool consists of two main components:

1. **Hook DLL (`cmdtest.dll`)**: A C++ DLL that hooks the `FindFixAndRun` function in `cmd.exe`
2. **Python Controller (`main.py`)**: A Python script that handles DLL injection and log monitoring

### How It Works

1. The Python controller launches a new `cmd.exe` process
2. The hook DLL is injected into the `cmd.exe` process using DLL injection
3. The DLL hooks the internal `FindFixAndRun` function using Microsoft Detours
4. Every command executed by the batch file is logged to `cmd_hook.json` before execution
5. The Python monitor displays the logged commands in real-time

## 📋 Prerequisites

- Windows 10/11 (x64)
- Visual Studio 2019/2022 with C++ development tools
- Python 3.7 or higher
- Administrator privileges (required for DLL injection)

## 🚀 Installation

### 1. Clone the Repository

```cmd
git clone https://github.com/YourUsername/Exorcism.git
cd Exorcism
```

### 2. Build the Hook DLL

1. Open `cmdtest/cmdtest.sln` in Visual Studio
2. Select **Release** configuration and **x64** platform
3. Build the solution (Ctrl+Shift+B)
4. The compiled DLL will be located at `x64/Release/cmdtest.dll`

### 3. Install Python Dependencies

```cmd
pip install -r requirements.txt
```

## 📖 Usage

### Basic Usage

1. **Run as Administrator** (required for DLL injection):
   ```cmd
   # Open Command Prompt as Administrator
   python main.py
   ```

2. **Enter the DLL path** when prompted:
   ```
   Enter the full path to the hook DLL: C:\path\to\Exorcism\x64\Release\cmdtest.dll
   ```

3. **Execute your batch file** in the monitored cmd.exe window that appears

4. **Monitor the output** in real-time as commands are logged

### Example Output

The tool logs commands in JSON format to `cmd_hook.json`:

```json
{"event_type":"hook_status","message":"FindFixAndRun hook initialized successfully"}
{"event_type":"command_execution","command":"echo Hello World","arguments":"Hello World","command_type":1}
{"event_type":"command_execution","command":"set VAR=secret_value","arguments":"VAR=secret_value","command_type":2}
{"event_type":"command_execution","command":"if exist file.txt del file.txt","arguments":"exist file.txt del file.txt","command_type":3}
```

## 🔧 Configuration

### Hook DLL Configuration

The hook DLL uses a hardcoded RVA (Relative Virtual Address) to locate the `FindFixAndRun` function:

```cpp
ULONG_PTR rva = 0x116B0;  // RVA for FindFixAndRun function
```

**Note**: This RVA is specific to certain versions of `cmd.exe`. If the hook fails, you may need to:

1. Use a debugger (x64dbg, IDA Pro) to find the current RVA for `FindFixAndRun`
2. Update the RVA value in `dllmain.cpp`
3. Rebuild the DLL

### Python Monitor Configuration

The Python script automatically:
- Cleans up previous log files
- Launches `cmd.exe` with DLL injection
- Monitors the JSON log file in real-time
- Provides a rich terminal interface

## 🛡️ Security Considerations

### For Analysts

- **Always use in isolated environments** when analyzing malicious samples
- Consider using a dedicated analysis VM that can be easily restored
- Monitor network connections and file system changes alongside command logging
- Be aware that some advanced malware may detect the hook and alter behavior

### For Developers

- The current implementation uses hardcoded RVAs which may break with Windows updates
- Consider implementing IAT (Import Address Table) hooking for better compatibility
- Add additional validation for command arguments and redirections
- Implement process monitoring for child processes spawned by batch files

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- **Better Compatibility**: Implement function name-based hooking instead of RVA (IAT (you can probably just rip it from clink src))
- **Enhanced Logging**: Add support for environment variable expansion logging
- **Process Monitoring**: Track child processes spawned by batch files
- **Network Monitoring**: Integration with network activity monitoring
- **GUI Interface**: Develop a graphical user interface for easier usage

## 📝 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Microsoft Detours library for function hooking capabilities
- nlohmann/json library for safe JSON handling
- Windows XP source code leak for cmd.exe internal structure insights
- The security research community for inspiration and guidance

## ⚖️ Legal Disclaimer

This tool is intended for:
- Security research
- Malware analysis in controlled environments  
- Educational purposes
- Legitimate batch file debugging

**Users are solely responsible for compliance with applicable laws and regulations. The authors assume no liability for misuse of this software.**

---

**Remember: The batch file WILL execute! Use appropriate safety measures!**
