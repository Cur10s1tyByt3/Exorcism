// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <windows.h>
#include <detours.h>
#include <fstream>
#include "json.hpp"  // nlohmann/json library

// Disable deprecation warnings for this file
#define _CRT_SECURE_NO_WARNINGS

typedef HANDLE CRTHANDLE;

// https://github.com/tongzx/nt5src/blob/master/Source/XPSP1/NT/base/cmd/cmd.c#L1220
// All of windows binaries have the pdb files and winxp got leaked so this was 100000x easier to make.
// I have 0 knowledge in reverse engineering except interpreted languages and the occasional .net binary.
// But basically, from what I can understand.

// Cmd calls BatLoop which then loops through the bat file and parses each command.
// Cmd then calls Dispatch on the parsed command to execute it.
// Dispatch then calls FindFixAndRun to ACTUALLY execute the command once all the variables have been expanded.
// So basically, we just internally hook FindFixAndRun to log the command before it is executed.
// Could you imagine that windows basically hasn't updated cmd.exe in over 20 years? I can!
// Also you might be asking, is this a good way of doing trampoline hooks? NO. I'M USING THE RVA THAT X64 DBG GAVE ME.
// The easiest and best way to imrpove this would be to scratch away the random RVA and use the function name instead.
// This would allow you to ALWAYS hook the function without having to update the RVA every time cmd.exe is updated.
// But, we don't REALLY have to worry about this since cmd.exe is basically a dead project by microsoft.
// So basically if you're reading this yap fest and you're wondering why the program is broken, go download the .pdb file from cmd.exe from windows
// and find the new RVA value for FindFixAndRun OR implement IAT to find the function by name instead of RVA. (Thank you c5 for teaching me ts a long ass time ago).
typedef int (*FindFixAndRunFunc)(struct cmdnode* cmdnode);
FindFixAndRunFunc OriginalFindFixAndRun = nullptr;

// Log file
std::ofstream logFile("cmd_hook.json", std::ios::app);

using json = nlohmann::json;

// Helper function to log JSON entry using nlohmann/json for safety
void LogJsonEntry(const std::string& event_type, const std::string& command, const std::string& arguments, int cmd_type, const std::string& message = "") {
    try {
        json j;
        j["event_type"] = event_type;
        
        if (!command.empty()) {
            j["command"] = command;
        }
        
        if (!arguments.empty()) {
            j["arguments"] = arguments;
        }
        
        if (cmd_type != -1) {
            j["command_type"] = cmd_type;
        }
        
        if (!message.empty()) {
            j["message"] = message;
        }
        
        logFile << j.dump() << std::endl;
        logFile.flush();
    }
    catch (const std::exception& e) {
        // Fallback logging if JSON creation fails
        logFile << "{\"error\":\"JSON serialization failed\",\"exception\":\"" << e.what() << "\"}" << std::endl;
        logFile.flush();
    }
}

// Structures based on your definitions
struct savtype {
    TCHAR* saveptrs[12];
};

struct relem {
    CRTHANDLE rdhndl;       // handle to be redirected
    TCHAR* fname;           // filename (or &n)
    CRTHANDLE svhndl;       // where orig handle is saved
    int flag;               // Append flag
    TCHAR rdop;             // Type ('>' | '<')
    struct relem* nxt;      // Next structure
};

struct node {               // Used for operators
    int type;               // Type of operator
    struct savtype save;    // FOR processor saves orig strings here
    struct relem* rio;      // M022 - Linked redirection list
    struct node* lhs;       // Ptr to left hand side of the operator
    struct node* rhs;       // Ptr to right hand side of the operator
    INT_PTR extra[4];       // M022 - Padding now needed
};

struct cmdnode {
    int type;               // Type of command
    struct savtype save;    // FOR processor saves orig strings here
    struct relem* rio;      // M022 - Linked redirection list
    PTCHAR cmdline;         // Ptr to command line
    PTCHAR argptr;          // Ptr to type of command
    int flag;               // M022 - Valid for cond and goto types
    int cmdarg;             // M022 - Argument to STRTYP routine
};

// Safe pointer checking function
bool IsSafePointer(void* ptr) {
    if (!ptr || (ULONG_PTR)ptr < 0x10000 || (ULONG_PTR)ptr > 0x7FFFFFFFFFFF) {
        return false;
    }

    // Use VirtualQuery to check if memory is accessible
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) {
        return false;
    }

    return (mbi.State == MEM_COMMIT) &&
        (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
}

// Safe string length check
size_t SafeStrLen(const char* str, size_t maxLen = 1000) {
    if (!IsSafePointer((void*)str)) return 0;
    size_t len = 0;
    while (len < maxLen && str[len] != '\0') len++;
    return len;
}

// Safe wide string length check  
size_t SafeWcsLen(const wchar_t* wstr, size_t maxLen = 500) {
    if (!IsSafePointer((void*)wstr)) return 0;
    size_t len = 0;
    while (len < maxLen && wstr[len] != L'\0') len++;
    return len;
}

// Helper function to safely extract string from TCHAR pointer
std::string SafeExtractString(PTCHAR str, size_t maxLen = 1000) {
    if (!IsSafePointer(str)) return "";
    
#ifdef UNICODE
    size_t len = SafeWcsLen(str, maxLen);
    if (len == 0) return "";
    
    // Convert wide string to narrow string
    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, str, (int)len, nullptr, 0, nullptr, nullptr);
    if (bufferSize <= 0) return "";
    
    std::string result(bufferSize, 0);
    WideCharToMultiByte(CP_UTF8, 0, str, (int)len, &result[0], bufferSize, nullptr, nullptr);
    return result;
#else
    size_t len = SafeStrLen(str, maxLen);
    if (len == 0) return "";
    return std::string(str, len);
#endif
}

// Our hooked FindFixAndRun function - logs every command before execution
int HookedFindFixAndRun(struct cmdnode* cmdnode) {
    if (cmdnode != nullptr && IsSafePointer(cmdnode)) {
        // Extract command and arguments using our safe helper function
        std::string command = SafeExtractString(cmdnode->cmdline, 500);
        std::string arguments = SafeExtractString(cmdnode->argptr, 500);
        
        // Log the command before execution if we have a valid command
        if (!command.empty()) {
            LogJsonEntry("command_execution", command, arguments, cmdnode->type);
        }
    }

    // Call original function
    return OriginalFindFixAndRun(cmdnode);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
    {
        // Get the base address of cmd.exe
        HMODULE cmdModule = GetModuleHandle(nullptr);
        ULONG_PTR baseAddress = (ULONG_PTR)cmdModule;
        ULONG_PTR rva = 0x116B0;  // RVA for FindFixAndRun function from X64dbg. (idk how to get it from ida lmfao)

        OriginalFindFixAndRun = (FindFixAndRunFunc)(baseAddress + rva);

        // Hook the function
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OriginalFindFixAndRun, HookedFindFixAndRun);
        LONG error = DetourTransactionCommit();

        if (error == NO_ERROR) {
            LogJsonEntry("hook_status", "", "", -1, "FindFixAndRun hook initialized successfully");
        }
        else {
            LogJsonEntry("hook_error", "", "", -1, "Failed to initialize FindFixAndRun hook, error: " + std::to_string(error));
        }
    }
    break;

    case DLL_PROCESS_DETACH:
        // Log hook removal
        LogJsonEntry("hook_status", "", "", -1, "FindFixAndRun hook being removed");
        
        // Unhook
        if (OriginalFindFixAndRun) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(&(PVOID&)OriginalFindFixAndRun, HookedFindFixAndRun);
            DetourTransactionCommit();
        }
        logFile.close();
        break;
    }
    return TRUE;

}