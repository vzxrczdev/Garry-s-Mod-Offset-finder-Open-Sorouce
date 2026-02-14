#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <iomanip>
#include <map>
#include <algorithm>

class GModOffsetScanner
{
public:
    HANDLE hProcess;
    DWORD processId;
    std::string processName;
    uintptr_t moduleBase;
    size_t moduleSize;

    GModOffsetScanner() : hProcess(nullptr), processId(0), moduleBase(0), moduleSize(0) {}

    ~GModOffsetScanner()
    {
        if (hProcess)
            CloseHandle(hProcess);
    }

    // List all running processes
    std::vector<std::pair<std::string, DWORD>> ListProcesses()
    {
        std::vector<std::pair<std::string, DWORD>> processes;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return processes;

        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &entry))
        {
            do
            {
                processes.push_back({ entry.szExeFile, entry.th32ProcessID });
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return processes;
    }

    // List modules for a process
    std::vector<std::string> ListModules(DWORD pid)
    {
        std::vector<std::string> modules;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot == INVALID_HANDLE_VALUE)
            return modules;

        MODULEENTRY32 entry;
        entry.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(snapshot, &entry))
        {
            do
            {
                modules.push_back(entry.szModule);
            } while (Module32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return modules;
    }

    // Attach to process by PID
    bool AttachToProcess(DWORD pid)
    {
        processId = pid;
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess)
        {
            std::cout << "[-] Failed to open process. Run as administrator.\n";
            return false;
        }

        // Get process name
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(snapshot, &entry))
        {
            do
            {
                if (entry.th32ProcessID == pid)
                {
                    processName = entry.szExeFile;
                    break;
                }
            } while (Process32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);

        std::cout << "[+] Attached to process: " << processName << " (PID: " << processId << ")\n";
        return true;
    }

    // Get module info
    bool GetModuleInfo(const std::string& moduleName)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        MODULEENTRY32 entry;
        entry.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(snapshot, &entry))
        {
            do
            {
                if (_stricmp(entry.szModule, moduleName.c_str()) == 0)
                {
                    moduleBase = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
                    moduleSize = entry.modBaseSize;
                    CloseHandle(snapshot);

                    std::cout << "[+] Module: " << moduleName << "\n";
                    std::cout << "    Base: 0x" << std::hex << moduleBase << "\n";
                    std::cout << "    Size: 0x" << moduleSize << std::dec << "\n";
                    return true;
                }
            } while (Module32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return false;
    }

    // Read memory
    template<typename T>
    T Read(uintptr_t address)
    {
        T value{};
        SIZE_T bytesRead;
        ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), &value, sizeof(T), &bytesRead);
        return value;
    }

    // Read bytes
    std::vector<uint8_t> ReadBytes(uintptr_t address, size_t size)
    {
        std::vector<uint8_t> buffer(size);
        SIZE_T bytesRead;
        ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), buffer.data(), size, &bytesRead);
        return buffer;
    }

    // Pattern to bytes
    std::vector<int> PatternToBytes(const std::string& pattern)
    {
        std::vector<int> bytes;
        char* start = const_cast<char*>(pattern.c_str());
        char* end = start + pattern.length();

        for (char* current = start; current < end; ++current)
        {
            if (*current == '?')
            {
                ++current;
                if (current < end && *current == '?')
                    ++current;
                bytes.push_back(-1);
            }
            else
            {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }

        return bytes;
    }

    // Find pattern
    uintptr_t FindPattern(const std::string& pattern)
    {
        auto patternBytes = PatternToBytes(pattern);
        
        // Read module in chunks to avoid memory issues
        const size_t chunkSize = 0x100000; // 1MB chunks
        
        for (size_t offset = 0; offset < moduleSize; offset += chunkSize)
        {
            size_t readSize = min(chunkSize, moduleSize - offset);
            std::vector<uint8_t> chunk = ReadBytes(moduleBase + offset, readSize);

            for (size_t i = 0; i < chunk.size() - patternBytes.size(); i++)
            {
                bool found = true;
                for (size_t j = 0; j < patternBytes.size(); j++)
                {
                    if (patternBytes[j] != -1 && chunk[i + j] != patternBytes[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                    return moduleBase + offset + i;
            }
        }

        return 0;
    }

    // Garry's Mod specific patterns (Source Engine)
    uintptr_t ScanGModEntityList()
    {
        std::cout << "\n[*] Scanning for Garry's Mod EntityList...\n";

        // Source Engine entity list patterns
        std::vector<std::string> patterns = {
            // Common Source Engine patterns
            "8B 0D ? ? ? ? 8B 01 FF 50 ? 85 C0",           // mov ecx,[addr]; mov eax,[ecx]
            "A1 ? ? ? ? 8B 14 B8 85 D2",                   // mov eax,[addr]; mov edx,[eax+edi*4]
            "8B 15 ? ? ? ? 33 C9 83 FA FF",                // mov edx,[addr]
            "8B 0D ? ? ? ? 8B 14 81",                      // mov ecx,[addr]; mov edx,[ecx+eax*4]
            // x64 patterns
            "48 8B 0D ? ? ? ? 48 85 C9 74 ? 48 8B 01",    // mov rcx,[addr]
            "4C 8B 05 ? ? ? ? 4D 85 C0",                   // mov r8,[addr]
        };

        for (const auto& pattern : patterns)
        {
            std::cout << "    Trying pattern: " << pattern.substr(0, 20) << "...\n";
            uintptr_t result = FindPattern(pattern);
            if (result)
            {
                // Check if x86 or x64
                bool is64bit = (pattern.find("48") == 0 || pattern.find("4C") == 0);
                
                if (is64bit)
                {
                    int32_t offset = Read<int32_t>(result + 3);
                    uintptr_t address = result + 7 + offset;
                    std::cout << "    [x64] Found at: 0x" << std::hex << result << "\n";
                    std::cout << "    Resolved: 0x" << address << std::dec << "\n";
                    return address;
                }
                else
                {
                    uintptr_t address = Read<uintptr_t>(result + 2);
                    std::cout << "    [x86] Found at: 0x" << std::hex << result << "\n";
                    std::cout << "    Resolved: 0x" << address << std::dec << "\n";
                    return address;
                }
            }
        }

        std::cout << "    [-] Not found\n";
        return 0;
    }

    // Scan for local player
    uintptr_t ScanGModLocalPlayer()
    {
        std::cout << "\n[*] Scanning for Garry's Mod LocalPlayer...\n";

        std::vector<std::string> patterns = {
            // Source Engine local player patterns
            "8B 0D ? ? ? ? 83 F9 FF 74 ? 8B 01",          // mov ecx,[addr]
            "A1 ? ? ? ? 83 F8 FF 74 ? 8B 08",             // mov eax,[addr]
            "8B 15 ? ? ? ? 85 D2 74 ? 8B 02",             // mov edx,[addr]
            // x64 patterns
            "48 8B 0D ? ? ? ? 48 85 C9 74 ? E8",          // mov rcx,[addr]
            "48 8B 05 ? ? ? ? 48 85 C0 74 ? 48 8B 08",    // mov rax,[addr]
        };

        for (const auto& pattern : patterns)
        {
            std::cout << "    Trying pattern: " << pattern.substr(0, 20) << "...\n";
            uintptr_t result = FindPattern(pattern);
            if (result)
            {
                bool is64bit = (pattern.find("48") == 0);
                
                if (is64bit)
                {
                    int32_t offset = Read<int32_t>(result + 3);
                    uintptr_t address = result + 7 + offset;
                    std::cout << "    [x64] Found at: 0x" << std::hex << result << "\n";
                    std::cout << "    Resolved: 0x" << address << std::dec << "\n";
                    return address;
                }
                else
                {
                    uintptr_t address = Read<uintptr_t>(result + 2);
                    std::cout << "    [x86] Found at: 0x" << std::hex << result << "\n";
                    std::cout << "    Resolved: 0x" << address << std::dec << "\n";
                    return address;
                }
            }
        }

        std::cout << "    [-] Not found\n";
        return 0;
    }

    // Scan for view matrix
    uintptr_t ScanGModViewMatrix()
    {
        std::cout << "\n[*] Scanning for Garry's Mod ViewMatrix...\n";

        std::vector<std::string> patterns = {
            // Source Engine view matrix patterns
            "F3 0F 10 05 ? ? ? ? F3 0F 11 45",            // movss xmm0,[addr]
            "0F 10 05 ? ? ? ? 0F 11 45",                  // movups xmm0,[addr]
            "F3 0F 10 0D ? ? ? ? F3 0F 59 0D",            // movss xmm1,[addr]
            // x64 patterns
            "0F 10 05 ? ? ? ? 8D 85 ? ? ? ? B9",         // movups xmm0,[addr]
            "F3 0F 10 05 ? ? ? ? F3 0F 11 85",           // movss xmm0,[addr]
        };

        for (const auto& pattern : patterns)
        {
            std::cout << "    Trying pattern: " << pattern.substr(0, 20) << "...\n";
            uintptr_t result = FindPattern(pattern);
            if (result)
            {
                int32_t offset = Read<int32_t>(result + 4);
                uintptr_t address = result + 8 + offset;
                std::cout << "    Found at: 0x" << std::hex << result << "\n";
                std::cout << "    Resolved: 0x" << address << std::dec << "\n";
                return address;
            }
        }

        std::cout << "    [-] Not found\n";
        return 0;
    }

    // Save results
    void SaveResults(const std::string& filename, uintptr_t entityList, uintptr_t localPlayer, uintptr_t viewMatrix)
    {
        std::ofstream file(filename);
        if (!file.is_open())
            return;

        file << "// Garry's Mod Offsets\n";
        file << "// Process: " << processName << "\n";
        file << "// Generated: " << __DATE__ << " " << __TIME__ << "\n\n";

        file << "[Offsets]\n";
        file << "EntityList=0x" << std::hex << entityList << "\n";
        file << "LocalPlayer=0x" << localPlayer << "\n";
        file << "ViewMatrix=0x" << viewMatrix << "\n";

        file << "\n[Module]\n";
        file << "Base=0x" << moduleBase << "\n";
        file << "Size=0x" << moduleSize << "\n";

        file << "\n[Entity] ; Source Engine typical offsets\n";
        file << "Health=0x100\n";
        file << "Team=0x104\n";
        file << "Position=0x138\n";
        file << "Dormant=0xED\n";
        file << "BoneMatrix=0x26A8\n";

        file.close();
        std::cout << "\n[+] Results saved to: " << filename << "\n";
    }

    // Generate header
    void GenerateHeader(const std::string& filename, uintptr_t entityList, uintptr_t localPlayer, uintptr_t viewMatrix)
    {
        std::ofstream file(filename);
        if (!file.is_open())
            return;

        file << "// Garry's Mod Auto-Generated Offsets\n";
        file << "// Process: " << processName << "\n\n";

        file << "#pragma once\n\n";
        file << "namespace GModOffsets\n{\n";
        file << "    // Global offsets\n";
        file << "    constexpr uintptr_t EntityList = 0x" << std::hex << entityList << ";\n";
        file << "    constexpr uintptr_t LocalPlayer = 0x" << localPlayer << ";\n";
        file << "    constexpr uintptr_t ViewMatrix = 0x" << viewMatrix << ";\n\n";

        file << "    // Source Engine entity offsets (typical values)\n";
        file << "    namespace Entity\n";
        file << "    {\n";
        file << "        constexpr uintptr_t Health = 0x100;\n";
        file << "        constexpr uintptr_t Team = 0x104;\n";
        file << "        constexpr uintptr_t Position = 0x138;\n";
        file << "        constexpr uintptr_t Dormant = 0xED;\n";
        file << "        constexpr uintptr_t BoneMatrix = 0x26A8;\n";
        file << "    }\n";
        file << "}\n";

        file.close();
        std::cout << "[+] Header generated: " << filename << "\n";
    }
};

// Interactive menu
void ShowMenu()
{
    std::cout << "\n========================================\n";
    std::cout << "       ArcticSoftwares\n";
    std::cout << "  Garry's Mod Offset Scanner\n";
    std::cout << "  Educational purposes only!\n";
    std::cout << "  Last update - 14.02.2026\n";
    std::cout << "========================================\n\n";
}

int main()
{
    ShowMenu();

    GModOffsetScanner scanner;

    // List all processes
    std::cout << "[*] Scanning for running processes...\n\n";
    auto processes = scanner.ListProcesses();

    // Filter for likely game processes
    std::vector<std::pair<std::string, DWORD>> gameProcesses;
    for (const auto& proc : processes)
    {
        std::string name = proc.first;
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        
        // Look for game-related processes
        if (name.find("gmod") != std::string::npos ||
            name.find("hl2") != std::string::npos ||
            name.find("garrysmod") != std::string::npos ||
            name.find("srcds") != std::string::npos)
        {
            gameProcesses.push_back(proc);
        }
    }

    // Show found game processes
    if (gameProcesses.empty())
    {
        std::cout << "[-] No Garry's Mod processes found!\n";
        std::cout << "\nShowing all processes instead:\n\n";
        
        // Show all processes
        for (size_t i = 0; i < processes.size() && i < 50; i++)
        {
            std::cout << "[" << (i + 1) << "] " << processes[i].first 
                      << " (PID: " << processes[i].second << ")\n";
        }
        
        std::cout << "\nEnter process number (1-" << min(processes.size(), (size_t)50) << "): ";
        int choice;
        std::cin >> choice;
        
        if (choice < 1 || choice > min(processes.size(), (size_t)50))
        {
            std::cout << "[-] Invalid choice!\n";
            std::cout << "\nPress Enter to exit...";
            std::cin.ignore();
            std::cin.get();
            return 1;
        }
        
        DWORD selectedPid = processes[choice - 1].second;
        std::string selectedName = processes[choice - 1].first;
        
        std::cout << "\n[+] Selected: " << selectedName << " (PID: " << selectedPid << ")\n";
        
        if (!scanner.AttachToProcess(selectedPid))
        {
            std::cout << "\nPress Enter to exit...";
            std::cin.ignore();
            std::cin.get();
            return 1;
        }
    }
    else
    {
        std::cout << "[+] Found Garry's Mod processes:\n\n";
        for (size_t i = 0; i < gameProcesses.size(); i++)
        {
            std::cout << "[" << (i + 1) << "] " << gameProcesses[i].first 
                      << " (PID: " << gameProcesses[i].second << ")\n";
        }
        
        std::cout << "\nSelect process (1-" << gameProcesses.size() << "): ";
        int choice;
        std::cin >> choice;
        
        if (choice < 1 || choice > gameProcesses.size())
        {
            std::cout << "[-] Invalid choice!\n";
            std::cout << "\nPress Enter to exit...";
            std::cin.ignore();
            std::cin.get();
            return 1;
        }
        
        DWORD selectedPid = gameProcesses[choice - 1].second;
        
        if (!scanner.AttachToProcess(selectedPid))
        {
            std::cout << "\nPress Enter to exit...";
            std::cin.ignore();
            std::cin.get();
            return 1;
        }
    }

    // List modules
    std::cout << "\n[*] Scanning for modules...\n\n";
    auto modules = scanner.ListModules(scanner.processId);
    
    if (modules.empty())
    {
        std::cout << "[-] No modules found!\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.ignore();
        std::cin.get();
        return 1;
    }

    // Filter for likely game modules
    std::vector<std::string> gameModules;
    for (const auto& mod : modules)
    {
        std::string name = mod;
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        
        if (name.find("client") != std::string::npos ||
            name.find("engine") != std::string::npos ||
            name.find("server") != std::string::npos ||
            name.find(".exe") != std::string::npos)
        {
            gameModules.push_back(mod);
        }
    }

    if (gameModules.empty())
        gameModules = modules;

    std::cout << "[+] Found modules:\n\n";
    for (size_t i = 0; i < gameModules.size() && i < 20; i++)
    {
        std::cout << "[" << (i + 1) << "] " << gameModules[i] << "\n";
    }
    
    std::cout << "\nSelect module (1-" << min(gameModules.size(), (size_t)20) << ") [default: 1]: ";
    std::string input;
    std::cin.ignore();
    std::getline(std::cin, input);
    
    int moduleChoice = 1;
    if (!input.empty())
    {
        try {
            moduleChoice = std::stoi(input);
        } catch (...) {
            moduleChoice = 1;
        }
    }
    
    if (moduleChoice < 1 || moduleChoice > min(gameModules.size(), (size_t)20))
        moduleChoice = 1;
    
    std::string selectedModule = gameModules[moduleChoice - 1];
    
    if (!scanner.GetModuleInfo(selectedModule))
    {
        std::cout << "[-] Failed to get module info!\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }

    // Scan for offsets
    std::cout << "\n[*] Starting Garry's Mod offset scan...\n";
    std::cout << "    This may take a few minutes...\n";

    uintptr_t entityList = scanner.ScanGModEntityList();
    uintptr_t localPlayer = scanner.ScanGModLocalPlayer();
    uintptr_t viewMatrix = scanner.ScanGModViewMatrix();

    // Display results
    std::cout << "\n========================================\n";
    std::cout << "  Scan Results\n";
    std::cout << "========================================\n";
    std::cout << "EntityList:  " << (entityList ? "FOUND" : "NOT FOUND") << "\n";
    std::cout << "LocalPlayer: " << (localPlayer ? "FOUND" : "NOT FOUND") << "\n";
    std::cout << "ViewMatrix:  " << (viewMatrix ? "FOUND" : "NOT FOUND") << "\n";

    if (entityList || localPlayer || viewMatrix)
    {
        scanner.SaveResults("gmod_offsets.ini", entityList, localPlayer, viewMatrix);
        scanner.GenerateHeader("GModOffsets.h", entityList, localPlayer, viewMatrix);

        std::cout << "\n[*] Next steps:\n";
        std::cout << "    1. Copy gmod_offsets.ini to your DLL directory\n";
        std::cout << "    2. Update Memory/Offsets.h with found values\n";
        std::cout << "    3. Build and inject your DLL\n";
        std::cout << "    4. Test ESP in Garry's Mod\n";
    }
    else
    {
        std::cout << "\n[-] No offsets found. Try:\n";
        std::cout << "    1. Make sure Garry's Mod is running and in-game\n";
        std::cout << "    2. Try different module (client.dll or engine.dll)\n";
        std::cout << "    3. Use Cheat Engine for manual scanning\n";
    }

    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}

