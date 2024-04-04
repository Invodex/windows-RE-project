#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <psapi.h>

// Link with ntdll.lib and psapi.lib for accessing system APIs and process information
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

// Declaration of NtQueryInformationProcess from the Windows Native API (NTAPI) for querying process information
extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength);

// Function to list all running processes along with their Process ID (PID) and name
void ListProcesses() {
	DWORD processes[1024], needed, cProcesses;
	unsigned int i;

	// Enumerate all processes
	if (!EnumProcesses(processes, sizeof(processes), &needed)) {
		std::cerr << "Failed to enumerate processes." << std::endl;
		return;
    }

    // Calculate how many process identifiers were returned
	cProcesses = needed / sizeof(DWORD);

	std::cout << "Process list:" << std::endl;
	// Iterate over each process to get its name and PID
	for (i = 0; i < cProcesses; i++) {
		if (processes[i] != 0) {
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
			TCHAR processName[MAX_PATH] = TEXT("<unknown>");

			// If process handle is valid, attempt to get the process name
			if (hProcess != NULL) {
				HMODULE hMod;
				DWORD cbNeeded;

				// Get the first module for the process (which is the executable itself)
				if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
					GetModuleBaseName(hProcess, hMod, processName, sizeof(processName) / sizeof(TCHAR));
				}
				CloseHandle(hProcess);
			}
			// Print the process name and PID
			std::wcout << "  PID: " << processes[i] << "\tName: " << processName << std::endl;
		}
	}
}

// Function to read specific details from the PEB (Process Environment Block) of a given process
void ReadPEBDetails(HANDLE processHandle) {
    PROCESS_BASIC_INFORMATION pbi;
    ZeroMemory(&pbi, sizeof(PROCESS_BASIC_INFORMATION));

    // Query the process for its basic information to get the address of its PEB
	if (NT_SUCCESS(NtQueryInformationProcess(processHandle, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr))) {
		PEB peb;
        SIZE_T bytesRead;

        // Read the PEB from the process's memory
        if (ReadProcessMemory(processHandle, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
            // Output specific fields from the PEB
            std::cout << "LDR: " << peb.Ldr << std::endl;
            std::cout << "Being Debugged: " << static_cast<unsigned>(peb.BeingDebugged) << std::endl;
            std::cout << "ProcessParameters: " << peb.ProcessParameters << std::endl;
            std::cout << "AtlThunkSListPtr: " << peb.AtlThunkSListPtr << std::endl;
            std::cout << "PostProcessInitRoutine: " << peb.PostProcessInitRoutine << std::endl;
            std::cout << "SessionId: " << peb.SessionId << std::endl;
        } else {
            std::cerr << "Failed to read PEB." << std::endl;
        }
    } else {
        std::cerr << "Failed to query process information." << std::endl;
    }
}

// Main function: Lists processes, then reads and displays PEB details for a chosen process
int main() {
    ListProcesses(); // List processes before asking the user to choose one

    std::cout << "Enter the PID of the process: ";
    DWORD pid;
    std::cin >> pid;

    // Open the chosen process with query and read permissions
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (processHandle != NULL) {
        ReadPEBDetails(processHandle); // Read and display the PEB details
        CloseHandle(processHandle);
    } else {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
    }

    // Wait for user to press Enter to exit
    std::cout << "Press Enter to exit...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();

    return 0;
}

