# ModuleGrabber

This reads the loaded modules of a process, given the process ID.
- This uses `NtQueryInformationProcess` to obtain the PEB of the process, and proceeds to use `ReadProcessMemory` to read the necessary data.
- This uses undocumented structs:
    - `PEB_LDR_DATA`, obtained from [here](https://www.nirsoft.net/kernel_struct/vista/PEB_LDR_DATA.html)
    - `LDR_DATA_TABLE_ENTRY`, obtained from [here](https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html)