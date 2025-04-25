#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <vector>
#include <string>

#define ID_LISTBOX    101
#define ID_BUTTON_ADD 102
#define ID_BUTTON_RUN 103

// Global handle to the listbox
HWND hList;

// Helper to show open-file dialog and get selected paths
std::vector<std::wstring> ShowOpenFiles(HWND hOwner) {
    OPENFILENAMEW ofn = {};
    wchar_t szFile[1024] = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = hOwner;
    ofn.lpstrFile   = szFile;
    ofn.nMaxFile    = _countof(szFile);

    // Filter: description\0pattern\0... ending with two nulls
    const wchar_t filter[] = L"SNES ROM\0*.sfc;*.smc\0All Files\0*.*\0\0";
    ofn.lpstrFilter = filter;
    ofn.Flags       = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_ALLOWMULTISELECT;

    std::vector<std::wstring> results;
    if (GetOpenFileNameW(&ofn)) {
        wchar_t *ptr = ofn.lpstrFile;
        std::wstring folder = ptr;
        ptr += folder.size() + 1;
        if (*ptr == L'\0') {
            // single file
            results.push_back(folder);
        } else {
            // multiple files
            while (*ptr) {
                results.push_back(folder + L"\\" + std::wstring(ptr));
                ptr += wcslen(ptr) + 1;
            }
        }
    }
    return results;
}

// Invoke recompiler.exe on the selected ROM
void CompileSelected(HWND hDlg) {
    int idx = (int)SendMessageW(hList, LB_GETCURSEL, 0, 0);
    if (idx == LB_ERR) {
        MessageBoxW(hDlg, L"Please select a ROM.", L"Error", MB_OK | MB_ICONWARNING);
        return;
    }
    wchar_t buf[1024];
    SendMessageW(hList, LB_GETTEXT, idx, (LPARAM)buf);
    std::wstring romPath(buf);
    std::wstring asmPath = romPath + L".asm";

    std::wstring cmdLine = L"recompiler.exe \"" + romPath + L"\" \"" + asmPath + L"\"";
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, (LPWSTR)cmdLine.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        MessageBoxW(hDlg, L"Failed to launch recompiler.exe", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    MessageBoxW(hDlg, (LPCWSTR)asmPath.c_str(), L"Compiled", MB_OK | MB_ICONINFORMATION);
}

// Window procedure
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        hList = CreateWindowW(L"LISTBOX", NULL,
            WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL,
            10, 10, 360, 200,
            hWnd, (HMENU)ID_LISTBOX, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Add ROM...",
            WS_CHILD | WS_VISIBLE,
            10, 220, 100, 30,
            hWnd, (HMENU)ID_BUTTON_ADD, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Compile",
            WS_CHILD | WS_VISIBLE,
            130, 220, 100, 30,
            hWnd, (HMENU)ID_BUTTON_RUN, NULL, NULL);
        break;
    }
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case ID_BUTTON_ADD:
            {
                auto files = ShowOpenFiles(hWnd);
                for (auto &f : files) {
                    SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)f.c_str());
                }
            }
            break;
        case ID_BUTTON_RUN:
            CompileSelected(hWnd);
            break;
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmdShow) {
    const wchar_t CLASS_NAME[] = L"RecompilerWindowClass";
    WNDCLASSW wc = {};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);

    RegisterClassW(&wc);
    HWND hWnd = CreateWindowW(CLASS_NAME, L"SNES Recompiler GUI",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_SIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
        NULL, NULL, hInst, NULL);
    if (!hWnd) return 0;
    ShowWindow(hWnd, nCmdShow);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

// Build instructions (MinGW):
// g++ -std=c++17 main_cpp_gui.cpp -o gui.exe -municode -static -static-libstdc++ -static-libgcc -lgdi32 -lcomdlg32 -lshell32

// End of project
