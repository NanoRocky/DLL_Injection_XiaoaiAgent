#pragma once
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Windows 7+：QueryFullProcessImageNameW / DebugSetProcessKillOnExit 等
#endif
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <cstdlib>  // _wtoi
#include <cwchar>   // _wcsicmp

// =============================================================================
//  多模式注入器核心
//
//  一个可执行文件同时支持四种运行模式：
//    1. 直接启动 (双击/无参数或 --launch)
//         经典 Launcher：从注册表读取目标路径 → 挂起启动 → 远程注入 → 恢复。
//         缺点：只覆盖“由本注入器亲自启动”的那一次，目标自拉起/开始菜单/
//         更新器等其它启动路径都会绕开。为向后兼容保留。
//
//    2. IFEO 调试器模式 (由 Windows 以 `注入器.exe "目标全路径" [参数...]` 调用)
//         当目标 EXE 在 IFEO 中登记了 Debugger 后，无论谁启动目标，Windows 都会
//         先启动本注入器并把目标命令行作为参数传入。此模式下我们用
//         DEBUG_ONLY_THIS_PROCESS 创建真正的目标进程（该标志会绕过 IFEO 重定向，
//         从而避免无限递归），在加载器断点处注入 DLL，然后分离，目标照常运行。
//
//    3. --install    将本注入器登记为目标 EXE 的 IFEO Debugger（需要管理员，自动提权）。
//    4. --uninstall  移除该 IFEO 登记。
// =============================================================================

// ---------- 通用小工具 ----------

// 本模块（注入器自身）完整路径（宽字符）。
inline std::wstring GetSelfPathW()
{
    wchar_t buffer[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, buffer, MAX_PATH);
    return std::wstring(buffer, n);
}

// 本模块所在目录（宽字符，不含结尾反斜杠）。
inline std::wstring GetSelfDirW()
{
    std::wstring path = GetSelfPathW();
    std::wstring::size_type pos = path.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? path.substr(0, pos) : L"";
}

// 从注册表 App Paths 读取安装目录（ANSI，保持与旧接口一致）。
inline std::string GetExecutablePathFromRegistry(const std::string &subKey, const std::string &valueName)
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return "";

    char buffer[MAX_PATH];
    DWORD bufferSize = sizeof(buffer);
    DWORD valueType = 0;
    if (RegQueryValueExA(hKey, valueName.c_str(), NULL, &valueType, reinterpret_cast<LPBYTE>(buffer), &bufferSize) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return "";
    }
    if ((valueType != REG_SZ && valueType != REG_EXPAND_SZ) || bufferSize == 0)
    {
        RegCloseKey(hKey);
        return "";
    }

    size_t stringLength = (bufferSize < sizeof(buffer)) ? static_cast<size_t>(bufferSize) : (sizeof(buffer) - 1);
    buffer[stringLength] = '\0';
    if (stringLength > 0 && buffer[stringLength - 1] == '\0')
        --stringLength;

    RegCloseKey(hKey);
    return std::string(buffer, stringLength);
}

// 定位待注入的 DLL（始终取注入器同级目录下的 msimg32.dll）。
inline std::wstring GetInjectDllPath()
{
    return GetSelfDirW() + L"\\msimg32.dll";
}

inline bool FileExistsW(const std::wstring &path)
{
    DWORD a = GetFileAttributesW(path.c_str());
    return (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

// ---------- 位数判定：注入器与目标位数必须一致，否则 LoadLibrary 存根地址无效 ----------

// 返回目标进程是否与本注入器位数一致（一致才允许注入）。
inline bool ProcessBitnessMatchesSelf(HANDLE hProcess)
{
    BOOL selfWow = FALSE, targetWow = FALSE;
    // 在 64 位系统上：64 位进程 IsWow64Process==FALSE，32 位进程==TRUE。
    // 本注入器与目标的 Wow64 状态一致即视为同位数（同一操作系统下成立）。
    if (!IsWow64Process(GetCurrentProcess(), &selfWow))
        return true; // 判定失败时不阻断，交由注入结果决定
    if (!IsWow64Process(hProcess, &targetWow))
        return true;
    return (selfWow == targetWow);
}

// ---------- 核心：向已打开的进程注入 DLL（LoadLibraryW 远程线程） ----------

inline bool InjectDllIntoProcess(HANDLE hProcess, const std::wstring &dllPath)
{
    if (!ProcessBitnessMatchesSelf(hProcess))
        return false; // 位数不匹配，跳过注入（调用方仍会让目标继续运行）

    SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(hProcess, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote)
        return false;

    bool ok = false;
    if (WriteProcessMemory(hProcess, remote, dllPath.c_str(), bytes, NULL))
    {
        FARPROC pLoadLib = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
        if (pLoadLib)
        {
            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                                (LPTHREAD_START_ROUTINE)pLoadLib, remote, 0, NULL);
            if (hThread)
            {
                WaitForSingleObject(hThread, 5000);
                CloseHandle(hThread);
                ok = true;
            }
        }
    }
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    return ok;
}

// =============================================================================
//  模式 1：直接启动（向后兼容的经典 Launcher）
// =============================================================================
inline int DoNormalLaunch(const std::string &consoleTitle, const std::string &regSubKey,
                          const std::string &exeName, const std::string &errRegMsg)
{
    SetConsoleTitleA(consoleTitle.c_str());

    std::wstring dllPath = GetInjectDllPath();
    if (!FileExistsW(dllPath))
    {
        MessageBoxA(NULL, "错误：在当前目录下未找到 msimg32.dll 文件！你需要从 DLL 作者 ChsBuffer 处获取最新的 msimg32.dll 并放置于当前目录！", "注入失败", MB_ICONERROR);
        return 1;
    }

    std::string installPath = GetExecutablePathFromRegistry(regSubKey, "Path");
    if (installPath.empty())
    {
        MessageBoxA(NULL, errRegMsg.c_str(), "注入失败", MB_ICONERROR);
        return 1;
    }
    std::string exePath = installPath + "\\" + exeName;

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(exePath.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        MessageBoxA(NULL, "错误：无法启动目标进程。", "注入失败", MB_ICONERROR);
        return 1;
    }

    // 注入失败也不能让用户打不开程序 —— 无论如何都恢复运行。
    InjectDllIntoProcess(pi.hProcess, dllPath);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

// =============================================================================
//  模式 2：IFEO 调试器模式
// =============================================================================

// 由 argv[1..] 重建目标命令行（对含空格的参数补引号）。
inline std::wstring RebuildTargetCmdLine(int argc, wchar_t **argv)
{
    std::wstring cmd;
    for (int i = 1; i < argc; ++i)
    {
        if (i > 1)
            cmd += L" ";
        std::wstring a = argv[i];
        bool needQuote = a.empty() || a.find(L' ') != std::wstring::npos;
        bool already = a.size() >= 2 && a.front() == L'"' && a.back() == L'"';
        if (needQuote && !already)
            cmd += L"\"" + a + L"\"";
        else
            cmd += a;
    }
    return cmd;
}

// 判断目标是否为 Chromium/Electron 子进程（渲染器/GPU/工具进程等，命令行带 --type=）。
// 这类进程依赖父进程传入的句柄/沙箱令牌，不应注入，且应尽量原样转发启动。
inline bool IsChromiumChild(const std::wstring &cmdLine)
{
    return cmdLine.find(L"--type=") != std::wstring::npos;
}

inline int DoDebuggerMode(int argc, wchar_t **argv)
{
    std::wstring appName = argv[1]; // IFEO 传入的目标 EXE 全路径
    std::wstring cmdLine = RebuildTargetCmdLine(argc, argv);
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    bool isChild = IsChromiumChild(cmdLine);
    std::wstring dllPath = GetInjectDllPath();
    bool haveDll = FileExistsW(dllPath) && !isChild; // 子进程一律不注入

    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // DEBUG_ONLY_THIS_PROCESS 绕过 IFEO Debugger 重定向（否则无限递归），且免管理员。
    // 仅对需要注入的主进程加 CREATE_SUSPENDED，以便抢在目标加载 System32 msimg32 前挂上代理 DLL。
    // 子进程用 bInheritHandles=TRUE 尽量原样转发父进程传入的句柄。
    DWORD flags = DEBUG_ONLY_THIS_PROCESS | (isChild ? 0 : CREATE_SUSPENDED);
    BOOL inherit = isChild ? TRUE : FALSE;
    if (!CreateProcessW(appName.c_str(), cmdBuf.data(), NULL, NULL, inherit,
                        flags, NULL, NULL, &si, &pi))
    {
        // 兜底：连调试方式都失败时，直接普通启动，至少不让用户打不开程序。
        STARTUPINFOW si2 = {sizeof(si2)};
        PROCESS_INFORMATION pi2;
        ZeroMemory(&pi2, sizeof(pi2));
        std::vector<wchar_t> cb2(cmdLine.begin(), cmdLine.end());
        cb2.push_back(L'\0');
        if (CreateProcessW(appName.c_str(), cb2.data(), NULL, NULL, inherit, 0, NULL, NULL, &si2, &pi2))
        {
            CloseHandle(pi2.hProcess);
            CloseHandle(pi2.hThread);
            return 0;
        }
        return 1;
    }

    // 精确递归检测：若被创建的进程映像实为注入器自身，说明 DEBUG 未能绕过 IFEO，
    // 才是真正的递归风暴（正常的多层进程嵌套不会命中此判断）。
    {
        wchar_t imgPath[MAX_PATH];
        DWORD imgSz = MAX_PATH;
        if (QueryFullProcessImageNameW(pi.hProcess, 0, imgPath, &imgSz) &&
            _wcsicmp(imgPath, GetSelfPathW().c_str()) == 0)
        {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            MessageBoxA(NULL, "检测到真实 IFEO 递归（DEBUG 绕过失效），已中止该链以避免进程风暴。", "注入器", MB_ICONERROR);
            return 1;
        }
    }

    // 分离后目标必须继续存活。
    DebugSetProcessKillOnExit(FALSE);

    // 消费初始的 CREATE_PROCESS_DEBUG_EVENT，以便干净地脱离调试关系。
    DEBUG_EVENT de;
    if (WaitForDebugEvent(&de, 3000))
    {
        if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT &&
            de.u.CreateProcessInfo.hFile)
            CloseHandle(de.u.CreateProcessInfo.hFile);
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }

    // 彻底脱离调试关系。此后目标不再被调试冻结。
    // 必须先分离，否则注入触发的 LOAD_DLL 调试事件无人处理会把目标卡死。
    DebugActiveProcessStop(pi.dwProcessId);

    // 主进程：经典远程线程注入（进程未冻结、主线程仍挂起），随后恢复运行。
    // 子进程：不注入，分离后即自由运行，无需 ResumeThread（未挂起）。
    if (haveDll)
        InjectDllIntoProcess(pi.hProcess, dllPath);
    if (!isChild)
        ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

// =============================================================================
//  模式 3/4：IFEO 登记的安装 / 卸载
// =============================================================================

inline bool IsRunningAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

// 以管理员身份重新启动自身，携带同样的参数；成功发起提权返回 true。
inline bool RelaunchAsAdmin(const std::wstring &args)
{
    std::wstring self = GetSelfPathW();
    SHELLEXECUTEINFOW sei = {sizeof(sei)};
    sei.lpVerb = L"runas";
    sei.lpFile = self.c_str();
    sei.lpParameters = args.c_str();
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&sei) == TRUE;
}

inline std::wstring IfeoKeyPath(const std::string &exeName)
{
    std::wstring w(exeName.begin(), exeName.end());
    return L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + w;
}

// ---------- 目录 EXE 枚举 + FilterFullPath 精确匹配 IFEO 的辅助函数 ----------

// 宽字符版 IFEO 键路径。
inline std::wstring IfeoKeyPathW(const std::wstring &base)
{
    return L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + base;
}

// 取路径最后一段（文件名）。
inline std::wstring BaseNameW(const std::wstring &full)
{
    std::wstring::size_type pos = full.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? full : full.substr(pos + 1);
}

// 由完整路径生成稳定唯一的 filter 子键名（FNV-1a），用于区分同名 EXE 的不同路径。
inline std::wstring FilterSubkeyName(const std::wstring &fullPath)
{
    unsigned int h = 2166136261u;
    const unsigned char *p = reinterpret_cast<const unsigned char *>(fullPath.data());
    size_t n = fullPath.size() * sizeof(wchar_t);
    for (size_t i = 0; i < n; ++i)
    {
        h ^= p[i];
        h *= 16777619u;
    }
    wchar_t buf[16];
    wsprintfW(buf, L"Flt%08X", h);
    return buf;
}

// 宽字符版注册表读取（避免 ANSI→宽转换在中文路径上出错）。
inline std::wstring GetRegStringW(const std::wstring &subKey, const std::wstring &valueName)
{
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return L"";
    wchar_t buffer[MAX_PATH];
    DWORD sz = sizeof(buffer);
    DWORD type = 0;
    LONG r = RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, reinterpret_cast<LPBYTE>(buffer), &sz);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || sz == 0)
        return L"";
    size_t len = sz / sizeof(wchar_t);
    if (len > 0 && buffer[len - 1] == L'\0')
        --len;
    if (len >= MAX_PATH)
        len = MAX_PATH - 1;
    return std::wstring(buffer, len);
}

// 递归枚举目录下所有 .exe（完整路径）。
inline void EnumerateExesRecursive(const std::wstring &dir, std::vector<std::wstring> &out)
{
    std::wstring search = dir + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do
    {
        std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..")
            continue;
        std::wstring full = dir + L"\\" + name;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            EnumerateExesRecursive(full, out);
        }
        else if (name.size() >= 4 && _wcsicmp(name.substr(name.size() - 4).c_str(), L".exe") == 0)
        {
            out.push_back(full);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// 跟踪键：记录本注入器为某应用登记了哪些完整路径，供 uninstall 精确回滚。
inline std::wstring TrackingKeyPath(const std::string &mainExe)
{
    std::wstring w(mainExe.begin(), mainExe.end());
    return L"SOFTWARE\\XiaomiInjector\\" + w;
}

inline void SaveTrackedPaths(const std::string &mainExe, const std::vector<std::wstring> &paths)
{
    HKEY h;
    DWORD disp;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, TrackingKeyPath(mainExe).c_str(), 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &h, &disp) != ERROR_SUCCESS)
        return;
    std::vector<wchar_t> buf;
    for (const auto &s : paths)
    {
        buf.insert(buf.end(), s.begin(), s.end());
        buf.push_back(L'\0');
    }
    buf.push_back(L'\0'); // 结尾双空
    if (buf.size() < 2)
        buf.push_back(L'\0');
    RegSetValueExW(h, L"Paths", 0, REG_MULTI_SZ,
                   reinterpret_cast<const BYTE *>(buf.data()), (DWORD)(buf.size() * sizeof(wchar_t)));
    RegCloseKey(h);
}

inline std::vector<std::wstring> LoadTrackedPaths(const std::string &mainExe)
{
    std::vector<std::wstring> out;
    HKEY h;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TrackingKeyPath(mainExe).c_str(), 0,
                      KEY_QUERY_VALUE | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return out;
    DWORD type = 0, sz = 0;
    if (RegQueryValueExW(h, L"Paths", NULL, &type, NULL, &sz) == ERROR_SUCCESS && type == REG_MULTI_SZ && sz > 0)
    {
        std::vector<wchar_t> buf(sz / sizeof(wchar_t) + 1, 0);
        if (RegQueryValueExW(h, L"Paths", NULL, NULL, reinterpret_cast<LPBYTE>(buf.data()), &sz) == ERROR_SUCCESS)
        {
            const wchar_t *p = buf.data();
            while (*p)
            {
                std::wstring s(p);
                out.push_back(s);
                p += s.size() + 1;
            }
        }
    }
    RegCloseKey(h);
    return out;
}

inline void DeleteTracking(const std::string &mainExe)
{
    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, TrackingKeyPath(mainExe).c_str(), KEY_WOW64_64KEY, 0);
}

// 为单个完整路径登记 FilterFullPath 精确匹配的 IFEO Debugger。
inline bool InstallIfeoFiltered(const std::wstring &fullPath, const std::wstring &debuggerVal)
{
    std::wstring keyPath = IfeoKeyPathW(BaseNameW(fullPath));
    HKEY hKey;
    DWORD disp;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &hKey, &disp) != ERROR_SUCCESS)
        return false;
    DWORD one = 1;
    RegSetValueExW(hKey, L"UseFilter", 0, REG_DWORD, reinterpret_cast<const BYTE *>(&one), sizeof(one));
    RegCloseKey(hKey);

    std::wstring subPath = keyPath + L"\\" + FilterSubkeyName(fullPath);
    HKEY hSub;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, subPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &hSub, &disp) != ERROR_SUCCESS)
        return false;
    RegSetValueExW(hSub, L"FilterFullPath", 0, REG_SZ,
                   reinterpret_cast<const BYTE *>(fullPath.c_str()), (DWORD)((fullPath.size() + 1) * sizeof(wchar_t)));
    RegSetValueExW(hSub, L"Debugger", 0, REG_SZ,
                   reinterpret_cast<const BYTE *>(debuggerVal.c_str()), (DWORD)((debuggerVal.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hSub);
    return true;
}

// 移除某完整路径的 filter 子键；若该 IFEO 项随之变空则一并清理。
inline void UninstallIfeoFiltered(const std::wstring &fullPath, const std::wstring &selfQuoted)
{
    std::wstring keyPath = IfeoKeyPathW(BaseNameW(fullPath));
    std::wstring subPath = keyPath + L"\\" + FilterSubkeyName(fullPath);
    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, subPath.c_str(), KEY_WOW64_64KEY, 0);

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0,
                      KEY_READ | KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return;
    DWORD subkeys = 0, values = 0;
    RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &subkeys, NULL, NULL, &values, NULL, NULL, NULL, NULL);
    if (subkeys == 0)
    {
        RegDeleteValueW(hKey, L"UseFilter");
        // 顺带清理老版单键 --install 遗留的、且确属本注入器的基级 Debugger。
        wchar_t buf[1024];
        DWORD sz = sizeof(buf), type = 0;
        if (RegQueryValueExW(hKey, L"Debugger", NULL, &type, reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS && type == REG_SZ)
        {
            buf[(sz / sizeof(wchar_t)) < 1024 ? (sz / sizeof(wchar_t)) : 1023] = L'\0';
            if (_wcsicmp(buf, selfQuoted.c_str()) == 0)
                RegDeleteValueW(hKey, L"Debugger");
        }
    }
    RegCloseKey(hKey);

    // 重新查询，若整项已空则删除。
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
    {
        DWORD sk = 0, vv = 0;
        RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &sk, NULL, NULL, &vv, NULL, NULL, NULL, NULL);
        RegCloseKey(hKey);
        if (sk == 0 && vv == 0)
            RegDeleteKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), KEY_WOW64_64KEY, 0);
    }
}

inline int DoInstall(const std::string &exeName, const std::string &regSubKey)
{
    if (!IsRunningAsAdmin())
    {
        if (RelaunchAsAdmin(L"--install"))
            return 0;
        MessageBoxA(NULL, "安装 IFEO 需要管理员权限，提权被拒绝。", "注入器", MB_ICONERROR);
        return 1;
    }

    std::wstring dllPath = GetInjectDllPath();
    if (!FileExistsW(dllPath))
    {
        MessageBoxA(NULL, "错误：注入器同级目录下未找到 msimg32.dll，请先放置该 DLL 再安装。", "注入器", MB_ICONERROR);
        return 1;
    }

    // 从 App Paths 读取安装目录（宽字符，兼容中文路径），递归枚举其下所有 EXE。
    std::wstring installDir = GetRegStringW(std::wstring(regSubKey.begin(), regSubKey.end()), L"Path");
    if (installDir.empty())
    {
        MessageBoxA(NULL, "错误：未能从注册表获取安装目录，无法枚举 EXE。", "注入器", MB_ICONERROR);
        return 1;
    }

    std::vector<std::wstring> exes;
    EnumerateExesRecursive(installDir, exes);
    if (exes.empty())
    {
        MessageBoxA(NULL, "错误：安装目录下未找到任何 EXE。", "注入器", MB_ICONERROR);
        return 1;
    }

    std::wstring debuggerVal = L"\"" + GetSelfPathW() + L"\"";
    std::vector<std::wstring> done;
    for (const auto &e : exes)
        if (InstallIfeoFiltered(e, debuggerVal))
            done.push_back(e);

    SaveTrackedPaths(exeName, done);

    std::wstring msg = L"已安装 IFEO 全局注入（精确路径匹配）。\n\n";
    msg += L"安装目录: " + installDir + L"\n";
    msg += L"已登记 EXE: " + std::to_wstring(done.size()) + L" / " + std::to_wstring(exes.size()) + L" 个\n\n";
    msg += L"此后从该目录启动的这些程序都会自动注入 DLL。\n如需撤销请运行 --uninstall（会精确回滚全部登记）。";
    MessageBoxW(NULL, msg.c_str(), L"注入器 · 安装成功", MB_ICONINFORMATION);
    return 0;
}

inline int DoUninstall(const std::string &exeName)
{
    if (!IsRunningAsAdmin())
    {
        if (RelaunchAsAdmin(L"--uninstall"))
            return 0;
        MessageBoxA(NULL, "卸载 IFEO 需要管理员权限，提权被拒绝。", "注入器", MB_ICONERROR);
        return 1;
    }

    std::wstring selfQuoted = L"\"" + GetSelfPathW() + L"\"";
    std::vector<std::wstring> paths = LoadTrackedPaths(exeName);

    // 无批量跟踪记录时，退回清理老版单键 --install 写下的基级 Debugger。
    if (paths.empty())
    {
        std::wstring keyPath = IfeoKeyPath(exeName);
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0,
                          KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
        {
            RegDeleteValueW(hKey, L"Debugger");
            RegCloseKey(hKey);
        }
        RegDeleteKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), KEY_WOW64_64KEY, 0);
        MessageBoxA(NULL, "未发现批量登记记录，已尝试移除单键登记。", "注入器 · 卸载完成", MB_ICONINFORMATION);
        return 0;
    }

    for (const auto &p : paths)
        UninstallIfeoFiltered(p, selfQuoted);
    DeleteTracking(exeName);

    std::wstring msg = L"已移除 IFEO 全局注入登记。\n\n共清理 EXE 规则: " + std::to_wstring(paths.size()) + L" 条。";
    MessageBoxW(NULL, msg.c_str(), L"注入器 · 卸载完成", MB_ICONINFORMATION);
    return 0;
}

// =============================================================================
//  模式 5：状态查询（报告 IFEO 登记与 DLL 就位情况）
// =============================================================================
inline int DoStatus(const std::string &exeName)
{
    std::wstring dllPath = GetInjectDllPath();
    bool dllOk = FileExistsW(dllPath);

    std::wstring msg = L"目标应用: " + std::wstring(exeName.begin(), exeName.end()) + L"\n\n";

    std::vector<std::wstring> paths = LoadTrackedPaths(exeName);
    if (paths.empty())
    {
        // 兼容老版单键 --install。
        std::wstring dbg = GetRegStringW(IfeoKeyPath(exeName), L"Debugger");
        if (dbg.empty())
            msg += L"IFEO 全局注入: 未安装\n";
        else
            msg += L"IFEO 全局注入: 已安装（旧版单键）\nDebugger = " + dbg + L"\n";
    }
    else
    {
        // 统计跟踪清单里仍然有效的规则数。
        int okCount = 0;
        for (const auto &p : paths)
        {
            std::wstring subPath = IfeoKeyPathW(BaseNameW(p)) + L"\\" + FilterSubkeyName(p);
            HKEY h;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath.c_str(), 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &h) == ERROR_SUCCESS)
            {
                ++okCount;
                RegCloseKey(h);
            }
        }
        msg += L"IFEO 全局注入: 已安装（批量 · 精确路径匹配）\n";
        msg += L"有效登记: " + std::to_wstring(okCount) + L" / " + std::to_wstring(paths.size()) + L" 条\n\n";
        int shown = 0;
        for (const auto &p : paths)
        {
            if (shown >= 12)
            {
                msg += L"  … 其余省略\n";
                break;
            }
            msg += L"  • " + BaseNameW(p) + L"\n";
            ++shown;
        }
    }

    msg += L"\n注入 DLL: " + dllPath + L"\n";
    msg += dllOk ? L"DLL 状态: 已就位" : L"DLL 状态: 缺失（需放置 msimg32.dll）";

    MessageBoxW(NULL, msg.c_str(), L"注入器 · 状态", MB_ICONINFORMATION);
    return 0;
}

// =============================================================================
//  入口分发
// =============================================================================
inline int RunInjector(const std::string &consoleTitle, const std::string &regSubKey,
                       const std::string &exeName, const std::string &errRegMsg)
{
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    int rc;
    if (argc >= 2 && argv)
    {
        std::wstring a1 = argv[1];
        if (a1 == L"--install" || a1 == L"/install")
            rc = DoInstall(exeName, regSubKey);
        else if (a1 == L"--uninstall" || a1 == L"/uninstall")
            rc = DoUninstall(exeName);
        else if (a1 == L"--status" || a1 == L"/status")
            rc = DoStatus(exeName);
        else if (a1 == L"--launch" || a1 == L"/launch")
            rc = DoNormalLaunch(consoleTitle, regSubKey, exeName, errRegMsg);
        else
            // 其余情况：argv[1] 是 IFEO 传入的目标路径 → 调试器模式。
            rc = DoDebuggerMode(argc, argv);
    }
    else
    {
        // 无参数（双击）→ 经典直接启动，保持向后兼容。
        rc = DoNormalLaunch(consoleTitle, regSubKey, exeName, errRegMsg);
    }

    if (argv)
        LocalFree(argv);
    return rc;
}
