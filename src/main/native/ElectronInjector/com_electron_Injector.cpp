#include "pch.h"

#include "com_electron_Injector.h"

#include <codecvt>
#include <jni.h>
#include <locale>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include "v8Tools.h"

#pragma data_seg(".shared")
DWORD_PTR g_remoteDllBase = 0;
#pragma data_seg()
#pragma comment(linker, "/section:.shared,RWS")

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = hModule;
        if (g_remoteDllBase == 0) { // 第一个加载的进程设置基地址
            g_remoteDllBase = (DWORD_PTR)hModule;
        }
    }
    return TRUE;
}

// Helper functions
static void CleanupProcess(PROCESS_INFORMATION& pi) {
    if (pi.hProcess) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
    }
    if (pi.hThread) CloseHandle(pi.hThread);
}

const char* GetLastErrorString(DWORD err) {
    static char msg[256];
    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        msg,
        sizeof(msg),
        NULL
    );
    return msg;
}

static void ThrowFormattedException(JNIEnv* env, const char* className,
    const char* format, ...)
{
    char buffer[256];
    va_list args;
    va_start(args, format);
    vsprintf_s(buffer, format, args);
    va_end(args);

    jclass exClass = env->FindClass(className);
    if (exClass) {
        env->ThrowNew(exClass, buffer);
    }
}

/* 目标进程Dll基址 */
DWORD_PTR dllBaseAddr;
/* 目标进程句柄 */
HANDLE g_hTargetProcess;
/*
     * Class:     com_electron_Injector
     * Method:    additionalProgram
     * Signature: (Ljava/lang/String;Ljava/lang/String;)V
     */
JNIEXPORT void JNICALL Java_com_electron_Injector_additionalProgram(
    JNIEnv* env, jclass clazz, jstring programPath)
{
    const wchar_t* exePath = (const wchar_t*)env->GetStringChars(programPath, nullptr);

    // Initialize process startup parameters
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    std::wstring fullCmdLine = (wchar_t*)exePath;

    // Create suspended process
    if (!CreateProcessW(
        nullptr,               // lpApplicationName 设为 nullptr，从命令行解析
        const_cast<LPWSTR>(fullCmdLine.c_str()),  // 完整命令行（路径+参数）
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        nullptr,
        &si,
        &pi))
    {
        env->ReleaseStringChars(programPath, (const jchar*)exePath);
        ThrowFormattedException(env, "java/lang/IllegalStateException",
            "Process creation failed (Error: 0x%08X)", GetLastError());
        return;
    }
    env->ReleaseStringChars(programPath, (const jchar*)exePath);

    // Store main process handle
    g_hTargetProcess = pi.hProcess;

    // Get DLL path
    wchar_t dllPath[MAX_PATH];
    if (!GetModuleFileNameW((HMODULE)g_hModule, dllPath, MAX_PATH)) {
        CleanupProcess(pi);
        ThrowFormattedException(env, "java/io/IOException",
            "Failed to get module path (Error: 0x%08X)", GetLastError());
        return;
    }

    // Allocate remote memory
    size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteDllPath = VirtualAllocEx(pi.hProcess, nullptr, pathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteDllPath) {
        CleanupProcess(pi);
        ThrowFormattedException(env, "java/lang/OutOfMemoryError",
            "Remote memory allocation failed (Error: 0x%08X)", GetLastError());
        return;
    }

    // Write DLL path to target
    if (!WriteProcessMemory(pi.hProcess, remoteDllPath, dllPath, pathSize, nullptr)) {
        VirtualFreeEx(pi.hProcess, remoteDllPath, 0, MEM_RELEASE);
        CleanupProcess(pi);
        ThrowFormattedException(env, "java/io/IOException",
            "Memory write failed (Error: 0x%08X)", GetLastError());
        return;
    }

    // Execute LoadLibrary in target
    LPTHREAD_START_ROUTINE loadLibrary = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(
        pi.hProcess, nullptr, 0, loadLibrary, remoteDllPath, 0, nullptr);

    if (!hThread) {
        VirtualFreeEx(pi.hProcess, remoteDllPath, 0, MEM_RELEASE);
        CleanupProcess(pi);
        ThrowFormattedException(env, "java/lang/IllegalStateException",
            "Thread creation failed (Error: 0x%08X)", GetLastError());
        return;
    }

    // Wait for DLL load
    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, (LPDWORD)&dllBaseAddr);
    CloseHandle(hThread);
    VirtualFreeEx(pi.hProcess, remoteDllPath, 0, MEM_RELEASE);

    if (dllBaseAddr == 0) {
        CleanupProcess(pi);
        ThrowFormattedException(env, "java/lang/IllegalStateException",
            "DLL injection failed (Base address: 0)");
        return;
    }

    // Get hook initialization function
    FARPROC initHooks = GetProcAddress((HMODULE)g_hModule, "InitializeHooks");
    if (!initHooks) {
        CleanupProcess(pi);
        ThrowFormattedException(env, "java/lang/NoSuchMethodError",
            "InitializeHooks export not found");
        return;
    }

    // Execute hooks initialization
    HANDLE hInitThread = CreateRemoteThread(
        pi.hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)initHooks, nullptr, 0, nullptr);

    if (hInitThread) {
        WaitForSingleObject(hInitThread, INFINITE);
        CloseHandle(hInitThread);
    }
    else {
        CleanupProcess(pi);
        ThrowFormattedException(env, "java/lang/ThreadException",
            "Hook initialization failed (Error: 0x%08X)", GetLastError());
        return;
    }

    // Resume main thread
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        CleanupProcess(pi);
        ThrowFormattedException(env, "java/lang/IllegalStateException",
            "Thread resume failed (Error: 0x%08X)", GetLastError());
        return;
    }

    // Cleanup handles
    //CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

     /*
      * Class:     com_electron_Injector
      * Method:    executeJavascript
      * Signature: (Ljava/lang/String;)V
      */
JNIEXPORT void JNICALL Java_com_electron_Injector_executeJavascript(
    JNIEnv* env, jclass clazz, jstring jsCode)
{
    if (!g_hTargetProcess || g_hTargetProcess == INVALID_HANDLE_VALUE) {
        jclass exCls = env->FindClass("java/lang/IllegalStateException");
        env->ThrowNew(exCls, "Unable to open the target process");
        return;
    }

    HANDLE hProcess = g_hTargetProcess;

    // 转换JS代码为UTF-8
    const char* codeStr = env->GetStringUTFChars(jsCode, nullptr);
    size_t codeSize = strlen(codeStr) + 1;

    // 在目标进程分配内存并写入JS代码
    LPVOID remoteCode = VirtualAllocEx(hProcess,
        NULL,
        codeSize,
        MEM_COMMIT | MEM_RESERVE,  // 明确保留并提交
        PAGE_READWRITE
    );
    if (!remoteCode) {
        DWORD err = GetLastError();
        char errorMsg[256];
        sprintf_s(errorMsg,
            "VirtualAllocEx failed (Error 0x%08X: %s)",
            err,
            GetLastErrorString(err));  // 需要实现错误码转文字
        env->ThrowNew(env->FindClass("java/lang/OutOfMemoryError"), errorMsg);
        return;
    }

    if (!WriteProcessMemory(hProcess, remoteCode, codeStr, codeSize, NULL)) {
        VirtualFreeEx(hProcess, remoteCode, 0, MEM_RELEASE);
        env->ReleaseStringUTFChars(jsCode, codeStr);
        //CloseHandle(hProcess);
        jclass exCls = env->FindClass("java/io/IOException");
        env->ThrowNew(exCls, "Remote memory write failed");
        return;
    }
    env->ReleaseStringUTFChars(jsCode, codeStr);

    // 获取ListExecution函数地址
    FARPROC localListExec = GetProcAddress(g_hModule, "ListExecution");
    if (!localListExec) {
        VirtualFreeEx(hProcess, remoteCode, 0, MEM_RELEASE);
       // CloseHandle(hProcess);
        jclass exCls = env->FindClass("java/lang/NoSuchMethodError");
        env->ThrowNew(exCls, "ListExecution function not found");
        return;
    }

    // 创建远程线程执行ListExecution
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(localListExec),
        remoteCode,
        0,
        NULL
    );

    if (!hThread) {
        VirtualFreeEx(hProcess, remoteCode, 0, MEM_RELEASE);
        //CloseHandle(hProcess);
        jclass exCls = env->FindClass("java/lang/ThreadException");
        env->ThrowNew(exCls, "Remote thread creation failed");
        return;
    }

    // 等待执行完成（最多5秒）
    WaitForSingleObject(hThread, INFINITE);
    /*if (waitResult == WAIT_TIMEOUT) {
        MessageBoxW(NULL,
            L"JavaScript execution timeout, recommend checking script logic",
            L"Execute Warnings",
            MB_ICONWARNING);
    }*/

    // 获取执行结果
    DWORD exitCode = 0;
    if (!GetExitCodeThread(hThread, &exitCode)) {
        exitCode = GetLastError();
    }

    // 清理资源
    VirtualFreeEx(hProcess, remoteCode, 0, MEM_RELEASE);
    CloseHandle(hThread);
    //CloseHandle(hProcess);

    // 处理错误代码
    if (exitCode != ERROR_SUCCESS) {
        char errorMsg[256];
        sprintf_s(errorMsg,
            "远程执行失败 (错误码: 0x%08X)",
            exitCode);
        jclass exCls = env->FindClass("java/lang/RuntimeException");
        env->ThrowNew(exCls, errorMsg);
    }
}

JNIEXPORT void JNICALL Java_com_electron_Injector_inject
(JNIEnv* env, jclass, jstring processName, jstring jsCode)
{
    // 获取目标进程ID
    const wchar_t* targetProcess = (const wchar_t*)env->GetStringChars(processName, nullptr);
    DWORD pid = FindProcessId(targetProcess);
    env->ReleaseStringChars(processName, (const jchar*)targetProcess);

    if (pid == 0) {
        return; // 进程未找到
    }

    // 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        return;
    }

    // 获取当前DLL路径
    wchar_t dllPath[MAX_PATH];
    if (!GetModuleFileNameW(g_hModule, dllPath, MAX_PATH)) {
        CloseHandle(hProcess);
        return;
    }

    // 在目标进程分配内存并写入DLL路径
    size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteDllPath = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteDllPath) {
        CloseHandle(hProcess);
        return;
    }

    if (!WriteProcessMemory(hProcess, remoteDllPath, dllPath, pathSize, NULL)) {
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // 加载DLL到目标进程
    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, remoteDllPath, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // 获取DLL基地址
    WaitForSingleObject(hThread, INFINITE);
    DWORD_PTR dllBaseAddr = 0;
    GetExitCodeThread(hThread, (LPDWORD)&dllBaseAddr);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);

    if (dllBaseAddr == 0) {
        CloseHandle(hProcess);
        return;
    }

    // 计算导出函数偏移量
    FARPROC localFunc = GetProcAddress(g_hModule, "ExportFunction");
    if (!localFunc) {
        CloseHandle(hProcess);
        return;
    }

    //DWORD_PTR offset = (DWORD_PTR)localFunc - (DWORD_PTR)g_hModule;
    LPVOID remoteFuncAddr = localFunc;

    // 写入JavaScript代码到目标进程
    const char* codeStr = env->GetStringUTFChars(jsCode, nullptr);
    size_t codeSize = strlen(codeStr) + 1;

    LPVOID remoteCode = VirtualAllocEx(hProcess, NULL, codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteCode) {
        env->ReleaseStringUTFChars(jsCode, codeStr);
        CloseHandle(hProcess);
        return;
    }

    if (!WriteProcessMemory(hProcess, remoteCode, codeStr, codeSize, NULL)) {
        VirtualFreeEx(hProcess, remoteCode, 0, MEM_RELEASE);
        env->ReleaseStringUTFChars(jsCode, codeStr);
        CloseHandle(hProcess);
        return;
    }

    env->ReleaseStringUTFChars(jsCode, codeStr);

    // 创建远程线程执行导出函数
    HANDLE hFuncThread = CreateRemoteThread(hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteFuncAddr),
        remoteCode, 0, nullptr);

    if (hFuncThread) {
        WaitForSingleObject(hFuncThread, INFINITE);
        CloseHandle(hFuncThread);

        LPTHREAD_START_ROUTINE freeLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary"));

        if (freeLibrary && dllBaseAddr != 0) {
            // 创建卸载线程（等待执行完成）
            HANDLE hUnloadThread = CreateRemoteThread(
                hProcess,
                nullptr,
                0,
                freeLibrary,
                reinterpret_cast<LPVOID>(dllBaseAddr),
                0,
                nullptr
            );

            if (hUnloadThread) {
                WaitForSingleObject(hUnloadThread, 2000);  // 最多等待2秒
                CloseHandle(hUnloadThread);
            }
        }
    }

    VirtualFreeEx(hProcess, remoteCode, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}

struct ThreadInfo {
    DWORD thread_id;
    wchar_t* thread_name = nullptr;
    char* js_code = nullptr;
    bool has_isolate = false;
    HANDLE completion_event;

    ~ThreadInfo() {
        if (thread_name) delete[] thread_name;
        if (js_code) delete[] js_code;
    }
};

/*
 * Javascript执行异常处理
 */
void ReportException(v8::Isolate* isolate, void* try_catch_ptr) {
    v8::Local<v8::Value> exception;
    V8TryCatchException(
        try_catch_ptr,  // this指针
        &exception      // 输出参数
    );

    v8::Local<v8::Message> message;
    V8TryCatchMessage(try_catch_ptr, &message);
    std::string error = "JS执行错误: ";
    if (message.IsEmpty() == false) {
        v8::ScriptOrigin origin;
        V8MessageGetScriptOrigin(*message, &origin);
        v8::Local<v8::Value> resource_name;
        V8ScriptOriginResourceName(&origin, &resource_name);
        std::string filename = "[unnamed]";
        if (resource_name.IsEmpty() == false) {
            filename = V8ValueToStdString(isolate, resource_name);
        }
        int linenum = -1;
        error += filename + ":" + std::to_string(linenum) + "\n";
    }
    std::string exception_str = V8ValueToStdString(isolate, exception);
    error += exception_str;
    MessageBoxA(NULL, error.c_str(), "JS错误", MB_ICONWARNING);
}

wchar_t* GetThreadName(DWORD thread_id) {
    HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, thread_id);
    if (!hThread) return nullptr;

    PWSTR desc = nullptr;
    HRESULT hr = GetThreadDescription(hThread, &desc);
    CloseHandle(hThread);

    if (SUCCEEDED(hr) && desc) {
        size_t len = wcslen(desc) + 1;
        wchar_t* buffer = new wchar_t[len];
        wcscpy_s(buffer, len, desc);
        LocalFree(desc);
        return buffer;
    }
    return nullptr;
}

void ExecuteJsCode(ThreadInfo* info, v8::Isolate* isolate)
{
    if (info->js_code) {
        {
            //alignas(16) Locker_ locker_mem;
            //alignas(16) Scope_ scope_mem;

            /*pV8LockerCtor(&locker_mem, isolate);
            pV8IsolateScopeCtor(&scope_mem, isolate);

            v8::HandleScope handle_scope;
            pHandleScopeCtor(&handle_scope, isolate);
            */
            v8::Local<v8::Context> context;
            v8_get_current_context_prt(isolate, &context);

            //v8::TryCatch try_catch;
            //pTryCatchCtor(&try_catch, isolate);

            v8::Local<v8::String> source = local_string_from_string(isolate, info->js_code);
            v8::Local<v8::Script> script;

            if (!v8_compile(context, source).ToLocal(&script)) {
                //ReportException(isolate, &try_catch);
                return;
            }

            v8::MaybeLocal<v8::Value> result;
            v8::Local<v8::Data> empty_options = v8::Local<v8::Data>::Cast(v8::Undefined(isolate));

            v8_script_run_ex(
                *script,       // 正确传递this指针（需验证script对象的内存布局）
                &result,       // 返回值存储地址
                context,       // Context参数
                empty_options  // 空Data参数
            );

            if (!result.IsEmpty()) {
                v8::Local<v8::Value> value = result.ToLocalChecked();
                //MessageBoxA(NULL, "Operation completed !", "1", MB_ICONINFORMATION);
                return;
            }
            //ReportException(isolate, &try_catch);
        }
    }
}

void ExecuteInV8Context(ThreadInfo* info) {
    // 获取线程名称
    if (!info->thread_name) {
        info->thread_name = GetThreadName(info->thread_id);
    }

    // 获取Isolate并执行JS
    if (v8::Isolate* isolate = GetSafeIsolate()) {
        info->has_isolate = true;

        // 显示线程信息
        //std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
        //std::string msg = "Thread ID: " + std::to_string(info->thread_id)
        //   + "\nName: " + converter.to_bytes(info->thread_name ? info->thread_name : L"<unknown>");

        //MessageBoxA(NULL, msg.c_str(), "V8 Context Found", MB_ICONINFORMATION);
        ExecuteJsCode(info, isolate);
        //pV8IsolateDispose(isolate);
    }
}

void NTAPI CheckIsolateAPC(ULONG_PTR param) {
    ThreadInfo* info = reinterpret_cast<ThreadInfo*>(param);
    if (!info) return;

    __try {
        InstallV8DisposeHook();
        ExecuteInV8Context(info);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exceptionCode = GetExceptionCode();
        char errorMsg[256];
        sprintf_s(errorMsg, "⚠ APC回调异常 (0x%08X)", exceptionCode);
        OutputDebugStringA(errorMsg);
        MessageBoxA(NULL, errorMsg, "运行时错误", MB_ICONERROR | MB_OK);
    }

    // 触发完成事件并清理
    SetEvent(info->completion_event);
    delete info;
}

// DLL导出函数（在目标进程执行）
extern "C" __declspec(dllexport) DWORD WINAPI ExportFunction(LPVOID lpParam) {
    const char* jsCode = static_cast<const char*>(lpParam);
    if (!jsCode || !*jsCode) {
        MessageBoxA(NULL, "无效的JS代码输入", "错误", MB_ICONERROR);
        return ERROR_INVALID_PARAMETER;
    }

    // 复制JS代码（线程安全）
    size_t jsLen = strlen(jsCode) + 1;
    char* jsCopy = new char[jsLen];
    strcpy_s(jsCopy, jsLen, jsCode);

    // 枚举线程并注入
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        delete[] jsCopy;
        return GetLastError();
    }

    THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
    std::vector<DWORD> threadIds;

    DWORD currentThreadId = GetCurrentThreadId();

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId() &&
                te32.th32ThreadID != currentThreadId) {
                threadIds.push_back(te32.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    CloseHandle(hSnapshot);

    std::vector<HANDLE> apcEvents;
    DWORD activeAPCCount = 0;

    // 提交APC请求
    for (DWORD tid : threadIds) {
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
        if (hThread) {
            // 为每个APC创建事件
            HANDLE hAPCEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
            ThreadInfo* info = new ThreadInfo();
            info->thread_id = tid;
            info->js_code = new char[jsLen];
            info->completion_event = hAPCEvent;
            strcpy_s(info->js_code, jsLen, jsCopy);
            //MessageBoxW(NULL, GetThreadName(tid), L"   ", MB_ICONERROR | MB_OK);
            if (QueueUserAPC(CheckIsolateAPC, hThread, (ULONG_PTR)info)) {
                apcEvents.push_back(hAPCEvent);
                activeAPCCount++;
            }
            else {
                CloseHandle(hAPCEvent);
                delete info;
            }
            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    }

    if (activeAPCCount > 0) {
        DWORD waitResult = WaitForMultipleObjects(
            apcEvents.size(),
            apcEvents.data(),
            TRUE,  // 等待所有信号
            8000); // 8秒超时

        if (waitResult == WAIT_TIMEOUT) {
            //MessageBoxA(NULL,
            //    "警告：部分线程未在规定时间内完成操作",
            //    "执行超时",
            //    MB_ICONWARNING | MB_OK);
        }
    }

    // 资源清理
    for (HANDLE h : apcEvents) CloseHandle(h);
    delete[] jsCopy;

    return (activeAPCCount > 0) ? ERROR_SUCCESS : ERROR_OPERATION_ABORTED;
}

using IsolateNewFunc = v8::Isolate* (__fastcall*)(const v8::Isolate::CreateParams*);
IsolateNewFunc OriginalIsolateNew = nullptr;


v8::Isolate* __fastcall HookedIsolateNew(const v8::Isolate::CreateParams* params) {
    v8::Isolate* isolate = OriginalIsolateNew(params);
    if (isolate) {
        if (std::find(g_isolateList.begin(), g_isolateList.end(), isolate) == g_isolateList.end()) {
            g_isolateList.push_back(isolate);
        }
    }
    return isolate;
}

extern "C" __declspec(dllexport) void InitializeHooks() {
    // 将耗时操作移到新线程中执行，避免阻塞主线程
    std::thread hookThread([]() {
        if (!v8_try_get_current) {
            // 初始化 v8_try_get_current（此部分可能较短，可保留在主线程）
            do {
                v8_try_get_current = reinterpret_cast<V8TryGetCurrent>(
                    GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?TryGetCurrent@Isolate@v8@@SAPEAV12@XZ")
                    );
            } while (v8_try_get_current == nullptr);
            Initialization();
        }

        OriginalIsolateNew = (IsolateNewFunc)GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME),
            "?New@Isolate@v8@@SAPEAV12@AEBUCreateParams@12@@Z");

        // 遍历所有线程并挂钩
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
        DWORD currentThreadId = GetCurrentThreadId();

        if (hSnapshot != INVALID_HANDLE_VALUE && Thread32First(hSnapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == GetCurrentProcessId() &&
                    te32.th32ThreadID != currentThreadId) {
                    // 对每个线程进行挂钩
                    DetourTransactionBegin();
                    HANDLE hThread = OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                        FALSE,
                        te32.th32ThreadID
                    );
                    if (hThread) {
                        DetourUpdateThread(hThread);
                        DetourAttach((PVOID*)&v8_try_get_current, HookedV8IsolateGetCurrent);
                        DetourAttach(&(PVOID&)OriginalIsolateNew, HookedIsolateNew);
                        DetourTransactionCommit();
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te32));
            CloseHandle(hSnapshot);
        }
    });

    // 启动线程但不等待（主线程继续执行）
    hookThread.detach();
}

static void InternalCheckIsolate(ThreadInfo* info) {
    for (auto isolate : g_isolateList) {
        if (!isolate) continue;
        ExecuteJsCode(info, isolate);
    }
}

void NTAPI ListExecution_CheckIsolateAPC(ULONG_PTR param) {
    ThreadInfo* info = reinterpret_cast<ThreadInfo*>(param);
    if (!info) return;

    __try {
        InternalCheckIsolate(info); // 调用无SEH的封装函数
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exceptionCode = GetExceptionCode();
        char errorMsg[256];
        sprintf_s(errorMsg, "⚠ APC回调异常 (0x%08X)", exceptionCode);
        OutputDebugStringA(errorMsg);
        //MessageBoxA(NULL, errorMsg, "运行时错误", MB_ICONERROR | MB_OK);
    }

    SetEvent(info->completion_event);
    delete info;
}

extern "C" __declspec(dllexport) DWORD WINAPI ListExecution(LPVOID lpParam) {
    const char* jsCode = static_cast<const char*>(lpParam);
    if (!jsCode || !*jsCode) {
        MessageBoxA(NULL, "无效的JS代码输入", "错误", MB_ICONERROR);
        return ERROR_INVALID_PARAMETER;
    }

    // 复制JS代码（线程安全）
    size_t jsLen = strlen(jsCode) + 1;
    char* jsCopy = new char[jsLen];
    strcpy_s(jsCopy, jsLen, jsCode);

    // 枚举线程并注入
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        delete[] jsCopy;
        return GetLastError();
    }

    THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
    std::vector<DWORD> threadIds;

    DWORD currentThreadId = GetCurrentThreadId();

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId() &&
                te32.th32ThreadID != currentThreadId) {
                threadIds.push_back(te32.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);

    std::vector<HANDLE> apcEvents;
    DWORD activeAPCCount = 0;

    // 提交APC请求
    for (DWORD tid : threadIds) {
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
        if (hThread) {
            // 为每个APC创建事件
            HANDLE hAPCEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
            ThreadInfo* info = new ThreadInfo();
            info->thread_id = tid;
            info->js_code = new char[jsLen];
            info->completion_event = hAPCEvent;
            strcpy_s(info->js_code, jsLen, jsCopy);

            if (QueueUserAPC(ListExecution_CheckIsolateAPC, hThread, (ULONG_PTR)info)) {
                apcEvents.push_back(hAPCEvent);
                activeAPCCount++;
            }
            else {
                CloseHandle(hAPCEvent);
                delete info;
            }
            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    }

    if (activeAPCCount > 0) {
        DWORD waitResult = WaitForMultipleObjects(
            apcEvents.size(),
            apcEvents.data(),
            TRUE,  // 等待所有信号
            8000); // 8秒超时

        if (waitResult == WAIT_TIMEOUT) {
            /*MessageBoxA(NULL,
                "警告：部分线程未在规定时间内完成操作",
                "执行超时",
                MB_ICONWARNING | MB_OK);*/
        }
    }

    // 资源清理
    for (HANDLE h : apcEvents) CloseHandle(h);
    delete[] jsCopy;

    return (activeAPCCount > 0) ? ERROR_SUCCESS : ERROR_OPERATION_ABORTED;
}