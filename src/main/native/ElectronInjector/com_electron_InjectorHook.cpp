#include "pch.h"

#include "com_electron_InjectorHook.h"

#include <TlHelp32.h>

#include "v8_printer_hook.h"
#include "v8_hook.h"

JavaVM* g_jvm = nullptr;
JNIEnv* env_global = nullptr;

DWORD_PTR g_pCallbackAddr = 0;

auto ShowError = [](const wchar_t* message) {
    MessageBoxW(
        NULL,
        message,
        L"Injection Error",
        MB_ICONERROR | MB_OK
    );
    };


JNIEXPORT jboolean JNICALL Java_com_electron_InjectorHook_initCompilationHook(
    JNIEnv* env, jclass, jstring processName)
{
    wchar_t errorMsg[512];
    DWORD lastError = 0;

    // 获取当前模块句柄（应在DLLMain中初始化）
    if (!g_hModule) {
        ShowError(L"Global module handle not initialized!");
        return false;
    }

    env->GetJavaVM(&g_jvm);

    // 打开当前进程
    HANDLE g_hCurrentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (!g_hCurrentProcess) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[1] OpenProcess failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        return false;
    }

    // 获取目标进程PID
    const wchar_t* targetProcess = (const wchar_t*)env->GetStringChars(processName, nullptr);
    DWORD pid = FindProcessId(targetProcess);
    env->ReleaseStringChars(processName, (const jchar*)targetProcess);

    if (pid == 0) {
        ShowError(L"[2] Target process not found!");
        return false;
    }

    // 打开目标进程（添加关键权限）
    HANDLE hTargetProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_DUP_HANDLE,  // 必须的复制句柄权限
        FALSE,
        pid
    );
    if (!hTargetProcess) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[3] OpenProcess failed! PID: %ld, Error: 0x%08lX", pid, lastError);
        ShowError(errorMsg);
        return false;
    }

    // 获取当前DLL路径
    wchar_t dllPath[MAX_PATH];
    if (!GetModuleFileNameW(g_hModule, dllPath, MAX_PATH)) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[4] GetModuleFileName failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 分配远程内存
    SIZE_T dllPathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hTargetProcess, NULL, dllPathSize, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[5] VirtualAllocEx failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 写入DLL路径
    if (!WriteProcessMemory(hTargetProcess, remoteMem, dllPath, dllPathSize, NULL)) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[6] WriteProcessMemory failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 加载DLL到目标进程
    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!loadLibraryAddr) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[7] GetProcAddress failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hTargetProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hTargetProcess, NULL, 0, loadLibraryAddr, remoteMem, 0, NULL);
    if (!hThread) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[8] CreateRemoteThread failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hTargetProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    // 获取DLL基地址
    DWORD_PTR dllBase = 0;
    if (!GetExitCodeThread(hThread, (LPDWORD)&dllBase) || !dllBase) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[9] GetExitCodeThread failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 计算远程函数地址
    FARPROC localHookFunc = GetProcAddress(g_hModule, "Init_CompileFunction_Hook");
    if (!localHookFunc) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[10] GetProcAddress failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 计算RVA
    //DWORD_PTR rva = (DWORD_PTR)localHookFunc - (DWORD_PTR)g_hModule;
    //DWORD_PTR remoteHookFunc = dllBase + rva;

    // 复制进程句柄
    HANDLE hTargetCurrentProcess = NULL;
    if (!DuplicateHandle(
        GetCurrentProcess(),
        g_hCurrentProcess,
        hTargetProcess,
        &hTargetCurrentProcess,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS
    )) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[11] DuplicateHandle failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 写入句柄参数
    LPVOID remoteParam = VirtualAllocEx(hTargetProcess, NULL, sizeof(HANDLE), MEM_COMMIT, PAGE_READWRITE);
    if (!remoteParam) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[12] VirtualAllocEx failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        CloseHandle(hTargetCurrentProcess);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hTargetProcess);
        return false;
    }

    if (!WriteProcessMemory(hTargetProcess, remoteParam, &hTargetCurrentProcess, sizeof(HANDLE), NULL)) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[13] WriteProcessMemory failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        CloseHandle(hTargetCurrentProcess);
        VirtualFreeEx(hTargetProcess, remoteParam, 0, MEM_RELEASE);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 执行远程Hook
    HANDLE hHookThread = CreateRemoteThread(
        hTargetProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)localHookFunc,
        remoteParam,
        0,
        NULL
    );
    if (!hHookThread) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[14] CreateRemoteThread failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        CloseHandle(hTargetCurrentProcess);
        VirtualFreeEx(hTargetProcess, remoteParam, 0, MEM_RELEASE);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hTargetProcess);
        return false;
    }

    WaitForSingleObject(hHookThread, INFINITE);

    // 新增：卸载DLL防止崩溃
    LPTHREAD_START_ROUTINE freeLibrary = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibrary");
    if (freeLibrary && dllBase != 0) {
        HANDLE hUnloadThread = CreateRemoteThread(
            hTargetProcess,
            NULL,
            0,
            freeLibrary,
            (LPVOID)dllBase,
            0,
            NULL
        );
        if (hUnloadThread) {
            WaitForSingleObject(hUnloadThread, 2000);
            CloseHandle(hUnloadThread);
        }
    }

    // 清理资源
    VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
    VirtualFreeEx(hTargetProcess, remoteParam, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hHookThread);
    CloseHandle(hTargetCurrentProcess);
    CloseHandle(hTargetProcess);
    return true;
}

JNIEXPORT jboolean JNICALL Java_com_electron_InjectorHook_initMessageHook(
    JNIEnv* env, jclass, jstring processName)
{
    wchar_t errorMsg[512];
    DWORD lastError = 0;

    // 获取当前模块句柄（应在DLLMain中初始化）
    if (!g_hModule) {
        ShowError(L"Global module handle not initialized!");
        return false;
    }

    env->GetJavaVM(&g_jvm);

    HANDLE g_hCurrentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (!g_hCurrentProcess) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[1] OpenProcess failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        return false;
    }

    const wchar_t* targetProcess = (const wchar_t*)env->GetStringChars(processName, nullptr);
    DWORD pid = FindProcessId(targetProcess);
    env->ReleaseStringChars(processName, (const jchar*)targetProcess);

    if (pid == 0) {
        ShowError(L"[2] Target process not found!");
        return false;
    }

    // 打开目标进程（添加关键权限）
    HANDLE hTargetProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_DUP_HANDLE,  // 必须的复制句柄权限
        FALSE,
        pid
    );
    if (!hTargetProcess) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[3] OpenProcess failed! PID: %ld, Error: 0x%08lX", pid, lastError);
        ShowError(errorMsg);
        return false;
    }

    // 获取当前DLL路径
    wchar_t dllPath[MAX_PATH];
    if (!GetModuleFileNameW(g_hModule, dllPath, MAX_PATH)) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[4] GetModuleFileName failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 分配远程内存
    SIZE_T dllPathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hTargetProcess, NULL, dllPathSize, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[5] VirtualAllocEx failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 写入DLL路径
    if (!WriteProcessMemory(hTargetProcess, remoteMem, dllPath, dllPathSize, NULL)) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[6] WriteProcessMemory failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 加载DLL到目标进程
    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!loadLibraryAddr) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[7] GetProcAddress failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hTargetProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hTargetProcess, NULL, 0, loadLibraryAddr, remoteMem, 0, NULL);
    if (!hThread) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[8] CreateRemoteThread failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hTargetProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    // 获取DLL基地址
    DWORD_PTR dllBase = 0;
    if (!GetExitCodeThread(hThread, (LPDWORD)&dllBase) || !dllBase) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[9] GetExitCodeThread failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 计算远程函数地址
    FARPROC localHookFunc = GetProcAddress(g_hModule, "Init_Message_Hook");
    if (!localHookFunc) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[10] GetProcAddress failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 计算RVA
    //DWORD_PTR rva = (DWORD_PTR)localHookFunc - (DWORD_PTR)g_hModule;
    //DWORD_PTR remoteHookFunc = dllBase + rva;

    // 复制进程句柄
    HANDLE hTargetCurrentProcess = NULL;
    if (!DuplicateHandle(
        GetCurrentProcess(),
        g_hCurrentProcess,
        hTargetProcess,
        &hTargetCurrentProcess,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS
    )) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[11] DuplicateHandle failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 写入句柄参数
    LPVOID remoteParam = VirtualAllocEx(hTargetProcess, NULL, sizeof(HANDLE), MEM_COMMIT, PAGE_READWRITE);
    if (!remoteParam) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[12] VirtualAllocEx failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        CloseHandle(hTargetCurrentProcess);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hTargetProcess);
        return false;
    }

    if (!WriteProcessMemory(hTargetProcess, remoteParam, &hTargetCurrentProcess, sizeof(HANDLE), NULL)) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[13] WriteProcessMemory failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        CloseHandle(hTargetCurrentProcess);
        VirtualFreeEx(hTargetProcess, remoteParam, 0, MEM_RELEASE);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hTargetProcess);
        return false;
    }

    // 执行远程Hook
    HANDLE hHookThread = CreateRemoteThread(
        hTargetProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)localHookFunc,
        remoteParam,
        0,
        NULL
    );
    if (!hHookThread) {
        lastError = GetLastError();
        swprintf(errorMsg, 512, L"[14] CreateRemoteThread failed! Error: 0x%08lX", lastError);
        ShowError(errorMsg);
        CloseHandle(hTargetCurrentProcess);
        VirtualFreeEx(hTargetProcess, remoteParam, 0, MEM_RELEASE);
        VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hTargetProcess);
        return false;
    }

    WaitForSingleObject(hHookThread, INFINITE);

    // 新增：卸载DLL防止崩溃
    LPTHREAD_START_ROUTINE freeLibrary = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibrary");
    if (freeLibrary && dllBase != 0) {
        HANDLE hUnloadThread = CreateRemoteThread(
            hTargetProcess,
            NULL,
            0,
            freeLibrary,
            (LPVOID)dllBase,
            0,
            NULL
        );
        if (hUnloadThread) {
            WaitForSingleObject(hUnloadThread, 2000);
            CloseHandle(hUnloadThread);
        }
    }

    // 清理资源
    VirtualFreeEx(hTargetProcess, remoteMem, 0, MEM_RELEASE);
    VirtualFreeEx(hTargetProcess, remoteParam, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hHookThread);
    CloseHandle(hTargetCurrentProcess);
    CloseHandle(hTargetProcess);
    return true;
}


/* 接收调用者进程句柄 */
void NTAPI Message_Hook_CheckIsolateAPC(ULONG_PTR param) {
    HANDLE hCallerProcess = reinterpret_cast<HANDLE>(param);
    __try {
        if (v8::Isolate* isolate = GetSafeIsolate()) {
            v8::Local<v8::Context> context;
            v8_get_current_context_prt(isolate, &context);
            BindJSPPrinter(context, hCallerProcess);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exceptionCode = GetExceptionCode();
        char errorMsg[256];
        sprintf_s(errorMsg, 256, "⚠ APC回调异常 (0x%08X)", exceptionCode);
        OutputDebugStringA(errorMsg);
        MessageBoxA(NULL, errorMsg, "运行时错误", MB_ICONERROR | MB_OK); // 服务环境建议移除弹窗
    }
}

extern "C" __declspec(dllexport) DWORD WINAPI Init_Message_Hook(LPVOID lpParam) {
    // 参数有效性验证
    if (!lpParam || IsBadReadPtr(lpParam, sizeof(HANDLE))) {
        return ERROR_INVALID_PARAMETER;
    }

    // 复制进程句柄保证跨进程有效性
    HANDLE hCallerProcessOrig = *reinterpret_cast<HANDLE*>(lpParam);
    HANDLE hCallerProcess = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), hCallerProcessOrig,
        GetCurrentProcess(), &hCallerProcess,
        0, FALSE, DUPLICATE_SAME_ACCESS)) {
        return GetLastError();
    }

    // 线程枚举优化
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
    std::vector<DWORD> threadIds;
    const DWORD currentPID = GetCurrentProcessId();
    const DWORD currentTID = GetCurrentThreadId();

    if (Thread32First(hSnapshot, &te32)) {
        do {
            // 包含所有非当前线程的线程
            if (te32.th32OwnerProcessID == currentPID &&
                te32.th32ThreadID != currentTID) {
                threadIds.push_back(te32.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    CloseHandle(hSnapshot);

    // APC注入优化
    constexpr DWORD APC_TIMEOUT = 8000;
    std::vector<std::pair<HANDLE, HANDLE>> apcHandles; // <hThread, hEvent>
    for (DWORD tid : threadIds) {
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            FALSE, tid);
        if (!hThread) continue;

        HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!hEvent) {
            CloseHandle(hThread);
            continue;
        }

        // 挂起线程确保APC执行
        if (SuspendThread(hThread) != -1) {
            if (QueueUserAPC(Message_Hook_CheckIsolateAPC, hThread,
                reinterpret_cast<ULONG_PTR>(hCallerProcess))) {
                apcHandles.emplace_back(hThread, hEvent);
            }
            else {
                ResumeThread(hThread);
                CloseHandle(hEvent);
                CloseHandle(hThread);
            }
        }
    }

    // 批量恢复线程并等待
    DWORD activeCount = apcHandles.size();
    for (auto& [hThread, hEvent] : apcHandles) {
        ResumeThread(hThread);
    }

    if (activeCount > 0) {
        HANDLE* events = new HANDLE[activeCount];
        for (size_t i = 0; i < activeCount; ++i) {
            events[i] = apcHandles[i].second;
        }

        WaitForMultipleObjects(activeCount, events, TRUE, APC_TIMEOUT);
        delete[] events;
    }

    // 资源清理
    for (auto& [hThread, hEvent] : apcHandles) {
        CloseHandle(hEvent);
        CloseHandle(hThread);
    }

    return activeCount > 0 ? ERROR_SUCCESS : ERROR_OPERATION_ABORTED;
}


extern "C" __declspec(dllexport) DWORD WINAPI Init_CompileFunction_Hook(LPVOID lpParam) {
    if (!lpParam || IsBadReadPtr(lpParam, sizeof(HANDLE))) {
        return ERROR_INVALID_PARAMETER;
    }
    HANDLE hCallerProcessOrig = *reinterpret_cast<HANDLE*>(lpParam);
    HANDLE hCallerProcess = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), hCallerProcessOrig,
        GetCurrentProcess(), &hCallerProcess,
        0, FALSE, DUPLICATE_SAME_ACCESS)) {
        return GetLastError();
    }
    g_hCallerProcess = hCallerProcess;
    InitializationCompileHook();
    return ERROR_SUCCESS;
}

extern "C" __declspec(dllexport) DWORD WINAPI Init_Message_CallbackJava(LPVOID lpParam)
{
    // 从共享内存解析数据
    struct CallbackData {
        char tag[64];
        char message[1024];
    }*pData = (CallbackData*)lpParam;

    // 附加到JVM
    JNIEnv* env;
    g_jvm->AttachCurrentThread((void**)&env, NULL);

    // 调用Java方法
    jclass cls = env->FindClass("com/electron/InjectorHook");
    jmethodID mid = env->GetStaticMethodID(cls, "receiveMessage",
        "(Ljava/lang/String;Ljava/lang/String;)V");

    jstring jTag = env->NewStringUTF(pData->tag);
    jstring jMsg = env->NewStringUTF(pData->message);

    env->CallStaticVoidMethod(cls, mid, jTag, jMsg);

    // 清理资源
    env->DeleteLocalRef(jTag);
    env->DeleteLocalRef(jMsg);
    env->DeleteLocalRef(cls);
    g_jvm->DetachCurrentThread();

    // 释放内存
    VirtualFreeEx(GetCurrentProcess(), lpParam, 0, MEM_RELEASE);
    return 0;
}

extern "C" __declspec(dllexport) DWORD WINAPI Init_Message_CallbackJava_Return(LPVOID lpParam) {
#pragma pack(push, 1)
    struct CallbackData {
        char tag[64];
        char message[65536];
    };
    struct ParamsWithResult {
        CallbackData* pInputData;
        char* pOutputResult;
    };
#pragma pack(pop)

    ParamsWithResult* pParams = (ParamsWithResult*)lpParam;
    CallbackData* pData = pParams->pInputData;
    char* pResult = pParams->pOutputResult;

    // 1. 附加到JVM
    JNIEnv* env;
    if (g_jvm->AttachCurrentThread((void**)&env, nullptr) != JNI_OK) {
        strcpy_s(pResult, 65536, "[JVM_ATTACH_FAILED]");
        return 1;
    }

    // 2. 调用Java方法
    jclass cls = env->FindClass("com/electron/InjectorHook");
    if (!cls) {
        strcpy_s(pResult, 65536, "[CLASS_NOT_FOUND]");
        g_jvm->DetachCurrentThread();
        return 1;
    }

    jmethodID mid = env->GetStaticMethodID(cls, "receiveMessageReturn", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if (!mid) {
        strcpy_s(pResult, 65536, "[METHOD_NOT_FOUND]");
        env->DeleteLocalRef(cls);
        g_jvm->DetachCurrentThread();
        return 1;
    }

    // 3. 转换字符串参数
    jstring jTag = env->NewStringUTF(pData->tag);
    jstring jMsg = env->NewStringUTF(pData->message);
    if (!jTag || !jMsg) {
        strcpy_s(pResult, 65536, "[STRING_CONVERT_FAILED]");
        if (jTag) env->DeleteLocalRef(jTag);
        if (jMsg) env->DeleteLocalRef(jMsg);
        env->DeleteLocalRef(cls);
        g_jvm->DetachCurrentThread();
        return 1;
    }

    // 4. 调用方法并处理异常
    jstring jResult = (jstring)env->CallStaticObjectMethod(cls, mid, jTag, jMsg);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        strcpy_s(pResult, 65536, "[JAVA_EXCEPTION]");
    }
    else if (jResult != nullptr) {
        const char* cResult = env->GetStringUTFChars(jResult, nullptr);
        strcpy_s(pResult, 65536, cResult); // 确保目标缓冲区足够大
        env->ReleaseStringUTFChars(jResult, cResult);
        env->DeleteLocalRef(jResult);
    }
    else {
        strcpy_s(pResult, 65536, "[NULL_RESULT]");
    }

    // 5. 清理资源
    env->DeleteLocalRef(jTag);
    env->DeleteLocalRef(jMsg);
    env->DeleteLocalRef(cls);
    g_jvm->DetachCurrentThread();

    return 0;
}