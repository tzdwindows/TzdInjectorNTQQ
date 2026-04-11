#include "pch.h"
#include "com_electron_InjectorHook.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <atomic>
#include <vector>
#include <utility>

#include "v8_printer_hook.h"
#include "v8_hook.h"
#include "InjectorCore.h"

// 全局变量
JavaVM* g_jvm = nullptr;
jclass g_hookClass = nullptr; // 用于缓存 Java 类引用

std::atomic<bool> g_bMessageHookInstalled{ false };

// 专门为 APC 传递参数的结构体
struct ApcContext {
    HANDLE hJavaProcess;
    HANDLE hEvent;
};

void ShowError(const wchar_t* message) {
    MessageBoxW(NULL, message, L"Injection Error", MB_ICONERROR | MB_OK);
}

// 辅助函数：初始化全局类引用
void InitGlobalClassReference(JNIEnv* env) {
    if (g_hookClass == nullptr) {
        jclass localClass = env->FindClass("com/electron/InjectorHook");
        if (localClass) {
            // 必须创建全局引用，否则 localClass 在函数返回后会失效
            g_hookClass = (jclass)env->NewGlobalRef(localClass);
        }
        else {
            ShowError(L"Critical: Cannot find com.electron.InjectorHook class!");
        }
    }
}

// ==============================================================================
// Java 触发注入接口 (运行在 Java 进程主线程)
// ==============================================================================

JNIEXPORT jboolean JNICALL Java_com_electron_InjectorHook_initCompilationHook(JNIEnv* env, jclass, jstring processName) {
    if (!g_hModule) return false;

    // 1. 缓存 JVM 和 Class
    env->GetJavaVM(&g_jvm);
    InitGlobalClassReference(env);

    const wchar_t* targetProcessStr = (const wchar_t*)env->GetStringChars(processName, nullptr);
    DWORD pid = FindProcessId(targetProcessStr);
    env->ReleaseStringChars(processName, (const jchar*)targetProcessStr);

    if (pid == 0) return false;

    HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hTargetProcess) return false;

    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(g_hModule, dllPath, MAX_PATH);

    PVOID remoteBase = InjectorCore::MapModuleGhosting(hTargetProcess, dllPath);
    if (!remoteBase) { CloseHandle(hTargetProcess); return false; }

    HMODULE hTempDll = LoadLibraryExW(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    FARPROC localHookFunc = GetProcAddress(hTempDll, "Init_CompileFunction_Hook");
    DWORD_PTR rva = (DWORD_PTR)localHookFunc - (DWORD_PTR)hTempDll;
    FreeLibrary(hTempDll);
    LPVOID remoteHookFunc = (LPVOID)((DWORD_PTR)remoteBase + rva);

    HANDLE hTargetCurrentProcess = NULL;
    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), hTargetProcess, &hTargetCurrentProcess, 0, FALSE, DUPLICATE_SAME_ACCESS);

    IPC_INIT_DATA initData = { 0 };
    initData.hJavaProcess = hTargetCurrentProcess;
    initData.pfnCallbackJava = GetProcAddress(g_hModule, "Init_Message_CallbackJava");
    initData.pfnCallbackJavaReturn = GetProcAddress(g_hModule, "Init_Message_CallbackJava_Return");

    LPVOID remoteParam = VirtualAllocEx(hTargetProcess, NULL, sizeof(IPC_INIT_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hTargetProcess, remoteParam, &initData, sizeof(IPC_INIT_DATA), NULL);

    HANDLE hHookThread = CreateRemoteThread(hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteHookFunc, remoteParam, 0, NULL);
    if (hHookThread) {
        WaitForSingleObject(hHookThread, INFINITE);
        CloseHandle(hHookThread);
    }

    VirtualFreeEx(hTargetProcess, remoteParam, 0, MEM_RELEASE);
    CloseHandle(hTargetCurrentProcess);
    CloseHandle(hTargetProcess);
    return true;
}

JNIEXPORT jboolean JNICALL Java_com_electron_InjectorHook_initMessageHook(JNIEnv* env, jclass, jstring processName) {
    if (!g_hModule) return false;

    // 1. 缓存 JVM 和 Class
    env->GetJavaVM(&g_jvm);
    InitGlobalClassReference(env);

    const wchar_t* targetProcessStr = (const wchar_t*)env->GetStringChars(processName, nullptr);
    DWORD pid = FindProcessId(targetProcessStr);
    env->ReleaseStringChars(processName, (const jchar*)targetProcessStr);

    if (pid == 0) return false;

    HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hTargetProcess) return false;

    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(g_hModule, dllPath, MAX_PATH);

    PVOID remoteBase = InjectorCore::MapModuleGhosting(hTargetProcess, dllPath);
    if (!remoteBase) { CloseHandle(hTargetProcess); return false; }

    HMODULE hTempDll = LoadLibraryExW(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    FARPROC localHookFunc = GetProcAddress(hTempDll, "Init_Message_Hook");
    DWORD_PTR rva = (DWORD_PTR)localHookFunc - (DWORD_PTR)hTempDll;
    FreeLibrary(hTempDll);
    LPVOID remoteHookFuncAddr = (LPVOID)((DWORD_PTR)remoteBase + rva);

    HANDLE hTargetCurrentProcess = NULL;
    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), hTargetProcess, &hTargetCurrentProcess, 0, FALSE, DUPLICATE_SAME_ACCESS);

    IPC_INIT_DATA initData = { 0 };
    initData.hJavaProcess = hTargetCurrentProcess;
    initData.pfnCallbackJava = GetProcAddress(g_hModule, "Init_Message_CallbackJava");
    initData.pfnCallbackJavaReturn = GetProcAddress(g_hModule, "Init_Message_CallbackJava_Return");

    LPVOID remoteParam = VirtualAllocEx(hTargetProcess, NULL, sizeof(IPC_INIT_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hTargetProcess, remoteParam, &initData, sizeof(IPC_INIT_DATA), NULL);

    HANDLE hHookThread = CreateRemoteThread(hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteHookFuncAddr, remoteParam, 0, NULL);
    if (hHookThread) {
        WaitForSingleObject(hHookThread, INFINITE);
        CloseHandle(hHookThread);
    }

    VirtualFreeEx(hTargetProcess, remoteParam, 0, MEM_RELEASE);
    CloseHandle(hTargetCurrentProcess);
    CloseHandle(hTargetProcess);
    return true;
}

// ==============================================================================
// 远程 Payload (运行在 QQ.exe 中)
// ==============================================================================

void NTAPI Message_Hook_CheckIsolateAPC(ULONG_PTR param) {
    ApcContext* ctx = reinterpret_cast<ApcContext*>(param);
    if (!ctx) return;

    if (!g_bMessageHookInstalled.load()) {
        __try {
            if (v8::Isolate* isolate = GetSafeIsolate()) {
                v8::Local<v8::Context> context;
                v8_get_current_context_prt(isolate, &context);

                bool expected = false;
                if (g_bMessageHookInstalled.compare_exchange_strong(expected, true)) {
                    BindJSPPrinter(context, ctx->hJavaProcess);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    SetEvent(ctx->hEvent);
    delete ctx;
}

extern "C" __declspec(dllexport) DWORD WINAPI Init_Message_Hook(LPVOID lpParam) {
    if (!lpParam) return ERROR_INVALID_PARAMETER;
    IPC_INIT_DATA* pData = (IPC_INIT_DATA*)lpParam;

    // 保存到 QQ 进程的全局变量
    g_hCallerProcess = pData->hJavaProcess;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return GetLastError();

    THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
    std::vector<DWORD> threadIds;
    const DWORD currentPID = GetCurrentProcessId();

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == currentPID && te32.th32ThreadID != GetCurrentThreadId()) {
                threadIds.push_back(te32.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    CloseHandle(hSnapshot);

    std::vector<HANDLE> waitEvents;
    for (DWORD tid : threadIds) {
        if (g_bMessageHookInstalled.load()) break;
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!hThread) continue;

        HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (SuspendThread(hThread) != -1) {
            ApcContext* ctx = new ApcContext{ g_hCallerProcess, hEvent };
            if (QueueUserAPC(Message_Hook_CheckIsolateAPC, hThread, reinterpret_cast<ULONG_PTR>(ctx))) {
                waitEvents.push_back(hEvent);
            }
            else {
                delete ctx;
                CloseHandle(hEvent);
            }
            ResumeThread(hThread);
        }
        else {
            CloseHandle(hEvent);
        }
        CloseHandle(hThread);
    }

    if (!waitEvents.empty()) {
        WaitForMultipleObjects(waitEvents.size(), waitEvents.data(), TRUE, 5000);
        for (HANDLE h : waitEvents) CloseHandle(h);
    }
    return ERROR_SUCCESS;
}

extern "C" __declspec(dllexport) DWORD WINAPI Init_CompileFunction_Hook(LPVOID lpParam) {
    if (!lpParam) return ERROR_INVALID_PARAMETER;
    IPC_INIT_DATA* pData = (IPC_INIT_DATA*)lpParam;
    g_hCallerProcess = pData->hJavaProcess;
    InitializationCompileHook();
    return ERROR_SUCCESS;
}

// ==============================================================================
// 逆向回调逻辑 (运行在 Java 进程中)
// ==============================================================================

extern "C" __declspec(dllexport) DWORD WINAPI Init_Message_CallbackJava(LPVOID lpParam) {
    if (!lpParam) return 1;
    struct CallbackData { char tag[64]; char message[1024]; }*pData = (CallbackData*)lpParam;

    JNIEnv* env;
    if (g_jvm->AttachCurrentThread((void**)&env, NULL) != JNI_OK) return 1;

    // 【修复点】使用全局缓存的 g_hookClass，不要调用 FindClass
    if (g_hookClass) {
        jmethodID mid = env->GetStaticMethodID(g_hookClass, "receiveMessage", "(Ljava/lang/String;Ljava/lang/String;)V");
        if (mid) {
            jstring jTag = env->NewStringUTF(pData->tag);
            jstring jMsg = env->NewStringUTF(pData->message);
            env->CallStaticVoidMethod(g_hookClass, mid, jTag, jMsg);
            env->DeleteLocalRef(jTag);
            env->DeleteLocalRef(jMsg);
        }
    }

    g_jvm->DetachCurrentThread();
    VirtualFree(lpParam, 0, MEM_RELEASE); // 释放由远程线程分配的内存
    return 0;
}

extern "C" __declspec(dllexport) DWORD WINAPI Init_Message_CallbackJava_Return(LPVOID lpParam) {
    if (!lpParam) return 1;
#pragma pack(push, 1)
    struct CallbackData { char tag[64]; char message[65536]; };
    struct ParamsWithResult { CallbackData* pInputData; char* pOutputResult; };
#pragma pack(pop)

    ParamsWithResult* pParams = (ParamsWithResult*)lpParam;
    JNIEnv* env;
    if (g_jvm->AttachCurrentThread((void**)&env, nullptr) != JNI_OK) return 1;

    if (g_hookClass) {
        jmethodID mid = env->GetStaticMethodID(g_hookClass, "receiveMessageReturn", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
        if (mid) {
            jstring jTag = env->NewStringUTF(pParams->pInputData->tag);
            jstring jMsg = env->NewStringUTF(pParams->pInputData->message);
            jstring jResult = (jstring)env->CallStaticObjectMethod(g_hookClass, mid, jTag, jMsg);

            if (!env->ExceptionCheck() && jResult) {
                const char* cResult = env->GetStringUTFChars(jResult, nullptr);
                strcpy_s(pParams->pOutputResult, 65536, cResult);
                env->ReleaseStringUTFChars(jResult, cResult);
                env->DeleteLocalRef(jResult);
            }
            env->DeleteLocalRef(jTag);
            env->DeleteLocalRef(jMsg);
        }
    }

    g_jvm->DetachCurrentThread();
    return 0;
}