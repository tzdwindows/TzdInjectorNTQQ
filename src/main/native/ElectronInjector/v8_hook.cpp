#include "pch.h"

#include "v8_hook.h"

#include <TlHelp32.h>

CompileFunctionPtr originalCompileFunction = nullptr;
CompileUnboundInternalPtr originalCompileUnboundInternal = nullptr;
CompileModulePtr originalCompileModule = nullptr;
OriginalCallType originalCall = nullptr;
OriginalNewInstanceWithSideEffectTypeType originalNewInstanceWithSideEffectType = nullptr;

// CompileFunction
// 编译函数时会执行这个函数
v8::MaybeLocal<v8::Function> HookCompileFunction(
    v8::Local<v8::Context> context, v8::ScriptCompiler::Source* source, size_t arguments_count,
    v8::Local<v8::String> arguments[], size_t context_extension_count,
    v8::Local<v8::Object> context_extensions[],
    v8::ScriptCompiler::CompileOptions options,
    v8::ScriptCompiler::NoCacheReason no_cache_reason
) {
    v8::Isolate* isolate = v8_context_get_isolate(context);
    if (std::find(g_isolateList.begin(), g_isolateList.end(), isolate) == g_isolateList.end()) {
        g_isolateList.push_back(isolate);
    }
    std::string originalCode = string_from_local_string(isolate, source->source_string);
    std::string modifiedCode = CallbackJavaLayer_Return("CompileFunction", originalCode);
    source->source_string = local_string_from_string(isolate, modifiedCode);
    return originalCompileFunction(context, source, arguments_count, arguments, context_extension_count, context_extensions, options, no_cache_reason);
}

// Hook for ScriptCompiler::CompileUnboundInternal
// 在编译模块和脚本的时候会调用整个函数
V8_WARN_UNUSED_RESULT v8::MaybeLocal<v8::UnboundScript> HookCompileUnboundInternal(
    v8::internal::Isolate* isolateInternal, v8::ScriptCompiler::Source* source,
    v8::ScriptCompiler::CompileOptions options, v8::ScriptCompiler::NoCacheReason no_cache_reason)
{
    v8::Isolate* isolate = reinterpret_cast<v8::Isolate*>(isolateInternal);
    if (std::find(g_isolateList.begin(), g_isolateList.end(), isolate) == g_isolateList.end()) {
        g_isolateList.push_back(isolate);
    }

    v8::Local<v8::Context> context;
    v8_get_current_context_prt(isolate, &context);
    std::string originalCode = string_from_local_string(isolate, source->source_string);
    std::string modifiedCode = CallbackJavaLayer_Return("CompileUnboundInternal", originalCode);
    source->source_string = local_string_from_string(isolate, modifiedCode);
    return originalCompileUnboundInternal(isolateInternal, source, options, no_cache_reason);
}

// Hook for v8::ScriptCompiler::CompileModule
v8::MaybeLocal<v8::Module> HookCompileModule(
    v8::Local<v8::Context> context,
    v8::ScriptCompiler::Source* source,
    v8::Local<v8::String> referrer,
    const v8::ScriptOrigin& origin)
{
    v8::Isolate* isolate = v8_context_get_isolate(context);
    if (std::find(g_isolateList.begin(), g_isolateList.end(), isolate) == g_isolateList.end()) {
        g_isolateList.push_back(isolate);
    }
    std::string originalCode = string_from_local_string(isolate, source->source_string);
    std::string modifiedCode = CallbackJavaLayer_Return("CompileModule", originalCode);
    source->source_string = local_string_from_string(isolate, modifiedCode);
    return originalCompileModule(context, source, referrer, origin);
}

// Hook for v8::Function::Call
void __fastcall HookCall(
    v8::Function* thisPtr,
    v8::MaybeLocal<v8::Value>* returnValue,
    v8::Local<v8::Context> context,
    v8::Local<v8::Value> recv, int argc,
    v8::Local<v8::Value> argv[])
{
    //MessageBoxA(NULL, "params.c_str()", "HookCall Parameters", MB_OK | MB_ICONINFORMATION);
    v8::Isolate* isolate = v8_context_get_isolate(context);
    if (std::find(g_isolateList.begin(), g_isolateList.end(), isolate) == g_isolateList.end()) {
        g_isolateList.push_back(isolate);
    }
    std::string params = "thisPtr=" + std::to_string(reinterpret_cast<uintptr_t>(thisPtr)) +
        ", argc=" + std::to_string(argc);
    params += ", recv=" + V8ValueToStdString(isolate, recv);
    for (int i = 0; i < argc; i++) {
        params += ", argv[" + std::to_string(i) + "]=" + V8ValueToStdString(isolate, argv[i]);
    }
    //MessageBoxA(NULL, params.c_str(), "HookCall Parameters", MB_OK | MB_ICONINFORMATION);
    std::string javaResponse = CallbackJavaLayer_Return("v8::Function::Call", params);
    if (javaResponse == "[end]") {
        *returnValue = v8::MaybeLocal<v8::Value>();
        return;
    }
    originalCall(thisPtr, returnValue, context, recv, argc, argv);
}

// Hook for v8::Function::NewInstanceWithSideEffectType
v8::MaybeLocal<v8::Object> __fastcall HookNewInstanceWithSideEffectType(
    v8::Function* thisPtr,
    v8::Local<v8::Context> context,
    int argc,
    v8::Local<v8::Value> argv[],
    v8::SideEffectType side_effect_type)
{
    v8::Isolate* isolate = v8_context_get_isolate(context);
    if (std::find(g_isolateList.begin(), g_isolateList.end(), isolate) == g_isolateList.end()) {
        g_isolateList.push_back(isolate);
    }
    std::string params = "thisPtr=" + std::to_string(reinterpret_cast<uintptr_t>(thisPtr)) +
        ", argc=" + std::to_string(argc) +
        ", side_effect_type=" + std::to_string(static_cast<int>(side_effect_type));
    for (int i = 0; i < argc; i++) {
        params += ", argv[" + std::to_string(i) + "]=" + V8ValueToStdString(isolate, argv[i]);
    }
    std::string javaResponse = CallbackJavaLayer_Return("v8::Function::NewInstanceWithSideEffectType", params);
    if (javaResponse == "[end]") {
        return v8::MaybeLocal<v8::Object>();
    }
    return originalNewInstanceWithSideEffectType(thisPtr, context, argc, argv, side_effect_type);
}

extern void InitializationCallHook() {
    std::thread hookThread([]() {
        while (originalCall == nullptr) {
            originalCall = reinterpret_cast<OriginalCallType>(
                GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "?Call@Function@v8@@QEAA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VValue@v8@@@2@HQEAV52@@Z"));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (originalNewInstanceWithSideEffectType == nullptr) {
            originalNewInstanceWithSideEffectType = reinterpret_cast<OriginalNewInstanceWithSideEffectTypeType>(
                GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME),
                    "?NewInstanceWithSideEffectType@Function@v8@@QEBA?AV?$MaybeLocal@VObject@v8@@@2@V?$Local@VContext@v8@@@2@HQEAV?$Local@VValue@v8@@@2@W4SideEffectType@2@@Z"));
        }
        if (originalNewInstanceWithSideEffectType == nullptr) {
            MessageBoxA(NULL, "Failed to find NewInstanceWithSideEffectType!",
                "Received tag", MB_OK | MB_ICONINFORMATION);
            return;
        }
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
                        __try {
                            DetourUpdateThread(hThread);
                            DetourDetach(&(PVOID&)originalCall, HookCall);
                            DetourAttach(&(PVOID&)originalNewInstanceWithSideEffectType, HookNewInstanceWithSideEffectType);
                            DetourTransactionCommit();
                            CloseHandle(hThread);
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {
                            OutputDebugStringA("SEH bypass successful! Executing code in exception handler.\n");
                        }
                    }
                }
            } while (Thread32Next(hSnapshot, &te32));
            CloseHandle(hSnapshot);
        }
    });
        hookThread.detach();
}

extern void InitializationCompileHook() {
    //v8::Function::Call
    std::thread hookThread([]() {
        while (originalCompileFunction == nullptr) {
            originalCompileFunction = reinterpret_cast<CompileFunctionPtr>(
                GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "?CompileFunction@ScriptCompiler@v8@@SA?AV?$MaybeLocal@VFunction@v8@@@2@V?$Local@VContext@v8@@@2@PEAVSource@12@_KQEAV?$Local@VString@v8@@@2@2QEAV?$Local@VObject@v8@@@2@W4CompileOptions@12@W4NoCacheReason@12@@Z"));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (originalCompileUnboundInternal == nullptr)
        {
            originalCompileUnboundInternal = reinterpret_cast<CompileUnboundInternalPtr>(
                GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "?CompileUnboundInternal@ScriptCompiler@v8@@CA?AV?$MaybeLocal@VUnboundScript@v8@@@2@PEAVIsolate@2@PEAVSource@12@W4CompileOptions@12@W4NoCacheReason@12@@Z"));
            if (originalCompileUnboundInternal == nullptr) {
                MessageBoxA(NULL, "Failed to find CompileFunction!",
                    "Received tag", MB_OK | MB_ICONINFORMATION);
                return;
            }
        }
        if (originalCompileModule == nullptr)
        {
            originalCompileModule = reinterpret_cast<CompileModulePtr>(
                GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "?CompileModule@ScriptCompiler@v8@@SA?AV?$MaybeLocal@VModule@v8@@@2@V?$Local@VContext@v8@@@2@PEAVStreamedSource@12@V?$Local@VString@v8@@@2@AEBVScriptOrigin@2@@Z"));
            if (originalCompileModule == nullptr) {
                MessageBoxA(NULL, "Failed to find CompileModule!",
                    "Received tag", MB_OK | MB_ICONINFORMATION);
            }
        }

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
                        __try {
                            DetourUpdateThread(hThread);
                            DetourAttach(&(PVOID&)originalCompileFunction, HookCompileFunction);
                            DetourAttach(&(PVOID&)originalCompileUnboundInternal, HookCompileUnboundInternal);
                            DetourAttach(&(PVOID&)originalCompileModule, HookCompileModule);
                            DetourTransactionCommit();
                            CloseHandle(hThread);
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {
                            OutputDebugStringA("SEH bypass successful! Executing code in exception handler.\n");
                        }
                    }
                }
            } while (Thread32Next(hSnapshot, &te32));
            CloseHandle(hSnapshot);
        }
        });
    hookThread.detach();
}