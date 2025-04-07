#include "pch.h"

#include "v8_hook.h"

#include <TlHelp32.h>

CompileFunctionPtr originalCompileFunction = nullptr;
CompileUnboundInternalPtr originalCompileUnboundInternal = nullptr;

// CompileFunction
// ���뺯��ʱ��ִ���������
v8::MaybeLocal<v8::Function> HookCompileFunction(
    v8::Local<v8::Context> context, v8::ScriptCompiler::Source* source, size_t arguments_count,
    v8::Local<v8::String> arguments[], size_t context_extension_count,
    v8::Local<v8::Object> context_extensions[],
    v8::ScriptCompiler::CompileOptions options,
    v8::ScriptCompiler::NoCacheReason no_cache_reason
) {
    v8::Isolate* isolate = v8_context_get_isolate(context);
    std::string originalCode = string_from_local_string(isolate, source->source_string);
    std::string modifiedCode = CallbackJavaLayer_Return("CompileFunction", originalCode);
    source->source_string = local_string_from_string(isolate, modifiedCode);
    return originalCompileFunction(context, source, arguments_count, arguments, context_extension_count, context_extensions, options, no_cache_reason);
}

//ScriptCompiler::CompileUnboundInternal
// �ڱ���ģ��ͽű���ʱ��������������
extern V8_WARN_UNUSED_RESULT v8::MaybeLocal<v8::UnboundScript> HookCompileUnboundInternal(
    v8::internal::Isolate* isolateInternal, v8::ScriptCompiler::Source* source,
    v8::ScriptCompiler::CompileOptions options, v8::ScriptCompiler::NoCacheReason no_cache_reason)
{
    // ����ʱ���ִ���������ʱ��ע�͵�
    v8::Isolate* isolate = reinterpret_cast<v8::Isolate*>(isolateInternal);
    v8::Local<v8::Context> context;
    v8_get_current_context_prt(isolate, &context);
    std::string originalCode = string_from_local_string(isolate, source->source_string);
    std::string modifiedCode = CallbackJavaLayer_Return("CompileUnboundInternal", originalCode);
    source->source_string = local_string_from_string(isolate, modifiedCode);
    return originalCompileUnboundInternal(isolateInternal, source, options, no_cache_reason);
}

void InitializationCompileHook() {
    if (originalCompileFunction == nullptr)
    {
        originalCompileFunction = reinterpret_cast<CompileFunctionPtr>(
            GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "?CompileFunction@ScriptCompiler@v8@@SA?AV?$MaybeLocal@VFunction@v8@@@2@V?$Local@VContext@v8@@@2@PEAVSource@12@_KQEAV?$Local@VString@v8@@@2@2QEAV?$Local@VObject@v8@@@2@W4CompileOptions@12@W4NoCacheReason@12@@Z"));
        if (originalCompileFunction == nullptr) {
            MessageBoxA(NULL, "Failed to find CompileFunction!",
                "Received tag", MB_OK | MB_ICONINFORMATION);
            return;
        }
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
    // ���������̲߳��ҹ�
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
    DWORD currentThreadId = GetCurrentThreadId();

    if (hSnapshot != INVALID_HANDLE_VALUE && Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId() &&
                te32.th32ThreadID != currentThreadId) {
                // ��ÿ���߳̽��йҹ�
                DetourTransactionBegin();
                HANDLE hThread = OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                    FALSE,
                    te32.th32ThreadID
                );
                if (hThread) {
                    DetourUpdateThread(hThread);
                    DetourAttach(&(PVOID&)originalCompileFunction, HookCompileFunction);
                    DetourAttach(&(PVOID&)originalCompileUnboundInternal, HookCompileUnboundInternal);
                    DetourTransactionCommit();
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
        CloseHandle(hSnapshot);
    }
}