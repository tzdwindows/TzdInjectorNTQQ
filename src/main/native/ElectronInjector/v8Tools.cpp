#include "pch.h"

#include "v8Tools.h"

#include <TlHelp32.h>

HMODULE g_hModule = nullptr;
std::vector<v8::Isolate*> g_isolateList;
std::mutex g_isolateMutex;
std::atomic<v8::Isolate*> g_MainIsolate{ nullptr };

V8TryCatchException_t V8TryCatchException = reinterpret_cast<V8TryCatchException_t>(
    GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?Exception@TryCatch@v8@@QEBA?AV?$Local@VValue@v8@@@2@XZ"));

V8TryCatchMessage_t V8TryCatchMessage = reinterpret_cast<V8TryCatchMessage_t>(
    GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?Message@TryCatch@v8@@QEBA?AV?$Local@VMessage@v8@@@2@XZ"));

V8MessageGetScriptOrigin_t V8MessageGetScriptOrigin = reinterpret_cast<V8MessageGetScriptOrigin_t>(
    GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?GetScriptOrigin@Message@v8@@QEBA?AVScriptOrigin@2@XZ"));

V8ScriptOriginResourceName_t V8ScriptOriginResourceName = reinterpret_cast<V8ScriptOriginResourceName_t>(
    GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?ResourceName@ScriptOrigin@v8@@QEBA?AV?$Local@VValue@v8@@@2@XZ"));

V8MessageGetLineNumber_t  V8MessageGetLineNumber = reinterpret_cast<V8MessageGetLineNumber_t>(
    GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?GetLineNumber@Message@v8@@QEBA?AV?$Maybe@H@2@V?$Local@VContext@v8@@@2@@Z"));

V8NewFromUtf8_t V8NewFromUtf8 = reinterpret_cast<V8NewFromUtf8_t>(
    GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?NewFromUtf8@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBDW4NewStringType@2@H@Z")
    );

V8ContextGetIsolate v8_context_get_isolate_prt = reinterpret_cast<V8ContextGetIsolate>(
    GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?GetIsolate@Object@v8@@QEAAPEAVIsolate@2@XZ")
    );

V8GetCurrentContext v8_get_current_context_prt = reinterpret_cast<V8GetCurrentContext>(
    GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?GetCurrentContext@Isolate@v8@@QEAA?AV?$Local@VContext@v8@@@2@XZ")
    );

V8ScriptRunEx_t v8_script_run_ex = reinterpret_cast<V8ScriptRunEx_t>(
    GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?Run@Script@v8@@QEAA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VData@v8@@@2@@Z")
    );

V8TryGetCurrent v8_try_get_current = reinterpret_cast<V8TryGetCurrent>(
    GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?TryGetCurrent@Isolate@v8@@SAPEAV12@XZ")
    );

 V8Utf8Length v8_Utf8Length = reinterpret_cast<V8Utf8Length>(
    GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?Utf8Length@String@v8@@QEBAHPEAVIsolate@2@@Z")
    );

V8WriteUtf8 v8_WriteUtf8 = reinterpret_cast<V8WriteUtf8>(
    GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?WriteUtf8@String@v8@@QEBAHPEAVIsolate@2@PEADHPEAHH@Z")
    );

ScriptCompileFunc pCompile = reinterpret_cast<ScriptCompileFunc>(
    GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "?Compile@Script@v8@@SA?AV?$MaybeLocal@VScript@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VString@v8@@@2@PEAVScriptOrigin@2@@Z")
    );

V8LockerCtor_t pV8LockerCtor = reinterpret_cast<V8LockerCtor_t>(
    GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "??0Locker@v8@@QEAA@PEAVIsolate@1@@Z")
    );

V8LockerDtor_t pV8LockerDtor = reinterpret_cast<V8LockerDtor_t>(
    GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "??1Locker@v8@@QEAA@XZ")
    );

V8IsolateScopeCtor_t pV8IsolateScopeCtor = reinterpret_cast<V8IsolateScopeCtor_t>(
    GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "??0Scope@Isolate@v8@@QEAA@PEAV12@@Z")
    );

V8IsolateScopeDtor_t pV8IsolateScopeDtor = reinterpret_cast<V8IsolateScopeDtor_t>(
    GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "??1Scope@Isolate@v8@@QEAA@XZ")
    );

V8IsolateDispose_t pV8IsolateDispose = reinterpret_cast<V8IsolateDispose_t>(
    GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "?Dispose@Isolate@v8@@QEAAXXZ")
    );

V8HandleScopeCtor_t pHandleScopeCtor = (V8HandleScopeCtor_t)GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME),
    "??0HandleScope@v8@@QEAA@PEAVIsolate@1@@Z");

V8HandleScopeDtor_t pHandleScopeDtor = (V8HandleScopeDtor_t)GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME),
    "??1HandleScope@v8@@QEAA@XZ");

V8TryCatchCtor_t pTryCatchCtor = (V8TryCatchCtor_t)GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME),
    "??0TryCatch@v8@@QEAA@PEAVIsolate@1@@Z");

V8TryCatchDtor_t pTryCatchDtor = (V8TryCatchDtor_t)GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME),
    "??1TryCatch@v8@@QEAA@XZ");

AddMessageListenerFunc OriginalAddMessageListener = nullptr;

void Initialization()
{
    V8TryCatchException = reinterpret_cast<V8TryCatchException_t>(
        GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?Exception@TryCatch@v8@@QEBA?AV?$Local@VValue@v8@@@2@XZ"));

    V8TryCatchMessage = reinterpret_cast<V8TryCatchMessage_t>(
        GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?Message@TryCatch@v8@@QEBA?AV?$Local@VMessage@v8@@@2@XZ"));

    V8MessageGetScriptOrigin = reinterpret_cast<V8MessageGetScriptOrigin_t>(
        GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?GetScriptOrigin@Message@v8@@QEBA?AVScriptOrigin@2@XZ"));

    V8ScriptOriginResourceName = reinterpret_cast<V8ScriptOriginResourceName_t>(
        GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?ResourceName@ScriptOrigin@v8@@QEBA?AV?$Local@VValue@v8@@@2@XZ"));

    V8MessageGetLineNumber = reinterpret_cast<V8MessageGetLineNumber_t>(
        GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?GetLineNumber@Message@v8@@QEBA?AV?$Maybe@H@2@V?$Local@VContext@v8@@@2@@Z"));

    V8NewFromUtf8 = reinterpret_cast<V8NewFromUtf8_t>(
        GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?NewFromUtf8@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBDW4NewStringType@2@H@Z")
        );

    v8_context_get_isolate_prt = reinterpret_cast<V8ContextGetIsolate>(
        GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?GetIsolate@Object@v8@@QEAAPEAVIsolate@2@XZ")
        );

    v8_get_current_context_prt = reinterpret_cast<V8GetCurrentContext>(
        GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?GetCurrentContext@Isolate@v8@@QEAA?AV?$Local@VContext@v8@@@2@XZ")
        );

    v8_script_run_ex = reinterpret_cast<V8ScriptRunEx_t>(
        GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?Run@Script@v8@@QEAA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VData@v8@@@2@@Z")
        );

    v8_try_get_current = reinterpret_cast<V8TryGetCurrent>(
        GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?TryGetCurrent@Isolate@v8@@SAPEAV12@XZ")
        );

    v8_Utf8Length = reinterpret_cast<V8Utf8Length>(
        GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?Utf8Length@String@v8@@QEBAHPEAVIsolate@2@@Z")
        );

    v8_WriteUtf8 = reinterpret_cast<V8WriteUtf8>(
        GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME), "?WriteUtf8@String@v8@@QEBAHPEAVIsolate@2@PEADHPEAHH@Z")
        );

    pCompile = reinterpret_cast<ScriptCompileFunc>(
        GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "?Compile@Script@v8@@SA?AV?$MaybeLocal@VScript@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VString@v8@@@2@PEAVScriptOrigin@2@@Z")
        );

    pV8LockerCtor = reinterpret_cast<V8LockerCtor_t>(
        GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "??0Locker@v8@@QEAA@PEAVIsolate@1@@Z")
        );

    pV8LockerDtor = reinterpret_cast<V8LockerDtor_t>(
        GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "??1Locker@v8@@QEAA@XZ")
        );

    pV8IsolateScopeCtor = reinterpret_cast<V8IsolateScopeCtor_t>(
        GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "??0Scope@Isolate@v8@@QEAA@PEAV12@@Z")
        );

    pV8IsolateScopeDtor = reinterpret_cast<V8IsolateScopeDtor_t>(
        GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "??1Scope@Isolate@v8@@QEAA@XZ")
        );

    pV8IsolateDispose = reinterpret_cast<V8IsolateDispose_t>(
        GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "?Dispose@Isolate@v8@@QEAAXXZ")
        );

    pHandleScopeCtor = (V8HandleScopeCtor_t)GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME),
        "??0HandleScope@v8@@QEAA@PEAVIsolate@1@@Z");

    pHandleScopeDtor = (V8HandleScopeDtor_t)GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME),
        "??1HandleScope@v8@@QEAA@XZ");

    pTryCatchCtor = (V8TryCatchCtor_t)GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME),
        "??0TryCatch@v8@@QEAA@PEAVIsolate@1@@Z");

    pTryCatchDtor = (V8TryCatchDtor_t)GetProcAddress(LoadLibrary(TARGET_V8_MODUIE_NAME),
        "??1TryCatch@v8@@QEAA@XZ");
}

void __fastcall HookedV8IsolateDispose(v8::Isolate* isolate) {
    // 检查是否为需要保护的主 Isolate
    if (isolate == g_MainIsolate.load(std::memory_order_acquire)) {
        OutputDebugStringA("[Hook] Blocked Dispose of main Isolate");
        return;  // 阻止释放
    }

    // 调用原始函数释放其他 Isolate
    pV8IsolateDispose(isolate);
}

bool InstallV8DisposeHook() {
    // 确保已获取原始函数地址
    if (!pV8IsolateDispose) {
        return false;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // 附加 Hook
    DetourAttach(
        reinterpret_cast<PVOID*>(&pV8IsolateDispose),
        HookedV8IsolateDispose
    );

    return DetourTransactionCommit() == NO_ERROR;
}

v8::Isolate* HookedV8IsolateGetCurrent() {
    v8::Isolate* isolate = v8_try_get_current();
    if (isolate) {
        if (std::find(g_isolateList.begin(), g_isolateList.end(), isolate) == g_isolateList.end()) {
            g_isolateList.push_back(isolate);
        }
    }
    return isolate;
}

v8::Local<v8::String> local_string_from_string(
    v8::Isolate* isolate,
    const std::string& str
) {

    v8::MaybeLocal<v8::String> result;
    V8NewFromUtf8(&result, isolate, str.c_str(), v8::NewStringType::kNormal, static_cast<int>(str.length()));
    return result.ToLocalChecked();
}

std::string V8ValueToStdString(v8::Isolate* isolate, v8::Local<v8::Value> value) {
    // 实现需要根据逆向的Utf8Value构造函数
    struct V8Utf8Value {
        char* str;
        int length;

        V8Utf8Value(v8::Isolate* isolate, v8::Local<v8::Value> value) {
            typedef void(__fastcall* Utf8ValueCtor_t)(void* self, v8::Isolate*, v8::Local<v8::Value>);
            static Utf8ValueCtor_t ctor = reinterpret_cast<Utf8ValueCtor_t>(
                GetProcAddress(GetModuleHandle(TARGET_V8_MODUIE_NAME), "??0Utf8Value@String@v8@@QEAA@PEAVIsolate@2@V?$Local@VValue@v8@@@2@@Z")
                );

            ctor(this, isolate, value);
        }
    };

    V8Utf8Value utf8(isolate, value);
    return std::string(utf8.str, utf8.length);
}

size_t v8_string_utf8_length(v8::Isolate* isolate, v8::Local<v8::String> local_string) {
    int length = v8_Utf8Length(local_string, isolate);
    if (length < 0) {
        throw std::runtime_error("Failed to get UTF-8 length");
    }
    return static_cast<size_t>(length);
}

std::string string_from_local_string(v8::Isolate* isolate, v8::Local<v8::String> local_string) {
    try {
        if (local_string.IsEmpty()) {
            return std::string("Error: local_string is empty");
        }
        size_t length = v8_string_utf8_length(isolate, local_string);
        std::vector<char> buffer(length + 1, '\0');
        v8_WriteUtf8(local_string, isolate, buffer.data(), length, nullptr, v8::String::NO_NULL_TERMINATION);
        return std::string(buffer.data());
    }
    catch (const std::exception& e) {
        return std::string("Error: ") + e.what();
    }
}

DWORD FindProcessId(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }
    CloseHandle(snapshot);
    return pid;
}

v8::Isolate* v8_context_get_isolate(v8::Local<v8::Context> context) {
    return v8_context_get_isolate_prt(context);
}

v8::MaybeLocal<v8::Script> v8_compile(
    v8::Local<v8::Context> context, v8::Local<v8::String> source,
    v8::ScriptOrigin* origin
)
{
    return pCompile(context, source, origin);
}

// 异常过滤函数（记录错误信息）
LONG WINAPI V8ExceptionFilter(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    PVOID addr = ep->ExceptionRecord->ExceptionAddress;
    return EXCEPTION_EXECUTE_HANDLER;
}

v8::Isolate* GetSafeIsolate() {
    if (!v8_try_get_current) {
        return nullptr;
    }

    __try {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(v8_try_get_current, &mbi, sizeof(mbi))) {
            if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                return nullptr;  // 内存区域不可执行
            }
        }
        v8::Isolate* isolate = v8_try_get_current();

        if (IsBadReadPtr(isolate, sizeof(v8::Isolate))) {
            return nullptr;
        }

        return isolate;
    }
    __except (V8ExceptionFilter(GetExceptionInformation())) {
        return nullptr;
    }
}