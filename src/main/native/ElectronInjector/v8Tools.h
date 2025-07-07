#pragma once

#include <stdexcept>
#include <string>
#include <v8.h>
#include <detours.h>
#include <mutex>


// 全局变量保存DLL模块句柄
extern HMODULE g_hModule;

/*	目标V8模块 */
#define TARGET_V8_MODUIE_NAME L"QQNT.dll"

/* v8列表 */
extern std::vector<v8::Isolate*> g_isolateList;
extern std::mutex g_isolateMutex;

// v8::FunctionTemplate::New 的实际签名
typedef void(__fastcall* V8FunctionTemplateNew_t)(
    v8::Local<v8::FunctionTemplate>* ret,
    v8::Isolate* isolate,
    v8::FunctionCallback callback,
    v8::Local<v8::Value> data,
    v8::Local<v8::Signature> signature,
    int length,
    v8::ConstructorBehavior behavior,
    v8::SideEffectType side_effect_type,
    const v8::CFunction* c_function,
    uint16_t instance_type,
    uint16_t allowed_receiver_instance_type_range_start,
    uint16_t allowed_receiver_instance_type_range_end
    );

// v8::Object::Set 的实际签名
typedef char* (__fastcall* V8ObjectSet_t)(
    v8::Local<v8::Object> object,
    char* ret,
    v8::Local<v8::Context> context,
    v8::Local<v8::Value> index,
    v8::Local<v8::Value> value
    );

// v8::String::NewFromUtf8 的声明
typedef v8::MaybeLocal<v8::String>(__fastcall* V8StringNewFromUtf8_t)(
    v8::Isolate* isolate,
    const char* data,
    v8::NewStringType type,
    int length
    );

typedef void(__fastcall* V8ContextGlobal_t)(
    v8::Local<v8::Context> context, // 隐式返回值通过第一个参数返回
    v8::Local<v8::Object>* result     // 隐式this指针
    );

// GetFunction
typedef v8::MaybeLocal<v8::Function>* (__fastcall* V8GetFunction_t)(
    v8::Local<v8::FunctionTemplate> func_template,
    v8::MaybeLocal<v8::Function>** result,
    v8::Local<v8::Context> context
    );

// v8::Object::New
typedef v8::Local<v8::Object>(*V8ObjectNew_t)(
    //v8::Local<v8::Object> result,
    v8::Isolate* isolate
    );

typedef bool(__fastcall* AddMessageListenerWithErrorLevelFunc)(v8::Isolate*, void (*)(v8::Local<v8::Message>, v8::Local<v8::Value>), int, v8::Local<v8::Value>);

typedef void(__fastcall* MessageGetFunc)(v8::Message* self, v8::Local<v8::String>* out);

// v8::Message::GetScriptResourceName
typedef void(__fastcall* GetScriptResourceNameFunc)(v8::Message* self, v8::Local<v8::Value>* out);

typedef uint64_t(__fastcall* StringUtf8ValueCtorFunc)(uint64_t, uint64_t, uint64_t);
typedef int(__fastcall* V8MessageErrorLevelFunc)(void* message);

typedef int(__fastcall* V8MessageGetLineNumberFunc)(v8::Message* self, v8::Local<v8::Context> context);
typedef int(__fastcall* V8MessageGetStartColumnFunc)(v8::Message* self);
typedef int(__fastcall* V8MessageGetEndColumnFunc)(v8::Message* self);
typedef __int64* (__fastcall* V8MessageGetSourceLineFunc)(v8::Message* self, v8::Local<v8::Context> context);
typedef void(__cdecl* V8NewFromUtf8_t)(
    v8::MaybeLocal<v8::String>* result,
    v8::Isolate* isolate,
    const char* data,
    v8::NewStringType type,
    int length
    );
typedef void (*AddMessageListenerFunc)(v8::Isolate*, v8::MessageCallback, v8::Local<v8::Value>);
typedef v8::Isolate* (__fastcall* V8ContextGetIsolate)(v8::Local<v8::Context> t_object);
typedef void(__fastcall* V8GetCurrentContext)(v8::Isolate* isolate, v8::Local<v8::Context>* out);
typedef int(__fastcall* V8Utf8Length)(
    v8::Local<v8::String> t_string,
    v8::Isolate* a2
    );
typedef int(__fastcall* V8WriteUtf8)(
    v8::Local<v8::String> t_string,
    v8::Isolate* isolate, char* buffer, int length,
    int* nchars_ref, int options
    );
typedef v8::Isolate* (__fastcall* V8TryGetCurrent)();

typedef v8::MaybeLocal<v8::Script>(*ScriptCompileFunc)(
    v8::Local<v8::Context>,
    v8::Local<v8::String>,
    v8::ScriptOrigin*
    );

typedef void(__fastcall* V8ScriptRunEx_t)(
    v8::Script* self,          // this指针 (RCX/XMM0)
    v8::MaybeLocal<v8::Value>* ret, // 返回值存储位置 (RDX/XMM1)
    v8::Local<v8::Context> context, // 参数1 (R8/XMM2)
    v8::Local<v8::Data> options     // 参数2 (R9/XMM3)
    );

typedef void(__fastcall* V8TryCatchException_t)(
    const void* try_catch,      // this指针 (RCX)
    v8::Local<v8::Value>* out_exception // 返回值存储位置 (RDX)
    );

typedef void(__fastcall* V8TryCatchMessage_t)(
    const void* try_catch,        // this指针 (RCX)
    v8::Local<v8::Message>* out   // 返回值存储位置 (RDX)
    );

typedef void(__fastcall* V8MessageGetScriptOrigin_t)(
    const void* message, 
    v8::ScriptOrigin* out
    );


typedef void(__fastcall* V8ScriptOriginResourceName_t)(
    const void* script_origin,  // this指针 (RCX)
    v8::Local<v8::Value>* out   // 返回值存储位置 (RDX)
    );

typedef void(__fastcall* V8MessageGetLineNumber_t)(
    const void* message,        // this指针 (RCX)
    v8::Maybe<int>* out_result, // 输出参数 (RDX)
    v8::Local<v8::Context> context // 参数 (R8)
    );


typedef void(__fastcall* V8HandleScopeCtor_t)(v8::HandleScope* self, v8::Isolate* isolate);
typedef void(__fastcall* V8HandleScopeDtor_t)(v8::HandleScope* self);
typedef void(__fastcall* V8TryCatchCtor_t)(v8::TryCatch* self, v8::Isolate* isolate);
typedef void(__fastcall* V8TryCatchDtor_t)(v8::TryCatch* self);

typedef void(__fastcall* V8IsolateDispose_t)(v8::Isolate* self);

class V8_EXPORT V8_NODISCARD Scope_ {
private:
    v8::internal::Isolate* v8_isolate_;
};

class V8_EXPORT Locker_ {

private:
    bool has_lock_;
    bool top_level_;
    v8::internal::Isolate* isolate_;
};

typedef void(__fastcall* V8LockerCtor_t)(Locker_* self, v8::Isolate* isolate);
typedef void(__fastcall* V8LockerDtor_t)(Locker_* self);

typedef void(__fastcall* V8IsolateScopeCtor_t)(Scope_* self, v8::Isolate* isolate);
typedef void(__fastcall* V8IsolateScopeDtor_t)(Scope_* self);

extern V8TryCatchException_t V8TryCatchException;
extern V8TryCatchMessage_t V8TryCatchMessage;
extern V8MessageGetScriptOrigin_t V8MessageGetScriptOrigin;
extern V8ScriptOriginResourceName_t V8ScriptOriginResourceName;
extern V8MessageGetLineNumber_t  V8MessageGetLineNumber;
extern V8NewFromUtf8_t V8NewFromUtf8;
extern V8ContextGetIsolate v8_context_get_isolate_prt;
extern V8GetCurrentContext v8_get_current_context_prt;
extern V8ScriptRunEx_t v8_script_run_ex;
extern V8TryGetCurrent v8_try_get_current;
extern V8Utf8Length v8_Utf8Length;
extern V8WriteUtf8 v8_WriteUtf8;
extern ScriptCompileFunc pCompile;
extern V8LockerCtor_t pV8LockerCtor;
extern V8LockerDtor_t pV8LockerDtor;
extern V8IsolateScopeCtor_t pV8IsolateScopeCtor;
extern V8IsolateScopeDtor_t pV8IsolateScopeDtor;
extern V8IsolateDispose_t pV8IsolateDispose;
extern V8HandleScopeCtor_t pHandleScopeCtor;
extern V8HandleScopeDtor_t pHandleScopeDtor;
extern V8TryCatchCtor_t pTryCatchCtor;
extern V8TryCatchDtor_t pTryCatchDtor;
extern std::atomic<v8::Isolate*> g_MainIsolate;
extern AddMessageListenerFunc OriginalAddMessageListener;
extern V8MessageErrorLevelFunc OriginalMessageErrorLevel;
extern MessageGetFunc OriginalMessageGet;
extern GetScriptResourceNameFunc OriginalGetScriptResourceName;
extern StringUtf8ValueCtorFunc OriginalUtf8ValueCtor;

extern AddMessageListenerWithErrorLevelFunc OriginalAddMessageListenerWithErrorLevel;
extern V8FunctionTemplateNew_t V8FunctionTemplateNew;
extern V8ObjectSet_t V8ObjectSet;
extern V8StringNewFromUtf8_t V8StringNewFromUtf8;
extern V8ContextGlobal_t V8ContextGlobal;
extern V8GetFunction_t V8GetFunction;
extern V8ObjectNew_t V8ObjectNew;

extern V8MessageGetLineNumberFunc OriginalGetLineNumber;
extern V8MessageGetStartColumnFunc OriginalGetStartColumn;
extern V8MessageGetEndColumnFunc OriginalGetEndColumn;
extern V8MessageGetSourceLineFunc OriginalGetSourceLine;

extern void Initialization();
extern void __fastcall HookedV8IsolateDispose(v8::Isolate* isolate);
extern bool InstallV8DisposeHook();
extern v8::Isolate* HookedV8IsolateGetCurrent();
extern v8::Local<v8::String> local_string_from_string(
    v8::Isolate* isolate,
    const std::string& str
);
extern void CallbackJavaLayer(const std::string& tag, const std::string& message);
extern std::string CallbackJavaLayer_Return(const std::string& tag, const std::string& message);

extern std::string V8ValueToStdString(v8::Isolate* isolate, v8::Local<v8::Value> value);
extern size_t v8_string_utf8_length(v8::Isolate* isolate, v8::Local<v8::String> local_string);
extern std::string string_from_local_string(v8::Isolate* isolate, v8::Local<v8::String> local_string);
extern DWORD FindProcessId(const wchar_t* processName);
extern v8::Isolate* v8_context_get_isolate(v8::Local<v8::Context> context);
extern v8::MaybeLocal<v8::Script> v8_compile(
    v8::Local<v8::Context> context, v8::Local<v8::String> source,
    v8::ScriptOrigin* origin = nullptr
);
extern LONG WINAPI V8ExceptionFilter(EXCEPTION_POINTERS* ep);
extern v8::Isolate* GetSafeIsolate();
extern bool InitializeV8Bindings();
extern "C" __declspec(dllexport) DWORD WINAPI ExportFunction(LPVOID lpParam);
extern "C" __declspec(dllexport) DWORD WINAPI InstallationHook(LPVOID lpParam);