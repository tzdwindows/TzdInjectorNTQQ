#pragma once

//#include "v8Tools.h"

#include <stdexcept>
#include <string>
#include <v8.h>
#include <detours.h>
#include <mutex>
#include <sstream>

#include "v8Tools.h"

FARPROC g_pCallbackJava = nullptr;
HANDLE g_hCallerProcess = nullptr;

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
typedef __int64*(__fastcall* V8MessageGetSourceLineFunc)(v8::Message* self, v8::Local<v8::Context> context);

V8MessageErrorLevelFunc OriginalMessageErrorLevel = nullptr;
MessageGetFunc OriginalMessageGet = nullptr;
GetScriptResourceNameFunc OriginalGetScriptResourceName = nullptr;
StringUtf8ValueCtorFunc OriginalUtf8ValueCtor = nullptr;

AddMessageListenerWithErrorLevelFunc OriginalAddMessageListenerWithErrorLevel = nullptr;
V8FunctionTemplateNew_t V8FunctionTemplateNew = nullptr;
V8ObjectSet_t V8ObjectSet = nullptr;
V8StringNewFromUtf8_t V8StringNewFromUtf8 = nullptr;
V8ContextGlobal_t V8ContextGlobal = nullptr;
V8GetFunction_t V8GetFunction = nullptr;
V8ObjectNew_t V8ObjectNew = nullptr;

V8MessageGetLineNumberFunc OriginalGetLineNumber = nullptr;
V8MessageGetStartColumnFunc OriginalGetStartColumn = nullptr;
V8MessageGetEndColumnFunc OriginalGetEndColumn = nullptr;
V8MessageGetSourceLineFunc OriginalGetSourceLine = nullptr;

bool InitializeV8Bindings() {
    HMODULE dllHandle = LoadLibrary(TARGET_V8_MODUIE_NAME);
    if (!dllHandle) {
        return false;
    }
    V8FunctionTemplateNew = reinterpret_cast<V8FunctionTemplateNew_t>(
        GetProcAddress(dllHandle, "?New@FunctionTemplate@v8@@SA?AV?$Local@VFunctionTemplate@v8@@@2@PEAVIsolate@2@P6AXAEBV?$FunctionCallbackInfo@VValue@v8@@@2@@ZV?$Local@VValue@v8@@@2@V?$Local@VSignature@v8@@@2@HW4ConstructorBehavior@2@W4SideEffectType@2@PEBVCFunction@2@GGG@Z")
        );

    V8ObjectSet = reinterpret_cast<V8ObjectSet_t>(
        GetProcAddress(dllHandle, "?Set@Object@v8@@QEAA?AV?$Maybe@_N@2@V?$Local@VContext@v8@@@2@V?$Local@VValue@v8@@@2@1@Z")
        );

    V8StringNewFromUtf8 = reinterpret_cast<V8StringNewFromUtf8_t>(
        GetProcAddress(dllHandle, "?NewFromUtf8@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBDW4NewStringType@2@H@Z")
        );

    V8ContextGlobal = reinterpret_cast<V8ContextGlobal_t>(
        GetProcAddress(dllHandle, "?Global@Context@v8@@QEAA?AV?$Local@VObject@v8@@@2@XZ")
        );

    V8GetFunction = reinterpret_cast<V8GetFunction_t>(
        GetProcAddress(dllHandle, "?GetFunction@FunctionTemplate@v8@@QEAA?AV?$MaybeLocal@VFunction@v8@@@2@V?$Local@VContext@v8@@@2@@Z")
        );

    V8ObjectNew = reinterpret_cast<V8ObjectNew_t>(
        GetProcAddress(dllHandle, "?New@Object@v8@@SA?AV?$Local@VObject@v8@@@2@PEAVIsolate@2@@Z")
        );

    OriginalAddMessageListenerWithErrorLevel = reinterpret_cast<AddMessageListenerWithErrorLevelFunc>(
        GetProcAddress(dllHandle, "?AddMessageListenerWithErrorLevel@Isolate@v8@@QEAA_NP6AXV?$Local@VMessage@v8@@@2@V?$Local@VValue@v8@@@2@@ZH1@Z")
        );

	OriginalMessageGet = reinterpret_cast<MessageGetFunc>(
        GetProcAddress(dllHandle, "?Get@Message@v8@@QEBA?AV?$Local@VString@v8@@@2@XZ")
        );

	OriginalGetScriptResourceName = reinterpret_cast<GetScriptResourceNameFunc>(
        GetProcAddress(dllHandle, "?GetScriptResourceName@Message@v8@@QEBA?AV?$Local@VValue@v8@@@2@XZ")
        );

    OriginalMessageErrorLevel = (V8MessageErrorLevelFunc)GetProcAddress(
        dllHandle,
        "?ErrorLevel@Message@v8@@QEBAHXZ" 
    );

    OriginalGetLineNumber = (V8MessageGetLineNumberFunc)GetProcAddress(dllHandle, 
        "?GetLineNumber@Message@v8@@QEBA?AV?$Maybe@H@2@V?$Local@VContext@v8@@@2@@Z");
    OriginalGetStartColumn = (V8MessageGetStartColumnFunc)GetProcAddress(dllHandle, "?GetStartColumn@Message@v8@@QEBAHXZ");
    OriginalGetEndColumn = (V8MessageGetEndColumnFunc)GetProcAddress(dllHandle, "?GetEndColumn@Message@v8@@QEBAHXZ");
    OriginalGetSourceLine = (V8MessageGetSourceLineFunc)GetProcAddress(dllHandle,
        "?GetSourceLine@Message@v8@@QEBA?AV?$MaybeLocal@VString@v8@@@2@V?$Local@VContext@v8@@@2@@Z");

    if (!V8FunctionTemplateNew || !V8ObjectSet || !V8StringNewFromUtf8 
        || !V8ContextGlobal || !V8GetFunction || !V8ObjectNew) {
        FreeLibrary(dllHandle);
        return false;
    }
    return true;
}

v8::Local<v8::Object> GetGlobalObject(v8::Local<v8::Context> context) {
    v8::Local<v8::Object> global;
    V8ContextGlobal(context, &global);
    return global;
}

void CallbackJavaLayer(const std::string& tag, const std::string& message)
{
    if (!g_hCallerProcess) return;

    // 在调用者进程分配内存
    struct CallbackData {
        char tag[64];
        char message[1024];
    } data;

    strcpy_s(data.tag, sizeof(data.tag), tag.c_str());
    strcpy_s(data.message, sizeof(data.message), message.c_str());

    LPVOID remoteData = VirtualAllocEx(g_hCallerProcess, NULL, sizeof(data), MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(g_hCallerProcess, remoteData, &data, sizeof(data), NULL);

    CreateRemoteThread(g_hCallerProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)
        GetProcAddress(g_hModule,
            "Init_Message_CallbackJava"),
        remoteData, 0, NULL);
}

std::string CallbackJavaLayer_Return(const std::string& tag, const std::string& message) {
    if (!g_hCallerProcess || tag.empty() || message.empty()) return message;

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

    // 1. 准备输入数据
    CallbackData data;
    strcpy_s(data.tag, sizeof(data.tag), tag.c_str()); // 明确指定缓冲区大小
    strcpy_s(data.message, sizeof(data.message), message.c_str());

    // 2. 分配远程内存
    LPVOID remoteInputData = VirtualAllocEx(g_hCallerProcess, nullptr, sizeof(CallbackData), MEM_COMMIT, PAGE_READWRITE);
    if (!remoteInputData || !WriteProcessMemory(g_hCallerProcess, remoteInputData, &data, sizeof(CallbackData), nullptr)) {
        if (remoteInputData) VirtualFreeEx(g_hCallerProcess, remoteInputData, 0, MEM_RELEASE);
        return message;
    }

    LPVOID remoteOutputData = VirtualAllocEx(g_hCallerProcess, nullptr, 1024, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteOutputData) {
        VirtualFreeEx(g_hCallerProcess, remoteInputData, 0, MEM_RELEASE);
        return message;
    }

    // 3. 构建参数结构体
    ParamsWithResult params = { (CallbackData*)remoteInputData, (char*)remoteOutputData };
    LPVOID remoteParams = VirtualAllocEx(g_hCallerProcess, nullptr, sizeof(ParamsWithResult), MEM_COMMIT, PAGE_READWRITE);
    if (!remoteParams || !WriteProcessMemory(g_hCallerProcess, remoteParams, &params, sizeof(ParamsWithResult), nullptr)) {
        VirtualFreeEx(g_hCallerProcess, remoteInputData, 0, MEM_RELEASE);
        VirtualFreeEx(g_hCallerProcess, remoteOutputData, 0, MEM_RELEASE);
        if (remoteParams) VirtualFreeEx(g_hCallerProcess, remoteParams, 0, MEM_RELEASE);
        return message;
    }

    // 4. 获取远程函数地址
    FARPROC pFunc = GetProcAddress(g_hModule, "Init_Message_CallbackJava_Return");
    if (!pFunc) {
        VirtualFreeEx(g_hCallerProcess, remoteInputData, 0, MEM_RELEASE);
        VirtualFreeEx(g_hCallerProcess, remoteOutputData, 0, MEM_RELEASE);
        VirtualFreeEx(g_hCallerProcess, remoteParams, 0, MEM_RELEASE);
        return message;
    }

    // 5. 创建远程线程
    HANDLE hThread = CreateRemoteThread(g_hCallerProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pFunc, remoteParams, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(g_hCallerProcess, remoteInputData, 0, MEM_RELEASE);
        VirtualFreeEx(g_hCallerProcess, remoteOutputData, 0, MEM_RELEASE);
        VirtualFreeEx(g_hCallerProcess, remoteParams, 0, MEM_RELEASE);
        return message;
    }

    // 6. 等待线程完成
    WaitForSingleObject(hThread, INFINITE);

    // 7. 读取结果
    char resultBuffer[65536] = { 0 };
    ReadProcessMemory(g_hCallerProcess, remoteOutputData, resultBuffer, 65536, nullptr);

    // 8. 释放资源
    VirtualFreeEx(g_hCallerProcess, remoteInputData, 0, MEM_RELEASE);
    VirtualFreeEx(g_hCallerProcess, remoteOutputData, 0, MEM_RELEASE);
    VirtualFreeEx(g_hCallerProcess, remoteParams, 0, MEM_RELEASE);
    CloseHandle(hThread);

    return std::string(resultBuffer);
}


void MessageCallback(v8::Local<v8::Message> message, v8::Local<v8::Value> data) {
    v8::Isolate* isolate = GetSafeIsolate();
    if (!isolate || message.IsEmpty()) return;

    v8::Local<v8::Context> context;
    v8_get_current_context_prt(isolate, &context);

    v8::HandleScope handle_scope(isolate);
    std::stringstream output;

    // ================ 基础信息 ================
    v8::Local<v8::String> msg_value;
    v8::Local<v8::Value> script_value;
    OriginalMessageGet(*message, &msg_value);
    OriginalGetScriptResourceName(*message, &script_value);

    output << "[Message] " << V8ValueToStdString(isolate, msg_value) << "\n";

    // ================ 脚本路径 ================
    if (!script_value.IsEmpty()) {
        output << "Script: " << V8ValueToStdString(isolate, script_value) << "\n";
    }

    int start_col = OriginalGetStartColumn(*message);
    int end_col = OriginalGetEndColumn(*message);

    // ================ 行列号信息 ================
    if (OriginalGetLineNumber) {
        int line = OriginalGetLineNumber(*message, context);

        output << "Position: Line " << line
            << ", Column " << start_col
            << "-" << end_col << "\n";
    }

    // ================ 错误代码片段 ================
    if (OriginalGetSourceLine) {
        // v8::Message::GetSourceLine(v8::Local<v8::Context>);
        __int64* pSourceLine = (__int64*)OriginalGetSourceLine(*message, context);
        if (!pSourceLine){
	        return;
        }
        v8::MaybeLocal<v8::String> maybe_source_line = *reinterpret_cast<v8::MaybeLocal<v8::String>*>(pSourceLine);
        v8::Local<v8::String> source_line;

        if (!maybe_source_line.IsEmpty() && maybe_source_line.ToLocal(&source_line) && !source_line.IsEmpty()) {
            std::string code = V8ValueToStdString(isolate, source_line);
            output << "Source:\n" << code << "\n";
        }
        else {
            output << "Source: [Not Available]\n";
        }
    }

    // ================ 错误分类 ================
    int error_level = OriginalMessageErrorLevel(*message);
    const char* type = (error_level == 2) ? "error" : "console"; // kMessageError=2
    CallbackJavaLayer(type, output.str());
}


void RegisterMessageListener(v8::Isolate* isolate) {
	if (!OriginalAddMessageListenerWithErrorLevel){
        InitializeV8Bindings();
	}
    v8::Local<v8::Context> context;
    v8_get_current_context_prt(isolate, &context);
    v8::Local<v8::Value> data = v8::Undefined(isolate);
    OriginalAddMessageListenerWithErrorLevel(isolate, 
        MessageCallback, 
        8,
        data);
}

// 挂钩 Js 的函数实现监控输出
void BindJSPPrinter(v8::Local<v8::Context> context, HANDLE hProcess) {
    g_hCallerProcess = hProcess;
    /*if (!InitializeV8Bindings()) {
        return;
    }
    {
        
        v8::Isolate* isolate = v8_context_get_isolate(context);
        v8::Local<v8::Object> global = GetGlobalObject(context);
        //v8::HandleScope handle_scope(isolate);
        v8::HandleScope handle_scope;
        pHandleScopeCtor(&handle_scope, isolate);
        v8::Local<v8::FunctionTemplate> print_template;
        V8FunctionTemplateNew(
            &print_template,        // 返回值通过指针写入
            isolate,
            JSPrintCallback,        // 这是一个回调函数
            v8::Local<v8::Value>(), // 显式构造空 Local 对象
            v8::Local<v8::Signature>(),
            0,                      // length
            v8::ConstructorBehavior::kAllow,
            v8::SideEffectType::kHasSideEffect,
            nullptr,                // c_function
            0,          // 0
            0,          // 0
            0             // 0
        );
        v8::MaybeLocal<v8::Function>* print_function;
        print_function = V8GetFunction(print_template, &print_function, context);
        if (print_function->IsEmpty()) {
            return;
        }
        v8::Local<v8::Object> console = V8ObjectNew(isolate);
        char ret;
        V8ObjectSet(
            console, &ret,
            context,
            local_string_from_string(isolate, "log"),
            print_function->ToLocalChecked()
        );
        if (ret != 1){
        	MessageBoxA(NULL, "Failed to set console.log", "错误", MB_ICONINFORMATION);
        }
        V8ObjectSet(
            global, &ret,
            context,
            local_string_from_string(isolate, "console"),
            console
        );
        if (ret != 1) {
            MessageBoxA(NULL, "Failed to set global.console", "错误", MB_ICONINFORMATION);
        }
    }*/
    v8::Isolate* isolate = v8_context_get_isolate(context);
    RegisterMessageListener(isolate);
}