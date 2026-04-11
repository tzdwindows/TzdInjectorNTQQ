#pragma once

#include "v8Tools.h"

extern FARPROC g_pCallbackJava;
extern FARPROC g_pCallbackJavaReturn;
extern HANDLE g_hCallerProcess;
extern V8MessageErrorLevelFunc OriginalMessageErrorLevel;

extern v8::Local<v8::Object> GetGlobalObject(v8::Local<v8::Context> context);
extern void MessageCallback(v8::Local<v8::Message> message, v8::Local<v8::Value> data);
extern VOID WINAPI HookedOutputDebugStringW(LPCWSTR lpOutputString);
extern VOID WINAPI HookedOutputDebugStringA(LPCSTR lpOutputString);
extern void RegisterMessageListener(v8::Isolate* isolate);
extern void BindJSPPrinter(v8::Local<v8::Context> context, HANDLE hProcess);