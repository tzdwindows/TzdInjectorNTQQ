#pragma once
#include "pch.h"

#include "v8Tools.h"
#include <TlHelp32.h>

typedef v8::MaybeLocal<v8::Function>(__fastcall* CompileFunctionPtr)(
    v8::Local<v8::Context> context, v8::ScriptCompiler::Source* source, size_t arguments_count,
    v8::Local<v8::String> arguments[], size_t context_extension_count,
    v8::Local<v8::Object> context_extensions[],
    v8::ScriptCompiler::CompileOptions options,
    v8::ScriptCompiler::NoCacheReason no_cache_reason
    );

typedef v8::MaybeLocal<v8::UnboundScript>(__fastcall* CompileUnboundInternalPtr)(
    v8::internal::Isolate* isolate,
    v8::ScriptCompiler::Source* source,
    v8::ScriptCompiler::CompileOptions options,
    v8::ScriptCompiler::NoCacheReason no_cache_reason
    );

extern CompileFunctionPtr originalCompileFunction;
extern CompileUnboundInternalPtr originalCompileUnboundInternal;

extern V8_WARN_UNUSED_RESULT v8::MaybeLocal<v8::UnboundScript> HookCompileUnboundInternal(
    v8::internal::Isolate* isolateInternal, v8::ScriptCompiler::Source* source,
    v8::ScriptCompiler::CompileOptions options, v8::ScriptCompiler::NoCacheReason no_cache_reason);

extern v8::MaybeLocal<v8::Function> HookCompileFunction(
    v8::Local<v8::Context> context, v8::ScriptCompiler::Source* source, size_t arguments_count = 0,
    v8::Local<v8::String> arguments[] = nullptr, size_t context_extension_count = 0,
    v8::Local<v8::Object> context_extensions[] = nullptr,
    v8::ScriptCompiler::CompileOptions options = v8::ScriptCompiler::kNoCompileOptions,
    v8::ScriptCompiler::NoCacheReason no_cache_reason = v8::ScriptCompiler::kNoCacheNoReason
);

extern void InitializationCompileHook();