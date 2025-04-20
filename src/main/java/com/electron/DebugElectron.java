package com.electron;

/**
 * 当脚本注入后可以使用它来注册V8的调试工具
 * “ global.debug ”
 * @author tzdwindows 7
 */
public class DebugElectron {
    /**
     * 注册调试工具
     * @param port 调试端口（请确保唯一不与Electron原本调试器冲突）
     * @param processName 目标进程名称 (需全匹配)
     * @apiNote 已经把脚本注入到了指定v8隔离后，才能注册本方法，否则可能会出现错误
     */
    @Injector.NativeMethod(platform = "Windows", minArchitecture = 64)
    @Injector.PrivilegedOperation(requiredPermissions = {"PROCESS_INJECTION"})
    @Injector.Concurrent(level = Injector.ThreadSafetyLevel.MULTITHREAD_SAFE)
    @Injector.GuardedBy("DebugElectron.class")
    public static native void registerDebugger(String processName, int port);
}
