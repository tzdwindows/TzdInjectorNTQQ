package com.electron;

import lombok.experimental.*;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.VisibleForTesting;

import java.lang.annotation.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Javascript钩子管理器
 *
 * @author tzdwindows 7
 * @version 1.3
 * @since 2023-11
 * @implNote 使用CopyOnWriteArrayList保证线程安全的钩子列表操作
 *
 * @Platform("Windows")
 * @Architecture(64)
 */
@UtilityClass
@SuppressWarnings("all")
public class InjectorHook {
    /**
     * Javascript消息钩子列表（线程安全）
     * @GuardedBy("JAVASCRIPT_MESSAGE_HOOKS")
     */
    private static final List<JavascriptMessageHook> JAVASCRIPT_MESSAGE_HOOKS = new CopyOnWriteArrayList<>();

    /**
     * Javascript编译器钩子列表（线程安全）
     * @GuardedBy("JAVASCRIPT_COMPILATION_HOOKS")
     */
    private static final List<JavascriptCompilationHook> JAVASCRIPT_COMPILATION_HOOKS = new CopyOnWriteArrayList<>();

    /**
     * 设置Javascript消息钩子
     * @param hook 消息钩子实例（不可为null）
     * @throws NullPointerException 当参数为null时抛出
     *
     * @LogOperation(type = OperationType.HOOK_MANAGEMENT)
     * @Auditable(action = "HOOK_REGISTRATION")
     */
    @Injector.Concurrent(level = Injector.ThreadSafetyLevel.MULTITHREAD_SAFE)
    public static void setJavascriptMessageHook(
            @NotNull JavascriptMessageHook hook
    ) {
        if (hook == null) {
            //log.error("尝试注册空消息钩子");
            throw new NullPointerException("消息钩子不可为null");
        }
        JAVASCRIPT_MESSAGE_HOOKS.add(hook);
        //log.info("注册消息钩子: {}", hook.getClass().getName());
    }

    /**
     * 移除已注册的消息钩子
     * @param hook 需要移除的钩子实例
     * @return 是否成功移除
     *
     * @LogOperation(type = OperationType.HOOK_MANAGEMENT)
     */
    public static boolean removeJavascriptMessageHook(
            JavascriptMessageHook hook
    ) {
        boolean result = JAVASCRIPT_MESSAGE_HOOKS.remove(hook);
        if (result) {
           // log.debug("移除消息钩子: {}", hook.getClass().getName());
        }
        return result;
    }

    /**
     * 设置Javascript编译器钩子
     * @param hook 编译器钩子实例（不可为null）
     * @throws NullPointerException 当参数为null时抛出
     *
     * @LogOperation(type = OperationType.HOOK_MANAGEMENT)
     * @Auditable(action = "COMPILER_HOOK_REGISTRATION")
     */
    @Injector.Concurrent(level = Injector.ThreadSafetyLevel.MULTITHREAD_SAFE)
    public static void setJavascriptCompilationHook(
            @NotNull JavascriptCompilationHook hook
    ) {
        if (hook == null) {
            // log.error("尝试注册空编译器钩子");
            throw new NullPointerException("编译器钩子不可为null");
        }
        JAVASCRIPT_COMPILATION_HOOKS.add(hook);
        //log.info("注册编译器钩子: {}", hook.getClass().getName());
    }

    /**
     * 移除已注册的编译器钩子
     * @param hook 需要移除的钩子实例
     * @return 是否成功移除
     *
     * @LogOperation(type = OperationType.HOOK_MANAGEMENT)
     */
    public static boolean removeJavascriptCompilationHook(
            JavascriptCompilationHook hook
    ) {
        boolean result = JAVASCRIPT_COMPILATION_HOOKS.remove(hook);
        if (result) {
            //log.debug("移除编译器钩子: {}", hook.getClass().getName());
        }
        return result;
    }

    /**
     * JNI消息接收入口（禁止外部调用）
     *
     * @param tag 消息标签
     * @param message 原始消息内容
     * @apiNote 此方法由本地代码异步调用
     *
     * @GuardedBy("JAVASCRIPT_MESSAGE_HOOKS")
     */
    @CalledByNative
    @VisibleForTesting
    static void receiveMessage(String tag, String message) {
        // log.trace("接收消息 - Tag: {}, Content: {}", tag, message);
        for (JavascriptMessageHook hook : JAVASCRIPT_MESSAGE_HOOKS) {
            try {
                hook.receiveMessage(tag, message);
            } catch (Exception e) {
                System.err.println("消息钩子执行异常: " + hook.getClass().getName());
            }
        }
    }

    /**
     * JNI编译器钩子处理入口（禁止外部调用）
     *
     * @param tag 处理阶段标签
     * @param message 待处理代码内容
     * @return 处理后的代码内容
     *
     * @GuardedBy("JAVASCRIPT_COMPILATION_HOOKS")
     */
    @CalledByNative
    @VisibleForTesting
    static String receiveMessageReturn(String tag, String message) {
        //log.trace("编译器处理请求 - Tag: {}, Content: {}", tag, message);
        String processed = message;
        for (JavascriptCompilationHook hook : JAVASCRIPT_COMPILATION_HOOKS) {
            try {
                processed = hook.receiveCompilationHook(tag, processed);
            } catch (Exception e) {
                //log.error("编译器钩子执行异常: {}", hook.getClass().getName(), e);
                System.err.println("编译器钩子执行异常: " + hook.getClass().getName());
            }
        }
        return processed;
    }

    /**
     * Javascript消息处理接口
     * @implSpec 实现类应确保线程安全性
     */
    @FunctionalInterface
    public interface JavascriptMessageHook {
        /**
         * 接收处理消息
         * @param tag 消息分类标签（如"network", "error"等）
         * @param message 原始消息内容
         *
         * @throws RuntimeException 实现类可能抛出任何运行时异常
         */
        @Injector.Auditable(action = "JS_MESSAGE_HANDLING")
        void receiveMessage(String tag, String message);
    }

    /**
     * Javascript编译器处理接口
     * @implNote 修改代码内容时需保持语法有效性
     */
    @FunctionalInterface
    public interface JavascriptCompilationHook {
        /**
         * 处理编译过程中的代码
         * @param tag 编译阶段标识
         * @param message 原始/前序处理后的代码内容
         * @return 处理后的代码内容
         *
         * @throws CompilationException 当代码处理导致语法错误时抛出
         */
        @Injector.Auditable(action = "CODE_TRANSFORMATION")
        String receiveCompilationHook(String tag, String message);
    }

    /**
     * 初始化编译器钩子系统
     * @param processName 目标进程名（需全匹配）
     * @return 是否成功初始化
     * @throws UnsatisfiedLinkError 当本地库未正确加载时抛出
     *
     * @NativeMethod(platform = "Windows", minArchitecture = 64)
     * @PrivilegedOperation(requiredPermissions = {"CODE_INJECTION"})
     */
    @Injector.LogOperation(type = Injector.OperationType.HOOK_INITIALIZATION)
    public static native boolean initCompilationHook(
            @NotNull @ProcessName String processName
    );

    /**
     * 初始化消息钩子系统
     * @param processName 目标进程名（需全匹配）
     * @return 是否成功初始化
     * @throws SecurityException 当权限不足时抛出
     *
     * @NativeMethod(platform = "Windows", minArchitecture = 64)
     * @PrivilegedOperation(requiredPermissions = {"MESSAGE_MONITORING"})
     */
    @Injector.LogOperation(type = Injector.OperationType.HOOK_INITIALIZATION)
    public static native boolean initMessageHook(
            @NotNull @ProcessName String processName
    );
}

/**
 * @author tzdwindows 7
 */
@Documented
@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.PARAMETER)
@interface ProcessName {
    String pattern() default "^[a-zA-Z0-9_\\-]+\\.exe$";
    String message() default "无效的进程名格式";
}

/**
 * @author tzdwindows 7
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.METHOD)
@interface CalledByNative {
}

/**
 * @author tzdwindows 7
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@interface CompilationException {
    Class<? extends Exception>[] handledExceptions() default {};
}
// endregion