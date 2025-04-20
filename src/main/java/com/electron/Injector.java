package com.electron;

import lombok.experimental.UtilityClass;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.TestOnly;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.*;

/**
 * Electron的Javascript注入器
 *
 * @author tzdwindows 7
 * @version 1.2
 * @since 2023-10
 * @implNote 该实现依赖于本地库ElectronInjector.dll
 * @see <a href="https://www.electronjs.org">Electron Framework</a>
 *
 * @Platform("Windows")
 * @Architecture(64)
 */
@UtilityClass
@SuppressWarnings("all")
public class Injector {

    // region 自定义注解定义（实际应放在独立文件中）
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface NativeMethod {
        String platform() default "Windows";
        int minArchitecture() default 64;
    }

    @Retention(RetentionPolicy.CLASS)
    @Target(ElementType.METHOD)
    public @interface PrivilegedOperation {
        String[] requiredPermissions() default {"FILE_SYSTEM", "PROCESS_MANAGEMENT"};
    }

    @Retention(RetentionPolicy.SOURCE)
    @Target(ElementType.LOCAL_VARIABLE)
    public @interface DllConfiguration {
        String value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface Concurrent {
        ThreadSafetyLevel level() default ThreadSafetyLevel.MULTITHREAD_SAFE;
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface GuardedBy {
        String value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface LogOperation {
        OperationType type();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface Auditable {
        String action();
    }

    public enum ThreadSafetyLevel { SINGLE_THREAD, MULTITHREAD_SAFE }
    public enum OperationType { JS_EXECUTION, HOOK_INITIALIZATION, PROCESS_ATTACH }
    // endregion

    //static {
    //    @SuppressWarnings("all")
    //    @DllConfiguration("ElectronInjector.dll")
    //    final String dllPath = "/ElectronInjector.dll";
    //    try {
    //        System.load(dllPath);
    //    } catch (UnsatisfiedLinkError e) {
    //        try (InputStream dllStream = Main.class.getResourceAsStream(dllPath)) {
    //            if (dllStream == null) {
    //                throw new RuntimeException("DLL not found in JAR: " + dllPath);
    //            }
    //            File tempDll = File.createTempFile("electron_injector_", ".dll");
    //            tempDll.deleteOnExit();
    //            try (FileOutputStream out = new FileOutputStream(tempDll)) {
    //                byte[] buffer = new byte[1024];
    //                int bytesRead;
    //                while ((bytesRead = dllStream.read(buffer)) != -1) {
    //                    out.write(buffer, 0, bytesRead);
    //                }
    //            }
    //            System.load(tempDll.getAbsolutePath());
    //        } catch (IOException ex) {
    //            throw new RuntimeException("Failed to extract DLL from JAR", ex);
    //        }
    //    }
    //}

    /**
     * 把js代码注入到主进程中
     * @param processName 目标进程名称 (需全匹配)
     * @param jsCode      要注入的JavaScript代码 (需符合ES6规范)
     * @throws UnsatisfiedLinkError 当本地库加载失败时抛出
     * @throws SecurityException 当缺少必要权限时抛出
     * @apiNote 注入操作需要目标进程已启动且处于可调试状态
     * @deprecated 该方法已过时，请使用{@link #injectMainProcess(String, String)}代替
     */
    @GuardedBy("Injector.class")
    @Deprecated()
    public static void inject(
            @NotNull String processName,
            @NotNull String jsCode
    ){
        injectMainProcess(processName, jsCode);
    }

    /**
     * 把js代码注入到主进程中
     * @param processName 目标进程名称 (需全匹配)
     * @param jsCode      要注入的JavaScript代码 (需符合ES6规范)
     * @throws UnsatisfiedLinkError 当本地库加载失败时抛出
     * @throws SecurityException 当缺少必要权限时抛出
     * @apiNote 注入操作需要目标进程已启动且处于可调试状态
     */
    @NativeMethod(platform = "Windows", minArchitecture = 64)
    @PrivilegedOperation(requiredPermissions = {"PROCESS_INJECTION"})
    @Concurrent(level = ThreadSafetyLevel.MULTITHREAD_SAFE)
    @GuardedBy("Injector.class")
    public static native void injectMainProcess(
            @NotNull String processName,
            @NotNull String jsCode
    );

    /**
     * 把js代码注入到渲染进程中
     * @param processName 目标进程名称 (需全匹配)
     * @param jsCode      要注入的JavaScript代码 (需符合ES6规范)
     * @throws UnsatisfiedLinkError 当本地库加载失败时抛出
     * @throws SecurityException 当缺少必要权限时抛出
     * @apiNote 注入操作需要目标进程已启动且处于可调试状态
     */
    @NativeMethod(platform = "Windows", minArchitecture = 64)
    @PrivilegedOperation(requiredPermissions = {"PROCESS_INJECTION"})
    @Concurrent(level = ThreadSafetyLevel.MULTITHREAD_SAFE)
    @GuardedBy("Injector.class")
    public static native void injectRendererProcess(
            @NotNull String processName,
            @NotNull String jsCode
    );

    /**
     * 注入js模块
     * @param jsCode js代码
     * @param processName
     */
    @Deprecated(since = "1.1", forRemoval = true)
    public static native void injectModule(
            @NotNull String processName,
            @NotNull String jsCode
    );

    /**
     * 附加Electron程序到调试端口
     * @param programPath 程序路径 (需包含调试参数)
     * @throws IllegalArgumentException 当路径无效时抛出
     * @example {@code
     * additionalProgram("C:/Program Files/App/app.exe --remote-debugging-port=9222")
     * }
     */
    @LogOperation(type = OperationType.PROCESS_ATTACH)
    @Auditable(action = "PROCESS_ATTACHMENT")
    public static native void additionalProgram(
            @FileExists @ExecutablePath String programPath
    );

    /**
     * 在所有上下文中执行Javascript代码
     * @param jsCode js代码
     * @throws IllegalStateException 当程序未附加时调用
     */
    @LogOperation(type = OperationType.JS_EXECUTION)
    @Auditable(action = "JS_CODE_EXECUTION")
    @TestOnly
    public static native void executeJavascript(@NotNull String jsCode);

    /**
     * @deprecated 使用新的{@link #executeJavascript(String)} 方法替代
     * @removalVersion 2.0
     */
    @Deprecated(since = "1.1", forRemoval = true)
    public static native void injectGlobal(String jsCode);

    // public static void main(String[] args) {
    //
    // }
}

/**
 * @author tzdwindows 7
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
@interface FileExists {
    String message() default "文件路径不存在";
}

/**
 * @author tzdwindows 7
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@interface Platform {
    String[] value() default "Windows";
}

/**
 * @author tzdwindows 7
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.TYPE)
@interface Architecture {
    int value() default 64;
}

/**
 * @author tzdwindows 7
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
@interface ExecutablePath {
    String message() default "无效的可执行路径";
}
// endregion