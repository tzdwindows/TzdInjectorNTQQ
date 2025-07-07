package com.electron;

/**
 * 进程过程控制类
 * @author tzdwindows 7
 */
public class ProcessInjection {

    /**
     * 在目标Electron渲染进程启动时加载监控钩子
     * <p>
     * 通过注入进程启动监控逻辑，捕获Electron渲染进程初始化事件，
     * 将其V8隔离实例保存到全局维护列表中。
     *
     * @param processName 目标渲染进程标识名（需与Electron主进程配置的进程名一致）
     * @apiNote 该方法适用于需要追踪多渲染进程V8隔离状态的Electron应用场景
     */
    public static native void injectionProcessHook(String processName);

    /**
     * 在指定的Electron渲染进程中注入JS代码
     * <p>
     * 注入逻辑使用{@link ProcessInjection#injectionProcessHook}维护的全局列表执行
     *
     * @param processName 目标Electron渲染进程的名称（需与全局列表中的标识匹配）
     * @param jsCode 注入的JS代码
     * @apiNote 该方法适用于Electron多进程架构中的渲染进程注入场景
     */
    public static native void injectionRenderJsCode(String processName,  String jsCode);

    public static void main(String[] args) {
        System.load("C:\\Users\\Administrator\\source\\repos\\ElectronInjector\\x64\\Release\\ElectronInjector.dll");
        injectionProcessHook("QQ.exe");
        injectionRenderJsCode("QQ.exe", "console.log('Hello World!')");
    }
}
