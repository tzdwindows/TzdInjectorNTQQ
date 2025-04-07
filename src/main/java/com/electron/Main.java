package com.electron;

/**
 * QQ 客户端JavaScript注入控制器
 *
 * <p>本类演示如何通过动态注入、编译器钩子、消息拦截等技术，
 * 实现对QQ客户端JavaScript执行环境的深度控制。</p>
 *
 * @author tzdwindows 7
 * @version 1.0
 */
public class Main {

    /**
     * 主入口 - JavaScript执行环境控制演示
     *
     * <p>包含四个核心功能演示：
     * 1. 动态代码注入
     * 2. 编译器钩子注册
     * 3. 消息监控钩子
     * 4. 远程调试附加控制</p>
     *
     * @param args 命令行参数（未使用）
     */
    public static void main(String[] args) {
        System.loadLibrary("Injector");
        //======================================================================
        // 模块一：动态代码注入
        //======================================================================
        /* 将指定JavaScript代码注入QQ主进程的JS上下文
         * @param processName 目标进程名称 (QQ.exe)
         * @param script      要注入的JS代码
         */
        Injector.inject(
                "QQ.exe",
                "console.log('Hello World!');"
        );

        //======================================================================
        // 模块二：编译器钩子系统
        //======================================================================
        /* 初始化编译器钩子（需在注册前调用） */
        InjectorHook.initCompilationHook("QQ.exe");

        /* 注册JS编译钩子
         * @param tag     触发来源标识
         * @param message 原始JS脚本
         * @return 修改后的JS脚本（示例直接返回原始内容）
         */
        InjectorHook.setJavascriptCompilationHook((tag, message) -> {
            System.out.println("[HOOK][" + tag + "]:\n" + message);
            return message;
        });

        // 保持主线程存活（正式环境建议使用更优雅的线程控制）
        // while (true);

        //======================================================================
        // 模块三：消息监控系统
        //======================================================================
        /* 初始化消息钩子系统 */
        InjectorHook.initMessageHook("QQ.exe");

        /* 注册消息监控回调
         * @param tag     消息类型标识
         * @param message 消息内容
         */
        InjectorHook.setJavascriptMessageHook((tag, message) -> {
            System.out.println("[MSG][" + tag + "]: " + message);
        });

        // 保持主线程存活
        // while (true);

        //======================================================================
        // 模块四：远程调试控制
        //======================================================================
        /* 附加到远程调试会话
         * 启动参数说明：
         * --remote-debugging-port=9222 启用Chrome调试协议
         * --enable-logging=stderr      启用日志输出
         * --no-sandbox                 禁用沙箱（需安全环境）
         */
        Injector.additionalProgram(
                "C:\\Program Files\\Tencent\\QQNT\\QQ.exe " +
                        "--remote-debugging-port=9222 " +
                        "--enable-logging=stderr " +
                        "--no-sandbox"
        );

        /* 在附加的JS上下文中执行代码 */
        Injector.executeJavascript("console.log('Test');");
    }
}