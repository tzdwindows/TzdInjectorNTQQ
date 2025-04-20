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
     * 主进程JavaScript文件路径
     */
    private static final String MAIN_JS = "\\\\main.js";

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
    public static void main(String[] args) throws InterruptedException {
        InjectorHook.setJavascriptMessageHook((tag, message) -> {
            System.out.print(message);
        });
        Injector.injectMainProcess(
                "QQ.exe",
                "process.mainModule.require('"
                + MAIN_JS + "');"
        );
    }
}
