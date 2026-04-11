package com.electron;
public class Main {
    private static final String MAIN_JS = "C:\\\\Users\\\\Administrator\\\\MCreatorWorkspaces\\\\ElectronInjector\\\\src\\\\main\\\\JavaScript\\\\main.js";
    public static void main(String[] args) throws InterruptedException {
        System.load("F:\\source\\repos\\ElectronInjector\\x64\\Release\\ElectronInjector.dll");
        Injector.injectMainProcess(
                "QQ.exe",
                "process.mainModule.require('"
                        + MAIN_JS + "');"
        );
    }
}
