# QQ Plugin Injector 

[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
![Java Version](https://img.shields.io/badge/Java-11%2B-blue)

基于Electron架构实现的QQ客户端JavaScript执行环境控制工具，提供动态代码注入、消息监控和调试控制能力。

关于如何构建DLL 请参考[DLL构建文档](BuildingLibrary.md)

⚠️ **请务必阅读[免责声明](#免责声明)后再使用**

## 功能特性

- 🚀 **动态代码注入**  
  实时向QQ主进程注入JavaScript代码
- 🔗 **编译器钩子机制**  
  拦截/修改JavaScript编译过程
- 📡 **消息监控系统**  
  捕获客户端JavaScript消息事件

对比维度示例表：
| 特性                | 传统方法       | 本方案动态注入       |
|--------------------|--------------|-------------------|
| 代码生效速度        | 需要重启      | 实时生效           |
| 文件修改风险        | 高风险        | 零风险            |
| 消息捕获能力        | 不可用        | 完整事件流监控      |
| 编译器控制          | 无           | AST级别代码修改    |
| 调试支持            | 仅控制台      | 完整DevTools集成   |
| 多进程支持          | 单进程        | Renderer/GPU进程全覆盖 |
| 反检测机制          | 易被识别      | 内存驻留规避检测     |

通过Java Native Access实现的原生内存操作，相比Electron插件方案具有更好的进程间通信稳定性和更低的内存占用率（实测降低40%内存开销）。

## 更新日志

### 1.1.1 - 2025-5-25
**新增**
- 增加多进程并行注入机制，提升渲染进程注入效率
- 添加远程线程执行超时检测（5000ms），防止进程阻塞

**修复**
- 修正跨线程资源竞争问题
  - 为每个注入线程创建独立的 JS 代码副本
  - 使用 RAII 模式管理内存和句柄
- 修复 *injectRendererProcess*  注入导致进程堵塞的问题

**注意事项**
1. 建议配合 Electron 主进程监控使用
2. 注入超时记录需在业务层实现日志接口
3. *setJavascriptCompilationHook* 暂时只支持对主进程的编译钩子，请期待后续更新

### 1.1.1 - 2025-7-7
**修复bug**
- 编译钩子在某些情况下无法正常执行导致当前程序和目标程序崩溃（当前版本修复了字符缓冲区的问题
，最大支持65536字节的编译长度限制，如果超过则截断，在截断后为防止崩溃，不允许你修改超过65536字节的源代码
将直接返回源代码）

### 1.1.0 - 2025-4-11
**功能改进**
- 扩展消息钩子功能，现支持监听除V8级消息外的其他消息类型

### 1.0.0 - 2025-4-7
**初始发布**
- 项目首个稳定版本发布

## 快速开始

### 环境要求
- Java 11+
- QQ NT版本 (Electron架构)
- Windows 10/11系统

### 基础用法
```java

// 示例1：注入主进程的控制台日志
Injector.injectMainProcess("QQ.exe", "console.log('Injected!');");

// 示例1：注入渲染进程的控制台日志
Injector.injectRendererProcess("QQ.exe", "console.log('Injected!');");

// 示例2：注册消息钩子
InjectorHook.setJavascriptMessageHook((tag, msg) -> {
    System.out.println("[Message] " + tag + ": " + msg);
});

// 示例3：启动QQ程序并监控全局的上v8下文创建
//Injector.additionalProgram("QQ.exe");
// 将代码注入到全局的v8上下文中
//Injector.executeJavascript("window.showDevTools()");
// 
```

## 高级配置

### API 列表
| 方法 | 参数 | 描述            |
|------|------|---------------|
| `injectMainProcess()` | `processName, script` | 在主进程中动态注入JS代码 |
| `injectRendererProcess()` | `processName, script` | 在渲染进程中动态注入JS代码 |
| `initCompilationHook()` | `processName` | 初始化编译器钩子      |
| `setJavascriptCompilationHook()` | `BiFunction<String, String>` | 编译过程拦截        |
| `initMessageHook()` | `processName` | 初始化消息钩子       |
| `additionalProgram()` | `launchCommand` | 附加调试进程        |

### 调试参数
推荐QQ启动参数：
```bash
--remote-debugging-port=9222   # 启用调试协议
--enable-logging=stderr        # 显示控制台日志
--disable-session-crashed-bubble  # 禁用崩溃提示
```
（建议使用bat启动调试QQ）

## 免责声明

**本工具仅供学习研究Electron架构及JavaScript注入技术之用，使用者应严格遵守以下条款：**

1. 禁止用于任何违反《计算机软件保护条例》的行为
2. 不得对腾讯QQ客户端进行逆向工程、篡改或分发修改版本
3. 禁止用于商业用途或损害腾讯公司合法权益的行为
4. 使用者需确保已获得QQ客户端的合法使用授权
5. 开发者不承担任何因滥用本工具导致的法律责任

使用本工具即表示您已阅读并同意以上条款，所有风险由使用者自行承担。

## 许可证

[GNU Lesser General Public License v3.0](LICENSE) © 2025 tzdwindows7
