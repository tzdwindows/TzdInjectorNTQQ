# QQ Plugin Injector 

[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
![Java Version](https://img.shields.io/badge/Java-11%2B-blue)

基于Electron架构实现的QQ客户端JavaScript执行环境控制工具，提供动态代码注入、消息监控和调试控制能力。

⚠️ **请务必阅读[免责声明](#免责声明)后再使用**

## 功能特性

- 🚀 **动态代码注入**  
  实时向QQ主进程注入JavaScript代码
- 🔗 **编译器钩子机制**  
  拦截/修改JavaScript编译过程
- 📡 **消息监控系统**  
  捕获客户端JavaScript消息事件

## 技术对比：动态注入 vs 传统方法

### 传统注入方式局限性
- ⏳ **静态修改**  
  需要直接修改JS文件，触发客户端签名校验
- 🔄 **重启依赖**  
  每次修改必须重启QQ客户端生效
- 📶 **单向通信**  
  只能发送指令，无法获取实时反馈
- 🚫 **功能单一**  
  缺乏消息监控和编译拦截能力
- ⚠️ **高检测风险**  
  易被安全机制识别为异常行为

### 本方案核心优势
- ⚡ **实时热更新**  
  动态注入无需重启客户端进程
- 🛡 **规避校验机制**  
  内存级注入不修改原始文件
- 🔄 **双向交互通道**  
  支持接收JS环境事件回调
- 🧩 **模块化扩展**  
  通过编译器钩子实现深度定制
- 🕵️ **隐蔽式操作**  
  注入过程完全驻留内存
- 🌐 **版本自适应**  
  兼容QQ NT各版本架构

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

## 快速开始

### 环境要求
- Java 11+
- QQ NT版本 (Electron架构)
- Windows 10/11系统

### 基础用法
```java
// 初始化注入器
Injector.init();

// 示例1：注入控制台日志
Injector.inject("QQ.exe", "console.log('Injected!');");

// 示例2：注册消息钩子
InjectorHook.setJavascriptMessageHook((tag, msg) -> {
    System.out.println("[Message] " + tag + ": " + msg);
});

// 示例3：启动调试会话
Injector.additionalProgram("QQ.exe --remote-debugging-port=9222");
Injector.executeJavascript("window.showDevTools()");
```

## 高级配置

### API 列表
| 方法 | 参数 | 描述 |
|------|------|------|
| `inject()` | `processName, script` | 动态注入JS代码 |
| `initCompilationHook()` | `processName` | 初始化编译器钩子 |
| `setJavascriptCompilationHook()` | `BiFunction<String, String>` | 编译过程拦截 |
| `initMessageHook()` | `processName` | 初始化消息钩子 |
| `additionalProgram()` | `launchCommand` | 附加调试进程 |

### 调试参数
推荐QQ启动参数：
```bash
--remote-debugging-port=9222   # 启用调试协议
--enable-logging=stderr        # 显示控制台日志
--disable-session-crashed-bubble  # 禁用崩溃提示
```

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
