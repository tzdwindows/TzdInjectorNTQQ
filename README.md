# QQ Plugin Injector

[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)  
![Java Version](https://img.shields.io/badge/Java-11%2B-blue)

A JavaScript execution environment control tool for QQ clients based on the Electron architecture, providing dynamic code injection, message monitoring, and debugging control capabilities.
一个可以动态植入QQ客户端的JavaScript执行环境控制的工具
[中文](https://github.com/tzdwindows/TzdInjectorNTQQ/blob/main/README_ZH.md) [English](https://github.com/tzdwindows/TzdInjectorNTQQ/blob/main/README.md)

See how c++ modules are built [BuildingLibrary.md](https://github.com/tzdwindows/TzdInjectorNTQQ/blob/main/src/main/native/BuildingLibrary.md)

⚠️ **Please read the [Disclaimer](#disclaimer) carefully before use**

## Features

- 🚀 **Dynamic Code Injection**  
  Inject JavaScript code into the QQ main process in real time
- 🔗 **Compiler Hook Mechanism**  
  Intercept/modify the JavaScript compilation process
- 📡 **Message Monitoring System**  
  Capture JavaScript message events from the client

Comparison table example:  
| Feature               | Traditional Method | Dynamic Injection (This Solution) |  
|----------------------|-------------------|----------------------------------|  
| Code Activation Speed | Requires restart  | Real-time生效                    |  
| File Modification Risk | High risk         | Zero risk                        |  
| Message Capture Capability | Unavailable      | Full event stream monitoring     |  
| Compiler Control      | None              | AST-level code modification      |  
| Debugging Support     | Console only      | Full DevTools integration        |  
| Multi-process Support | Single process    | Renderer/GPU process全覆盖       |  
| Anti-detection Mechanism | Easily detected | Memory-resident evasion          |

Native memory operations implemented via Java Native Access offer better inter-process communication stability and lower memory usage (40% reduction in testing) compared to Electron plugin solutions.

## Changelog

### 1.1.2 - 2025-7-7
**Fixes**
- When the compiler hook data transmitted to the Java layer exceeds 65536 bytes, it is automatically truncated and sent to the Java side first, then the original data is returned. The Java side cannot modify source code exceeding 65536 bytes. Blank returns automatically revert to the original data. The modification is located in the *CallbackJavaLayer_Return* function in *[ElectronInjector\ElectronInjector\v8_printer_hook.h](https://github.com/tzdwindows/TzdInjectorNTQQ/blob/main/src/main/native/ElectronInjector/v8_printer_hook.h)*.

### 1.1.1 - 2025-5-25
**Additions**
- Added multi-process parallel injection mechanism to improve renderer process injection efficiency
- Added remote thread execution timeout detection (5000ms) to prevent process blocking

**Fixes**
- Fixed cross-thread resource competition issues
  - Created independent JS code copies for each injection thread
  - Used RAII pattern for memory and handle management
- Fixed *injectRendererProcess* causing process blockage

**Notes**
1. Recommended for use with Electron main process monitoring
2. Injection timeout logging requires business-layer log interface implementation
3. *setJavascriptCompilationHook* currently only supports compilation hooks for the main process. Stay tuned for updates.

### 1.1.0 - 2025-4-11
**Improvements**
- Expanded message hook functionality to support monitoring non-V8-level messages

### 1.0.0 - 2025-4-7
**Initial Release**
- First stable version of the project

## Technical Comparison: Dynamic Injection vs. Traditional Methods

### Limitations of Traditional Injection
- ⏳ **Static Modification**  
  Requires direct JS file changes, triggering client signature verification
- 🔄 **Restart Dependency**  
  Modifications require QQ client restart
- 📶 **One-way Communication**  
  Only sends commands, no real-time feedback
- 🚫 **Limited Functionality**  
  Lacks message monitoring and compilation interception
- ⚠️ **High Detection Risk**  
  Easily flagged as suspicious by security mechanisms

### Core Advantages of This Solution
- ⚡ **Real-time Hot Updates**  
  Dynamic injection requires no client restart
- 🛡 **Bypasses Verification**  
  Memory-level injection leaves original files untouched
- 🔄 **Two-way Interaction**  
  Supports JS environment event callbacks
- 🧩 **Modular Expansion**  
  Deep customization via compiler hooks
- 🕵️ **Stealth Operations**  
  Injection fully resides in memory
- 🌐 **Version Adaptability**  
  Compatible with QQ NT architecture across versions
- 🔧 **Integrated Debugging**  
  Native Chrome debugging protocol support

Comparison table example:  
| Feature               | Traditional Method | Dynamic Injection (This Solution) |  
|----------------------|-------------------|----------------------------------|  
| Code Activation Speed | Requires restart  | Real-time生效                    |  
| File Modification Risk | High risk         | Zero risk                        |  
| Message Capture Capability | Unavailable      | Full event stream monitoring     |  
| Compiler Control      | None              | AST-level code modification      |  
| Debugging Support     | Console only      | Full DevTools integration        |  
| Multi-process Support | Single process    | Renderer/GPU process全覆盖       |  
| Anti-detection Mechanism | Easily detected | Memory-resident evasion          |

Native memory operations via Java Native Access offer better IPC stability and lower memory usage (40% reduction in testing) compared to Electron plugins.

## Quick Start

### Requirements
- Java 11+
- QQ NT version (Electron architecture)
- Windows 10/11

### Basic Usage
```java  
// Example 1: Inject console log into main process  
Injector.injectMainProcess("QQ.exe", "console.log('Injected!');");  

// Example 1: Inject console log into renderer process  
Injector.injectRendererProcess("QQ.exe", "console.log('Injected!');");  

// Example 2: Register message hook  
InjectorHook.setJavascriptMessageHook((tag, msg) -> {  
    System.out.println("[Message] " + tag + ": " + msg);  
});  

// Example 3: Launch QQ and monitor global V8 context creation  
//Injector.additionalProgram("QQ.exe");  
// Inject code into global V8 context  
//Injector.executeJavascript("window.showDevTools()");  
```  

## Advanced Configuration

### Java API List
| Method | Parameters | Description |  
|--------|------------|-------------|  
| `injectMainProcess()` | `processName, script` | Dynamically inject JS into main process |  
| `injectRendererProcess()` | `processName, script` | Dynamically inject JS into renderer process |  
| `initCompilationHook()` | `processName` | Initialize compiler hook |  
| `setJavascriptCompilationHook()` | `BiFunction<String, String>` | Intercept compilation process |  
| `initMessageHook()` | `processName` | Initialize message hook |  
| `additionalProgram()` | `launchCommand` | Attach debug process |  

### Javascript API List
| Method | Parameters | Description |  
|--------|------------|-------------|  
| `global.windowManager.requestInjection()` | `window,path` | Inject JS script into specified window's renderer thread |  

### Javascript Events List
| Event Name | Declaration | Description |  
|------------|-------------|-------------|  
| `onLogin` | `exports.onLogin = (uid) => {console.log(`User ${uid} logged in`)}` | Executed on user login (deprecated, no longer maintained) |  
| `onBrowserWindowCreated` | `exports.onBrowserWindowCreated = (window) => {console.log('[Electron] Window created')}` | Executed on window creation |  

### Debug Parameters
Recommended QQ launch parameters:
```bash  
--remote-debugging-port=9222   # Enable debug protocol  
--enable-logging=stderr        # Show console logs  
--disable-session-crashed-bubble  # Disable crash prompts  
```  
(Recommended to use a .bat file to launch QQ for debugging)

## Disclaimer

**This tool is for educational and research purposes only regarding Electron architecture and JavaScript injection technology. Users must strictly adhere to the following terms:**

1. Prohibited for any violation of the "Computer Software Protection Regulations"
2. No reverse engineering, modification, or distribution of modified versions of the Tencent QQ client
3. Prohibited for commercial use or actions harming Tencent's legal rights
4. Users must ensure proper authorization for QQ client usage
5. Developers assume no liability for misuse of this tool

Use of this tool signifies acceptance of these terms. All risks are borne by the user.

## License

[GNU Lesser General Public License v3.0](LICENSE) © 2025 tzdwindows7