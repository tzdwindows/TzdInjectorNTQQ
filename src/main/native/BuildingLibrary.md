# 如何构建 **ElectronInjector** 链接库

## 环境准备
1. 安装 **Visual Studio 2022**
   - 在安装时选择：
     - "使用C++的桌面开发" 工作负载
     - Windows SDK（推荐最新版本）
     - C++ MFC 用于最新 v143 生成工具（可选）

## 一、准备所需库文件

### 1. Detours 库
- 获取方式：
  ```bash
  git clone https://github.com/microsoft/Detours.git
  ```

### 2. rusty_v8 库
- 获取方式：
    - 预编译二进制（推荐）：
      ```bash
      git clone https://github.com/denoland/rusty_v8
      ```
    - 或从 [rusty_v8 发布页](https://github.com/denoland/rusty_v8) 下载自行构建

- 关键文件：
    - `include` 目录：所有 V8 头文件
    - `release` 目录：`v8_monolith.lib`，`v8.dll` 等

### 3. Corretto JDK (include 部分)
- 下载 [Amazon Corretto 20.0.2.1](https://docs.aws.amazon.com/corretto/latest/corretto-20-ug/downloads-list.html)
- 关键目录：
    - `include`：JDK 原生接口头文件
    - `include\win32`：Windows 平台特定头文件

这份指南提供了从环境准备到最终配置的完整流程，包含了具体路径设置和常见问题解决方案，可帮助开发者顺利构建 ElectronInjector 链接库。