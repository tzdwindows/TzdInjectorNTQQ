# How to Build the **ElectronInjector** Link Library

## Environment Preparation
1. Install **Visual Studio 2022**
    - During installation, select:
        - "Desktop development with C++" workload
        - Windows SDK (recommended: latest version)
        - C++ MFC for latest v143 build tools (optional)

## I. Prepare Required Library Files

### 1. Detours Library
- How to obtain:
  ```bash  
  git clone https://github.com/microsoft/Detours.git  
  ```  

### 2. rusty_v8 Library
- How to obtain:
    - Precompiled binaries (recommended):
      ```bash  
      git clone https://github.com/denoland/rusty_v8  
      ```  
    - Or download and build from [rusty_v8 release page](https://github.com/denoland/rusty_v8)

- Key files:
    - `include` directory: All V8 header files
    - `release` directory: `v8_monolith.lib`, `v8.dll`, etc.

### 3. Corretto JDK (include section)
- Download [Amazon Corretto 20.0.2.1](https://docs.aws.amazon.com/corretto/latest/corretto-20-ug/downloads-list.html)
- Key directories:
    - `include`: JDK native interface header files
    - `include\win32`: Windows platform-specific header files

This guide provides a complete workflow from environment setup to final configuration, including specific path settings and solutions to common issues, helping developers successfully build the ElectronInjector link library.