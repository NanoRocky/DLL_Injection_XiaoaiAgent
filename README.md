# WARNING: 100% VIBE CODING FOR ENTIRE REPO

# DLL Injector —— 小爱同学、小米AI创作 & 小米电脑管家注入器

一个轻量级的 Windows DLL 注入工具，用于将 `msimg32.dll` 注入到 **PC 版小爱同学**、**小米AI创作 PC 版** 和 **小米电脑管家** 进程中。采用经典的 `CreateProcess` + `CreateRemoteThread` + `LoadLibrary` 注入技术实现。

> 本项目仅供学习和研究参考，请勿用于非法用途。

## 功能特点

- **三目标支持** — 分别为小爱同学、小米AI创作和小米电脑管家生成独立注入器
- **注册表路径自动发现** — 从 Windows 注册表 (`App Paths`) 自动定位目标程序安装位置
- **极简代码** — 核心注入逻辑全部封装在单个头文件中，易于理解和修改
- **静态链接** — 生成的独立可执行文件无运行时依赖
- **嵌入元数据** — 通过 Windows 资源文件嵌入版本信息与自定义图标
- **无需管理员权限** — 用户权限即可运行（适用于当前用户安装的程序）

## 两种注入模式

注入器现在是**多模式**的，同一个 EXE 支持以下几种用法：

### 模式一：直接启动（经典 Launcher，向后兼容）

双击运行、或无参数运行，行为与旧版一致：

1. 从注册表 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\<程序名>.exe` 读取安装路径
2. 以**挂起状态** (`CREATE_SUSPENDED`) 启动目标进程
3. `VirtualAllocEx` → `WriteProcessMemory` 写入 DLL 路径
4. `CreateRemoteThread` 调用 `LoadLibraryW` 加载 DLL
5. 恢复目标主线程执行

**局限**：只覆盖“由注入器亲自启动”的这一次。如果目标程序由开始菜单、桌面快捷方式、更新器或程序自身重新拉起，就会绕开注入。

### 模式二：IFEO 全局注入（推荐）

利用 Windows 的 **Image File Execution Options (IFEO) Debugger** 机制，把注入器登记为目标 EXE 的“调试器”。此后**无论谁、以何种方式启动目标程序**，Windows 都会先启动注入器：

1. 注入器以 `DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED` 创建真正的目标进程（`DEBUG` 标志**绕过 IFEO 重定向**避免无限递归，`CREATE_SUSPENDED` 保证在目标解析动态依赖前抢先注入；二者均**无需管理员权限**即可启动目标）
2. 干净地脱离调试关系后，用经典远程线程方式注入 `msimg32.dll`
3. 恢复目标主线程，进程照常自由运行

**批量覆盖整个安装目录**：`--install` 会从 `App Paths` 读取安装目录，**递归枚举其下所有 `.exe`**，为每一个用 IFEO 的 `UseFilter` + `FilterFullPath` 机制登记**精确完整路径**的规则。这样：

- 覆盖目标程序自我重启、更新器、启动器桩等**任意 EXE 启动路径**；
- 用完整路径精确匹配，**不会误伤系统里其它同名 EXE**（如 `update.exe`）；
- 安装时把已登记路径记录到 `HKLM\SOFTWARE\XiaomiInjector\<主程序名>`，`--uninstall` 据此**精确回滚全部规则**。

> **注意（重要）**：如果目标是 Electron/Chromium 套壳，目录里的 GPU/渲染器/工具子进程一旦被 IFEO 接管，可能因丢失父进程的句柄继承/沙箱令牌而**崩溃或导致整个程序打不开**。若安装后程序异常，先 `--uninstall` 一键还原，再按需缩小注入范围。

命令：

```powershell
# 安装全局注入（会弹出 UAC 请求管理员权限，写入 HKLM IFEO）
.\XiaoaiAgentInjector.exe --install

# 查看当前状态（是否已安装、Debugger 指向、DLL 是否就位）
.\XiaoaiAgentInjector.exe --status

# 卸载全局注入
.\XiaoaiAgentInjector.exe --uninstall
```

**内建保护措施**：
- 注入失败也**一定会让目标程序照常启动**，绝不会把你锁在程序外
- 递归护栏：万一 `DEBUG` 绕过在某些系统上失效，会弹窗中止而非产生进程风暴
- 位数校验：64 位注入器不会向 32 位目标注入（会跳过注入、仅启动程序）

> **注意**：IFEO 按 EXE **文件名**匹配，不区分目录；安装/卸载需要管理员权限；安全软件会重点监控 IFEO Debugger。请仅在授权的兼容/测试场景使用。目标若为 32 位进程，需要用 32 位工具链另行编译注入器。

`msimg32.dll` 必须放置在注入器可执行文件的**同级目录**下。本仓库不包含该 DLL 文件。

## 项目结构

```
.
├── src/
│   ├── XiaoaiAgentInjector.cpp      # 小爱同学注入器入口
│   ├── XiaomiAICreatorInjector.cpp  # 小米AI创作注入器入口
│   └── XiaomiPcManagerInjector.cpp  # 小米电脑管家注入器入口
├── include/
│   └── InjectorCore.h               # 核心注入逻辑（头文件）
├── resources/
│   ├── XiaoaiAgent.ico              # 小爱同学主程序图标
│   ├── XiaoaiAgent.rc               # 小爱同学资源脚本（含版本信息）
│   ├── XiaomiAICreatorClient.ico    # 小米AI创作主程序图标
│   ├── XiaomiAICreatorClient.rc     # 小米AI创作资源脚本（含版本信息）
│   ├── XiaomiPcManager.ico          # 小米电脑管家主程序图标
│   └── XiaomiPcManager.rc           # 小米电脑管家资源脚本（含版本信息）
├── build.ps1                        # PowerShell 编译脚本
├── LICENSE                          # MIT 许可证
└── README.md                        # 说明文档
```

## 编译方法

### 环境要求

- **MinGW-w64**（含 `g++` 和 `windres`）— 通过 [MSYS2](https://www.msys2.org/) 或其他 MinGW-w64 工具链安装
- **Windows SDK** — MinGW-w64 已自带所需头文件
- **msimg32.dll** — 请向 DLL 作者 ChsBuffer 获取，并放置于注入器同级目录

### 编译步骤

打开 PowerShell 终端并运行：

```powershell
.\build.ps1
```

编译完成后会生成三个可执行文件：
- `XiaoaiAgentInjector.exe` — 小爱同学注入器
- `XiaomiAICreatorInjector.exe` — 小米AI创作注入器
- `XiaomiPcManagerInjector.exe` — 小米电脑管家注入器

### 编译选项说明

- `-static -static-libgcc -static-libstdc++` — 静态链接运行时库，生成独立可执行文件
- `-mwindows` — Windows 子系统（默认不显示控制台窗口）
- `-luser32` — 链接 `user32` 库以支持消息弹窗
- `-finput-charset=UTF-8 -fexec-charset=GBK` — 源代码 UTF-8 编码，生成 GBK 编码的可执行文件（确保中文正常显示）

## 使用方法

1. 将 `msimg32.dll` 放入注入器可执行文件的同级目录
2. 直接运行注入器，目标程序将自动启动并完成 DLL 注入
3. 如果缺少 `msimg32.dll`，注入器会弹出错误提示

> **注意：** 目标程序必须已安装，注册表路径才存在。如果小爱同学是当前用户安装的，请以相同用户身份运行注入器。

## 许可证

本项目基于 MIT 许可证发布。详见 [LICENSE](LICENSE) 文件。
