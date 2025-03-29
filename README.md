GalaxyGate 是一个结合硬件断点与 VEH（异常处理机制）的创新项目，旨在实现调用堆栈合法且完整的情况下，执行任意系统调用。

## 工作原理

GalaxyGate 通过以下步骤实现其功能：

1. **参数传递**：利用全局变量 `SFParams` 向 VEH 传递真实的调用参数，包括 `Syswhisper3` 函数哈希值和参数数量。
2. **触发异常**：制造内存访问冲突，使执行流进入 VEH，从而在无需调用额外 Windows API（如 `SetThreadContext`）的情况下修改调试寄存器。
3. **系统调用解析**：项目引用了经过修改的 `Syswhisper3`，用于解析系统调用地址和系统调用号。
4. **高层傀儡函数调用**：通过调用高层傀儡函数，间接触发目标 `Nt*` 函数的 `Syscall` 指令码位置，从而激活硬件断点。
5. **VEH 参数填充**：执行流进入 VEH 后，根据 Fastcall 调用约定填充真实调用参数。
6. **清理调试寄存器**：在操作完成后清除调试寄存器，避免内核态检测到异常。
7. **伪装合法性**：由于高层函数自带错误处理机制，真实调用完成后，高层傀儡函数能够正常返回，进一步触发更多 EDR Hook，增强调用的合法性。

## 项目模式

GalaxyGate 提供两种操作模式：

- **NextGen 模式**：通过 Ghidra 反编译，定位间接调用目标底层函数的高层傀儡函数进行操作。
- **Legacy 模式**：调用高层傀儡函数 `GetFileAttributesW`，拦截其下游函数 `NtQueryAttributesFile`，并通过修改系统调用号完成操作。

## 灵感来源

GalaxyGate 的灵感来源于 `SilentMoonWalk` 调用堆栈欺骗项目。与其使用伪造的调用堆栈以假乱真，GalaxyGate 选择直接利用真实的函数调用堆栈，从而提升隐蔽性和自然性。


## 与类似项目比较

在首个版本发布两个月后，在 `Github` 发现一个类似项目（Grok3找到的）：[LayeredSyscall](https://github.com/WKL-Sec/LayeredSyscall)。

### 与 LayeredSyscall 的比较

| 特性                  | GalaxyGate                         | LayeredSyscall                     |
|----------------------|------------------------------------|------------------------------------|
| **傀儡函数**          | 可选择多种高层函数 | 固定为 `MessageBoxW`               |
| **拦截方式**          | 拦截 `Syscall` 指令码              | 拦截 `Syscall` `ret` 指令码                  |
| **副作用**            | 无明显副作用                       | 未拦截 `ret` 会导致消息框弹出             |
| **调试寄存器清理**    | 在系统调用前清零，避免内核态检测           | 未在系统调用前清零，可能留下痕迹               |
| **调用堆栈自然性**    | 高度自然，符合函数调用逻辑         | 不自然，`Nt*` 函数与 `MessageBoxW` 无直接关联 |
| **Syswhisper3 优化**  | 优化不足，`SYSCALL_LIST` 留存内存可能被扫描 | 使用其他项目                 |

## 不足与改进方向

GalaxyGate 当前使用的 `Syswhisper3` 需更多优化，`SYSCALL_LIST` 留存在内存中可能被安全软件扫描检测，未来可进一步修改以提升隐蔽性。

## 示例代码

以下是部分核心代码片段，展示了 GalaxyGate 的实现逻辑：

```c
typedef struct _SFParams {
    DWORD ParamNum;         // 参数数量
    BOOL IsLegacy;          // 是否为 Legacy 模式
    DWORD FuncHash;         // 函数哈希值
    DWORD_PTR param[17];    // 调用参数
} SFParams, *PSFParams;

SFParams Params = { 0 }; // 全局变量，用于向 VEH 传递参数
DWORD* NullPointer = NULL;

LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS pExceptInfo) {
    if (pExceptInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // 按照 Fastcall 调用协定 重设参数
        pExceptInfo->ContextRecord->Rcx = Params.param[1];
        pExceptInfo->ContextRecord->Rdx = Params.param[2];
        pExceptInfo->ContextRecord->R8 = Params.param[3];
        pExceptInfo->ContextRecord->R9 = Params.param[4];
        pExceptInfo->ContextRecord->R10 = Params.param[1];
        if (Params.ParamNum > 4) {
            DWORD64* stack = (DWORD64*)(pExceptInfo->ContextRecord->Rsp + 40); // 保留影子空间
            for (int i = 5; i <= Params.ParamNum; ++i) {
                stack[i - 5] = (DWORD64)(Params.param[i]); // 堆栈传递额外参数
            }
        }
        if (Params.IsLegacy) {
            pExceptInfo->ContextRecord->Rax = SW3_GetSyscallNumber(Params.FuncHash);
        }
        // 清除调试寄存器
        pExceptInfo->ContextRecord->Dr0 = 0;
        pExceptInfo->ContextRecord->Dr7 = 0;
        memset(&Params, 0, sizeof(Params));
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if (pExceptInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        // 设置硬件断点
        if (Params.IsLegacy) {
            pExceptInfo->ContextRecord->Dr0 = (DWORD_PTR)SW3_GetSyscallAddress(0x022B80BFE);
        } else {
            pExceptInfo->ContextRecord->Dr0 = (DWORD_PTR)SW3_GetSyscallAddress(Params.FuncHash);
        }
        pExceptInfo->ContextRecord->Dr7 = 0x00000303;
        pExceptInfo->ContextRecord->Rip += 6;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

NTSTATUS SFNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, 
                        PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, 
                        ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    // 设置参数
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    // ... 其他参数赋值
    Params.ParamNum = 11;
    Params.FuncHash = 0x0BDDB5F9C;
    Params.IsLegacy = 0;
    *NullPointer = 1; // 触发异常
    TCHAR tempFileName[MAX_PATH];
    GetTempFileName(0, 0, 0, tempFileName); // GetTempFileName -> NtCreateFile
    return 0;
}
