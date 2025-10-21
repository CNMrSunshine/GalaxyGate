GalaxyGate 是一个结合硬件断点与 VEH（异常处理机制）的创新项目，旨在实现调用堆栈合法且完整的情况下，执行任意系统调用。

[详情请前往 菜叶片的博客](https://cnmrsunshine.github.io/2025/04/04/galaxygate-zi-yan-zhan-qi-pian-idsc-fang-an/)
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


## 该项目当前已与StarFly项目整合 后续更新将推送至[StarFly仓库](https://github.com/cnmrsunshine/starfly)
