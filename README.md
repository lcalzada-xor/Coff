# Coff - Call Stack Spoof with Indirect Syscall for Rust

[Español](README.md) • [English](README.en.md)

## Yet another Call Stack Spoof implementation? -> Result\<It's different\>

Although the ultimate goal of the implemented technique is the same as implementations like SilentMoonWalk, its architecture is different. The most notable aspect is that it does not use TLS callbacks nor does it exploit the desynchronization of unwinding with the RBP register through the UWOP_SET_FPREG code. 

Instead, it strictly adheres to the Windows x64 ABI, building a contiguous and mathematically perfect synthetic stack that synchronizes to the millimeter with the system's .pdata through a double set of gadgets (ADD RSP + CALL), achieving a clean and undetectable cut of the trace (Unwind) ending in a NULL to stop the unwinding. (So far it hasn't given me any problems testing several functions :) )

<img width="1915" height="973" alt="imagen" src="https://github.com/user-attachments/assets/162b4b70-c7c5-4850-aa8d-f11f6b3b902b" />


## How to use it?
The implementation carried out is oriented to be imported as a dependency, for this it is necessary to put the zada-xor dependency (the library I am developing) in the **Cargo.toml**:

### Cargo.toml
~~~
[dependencies]
zada-xor = { git = "https://github.com/lcalzada-xor/zada-xor" }
~~~

Once the dependency is included, you will have to **import it** in your code as follows:

~~~
use zada_xor::techniques::evasion::execution::indirect_syscall::*;
use zada_xor::techniques::evasion::api_hashing::unique_hash;

~~~

If you are curious and restless, I encourage you to take a look at more implementations of other techniques I have around there ;).

Finally, the function to use is called indirect syscall (it accepts 6 args - for now I haven't needed more - it can be expandable in the future):

### Example

~~~
let status = indirect_syscall_6( // this function implements call stack spoofing
            unique_hash("NtDelayExecution"),
            ssn_code,
            0,
            &mut delay_interval as *mut i64 as usize,
            0,
            0,
            0,
            0,
        );

        match status {
            Ok(0) => println!("bien"),
            Ok(val) => println!("mal, status: 0x{:X}", val),
            Err(err) => println!("Error al ejecutar la syscall: {}", err),
        }
~~~
**Note 1**: If the function you want to call has fewer than 6 arguments, just put 0 where there is no arg.

**Note 2**: To **not** get the **debug** messages, it is recommended to compile with the --release attribute.

> **OPSEC Recommendation:** Before invoking the function, it is recommended to calculate the hash of its name (for example, using `unique_hash("NtDelayExecution")`) and include it as a *hardcoded* constant in the final code:
>
> ```rust
> const HASH_NT_DELAY_EXECUTION: u32 = 0x323423;
> ```
>
> To maintain rigorous OPSEC, avoid including the text string `"NtDelayExecution"` (or the api you are going to use) anywhere in the binary, thus preventing it from being detected through static analysis or tools like `strings`.


## Execution Flow of the implementation (highlighted parts)

1. The injector locates NTDLL and Kernel32, the **SSN (System Service Number) is dynamically extracted** from the target API (by scanning the function loaded in memory).

<img width="805" height="337" alt="imagen" src="https://github.com/user-attachments/assets/b665fbf4-3c82-4510-8c95-f48c0120ed2a" />


2. The memory is scanned again in **search of the necessary Gadgets** - The following have been used: **ADD RSP, \{variable\}; RET** and **CALL RDI/RSI/R15/R12** (any of them).

<img width="984" height="160" alt="imagen" src="https://github.com/user-attachments/assets/aedfbf2c-5d10-4db1-a8f7-7b52d34807b4" />

3. The parser reads the **.pdata** of the **Gadgets** and the base Windows functions (**BaseThreadInitThunk**, **RtlUserThreadStart**), extracting the exact size each one will occupy in memory.

<img width="735" height="195" alt="imagen" src="https://github.com/user-attachments/assets/9f5b67f1-f0d3-4d82-ad22-6bf34c2f591a" />


4. The asm! block hijacks the RSP register, **expands the stack** by subtracting the **calculated bytes that the functions to spoof will occupy**, and places the return addresses of these spoofed functions (in the case of BaseThreadInitThunk, RtlUserThreadStart, the offsets +0x14 and +0x21 are added for **greater opsec**).

<img width="980" height="558" alt="imagen" src="https://github.com/user-attachments/assets/430b4ddc-d643-4e2f-8f3b-655ff2b701b4" />


5. The R10 register and EAX are set for the **Syscall**, and the **jump** towards NTDLL is executed.

<img width="1012" height="148" alt="imagen" src="https://github.com/user-attachments/assets/227c015b-917c-46f6-9bdb-4d4d5b287d3d" />


6. The **Syscall finishes**, lands on **Gadget 1** (which **cleans** the Shadow Space), bounces to **Gadget 2** (which returns execution **control**), and finally the original **RSP is restored**.

<img width="1094" height="240" alt="imagen" src="https://github.com/user-attachments/assets/23cb4456-7f89-45a6-b9cd-bf0e612e6e72" />


## What does the stack look like before the syscall execution?
~~~
Low Addresses 0x0000000000
================================================================================
[RSP + pos4] -> pos4 (0x00): Address of Gadget 1 (ADD RSP, 0x38; RET)
                             (The real NTDLL Syscall does RET and lands here)
[RSP + 0x08] -> Shadow Space 1 (Garbage / RCX)
[RSP + 0x10] -> Shadow Space 2 (Garbage / RDX)
[RSP + 0x18] -> Shadow Space 3 (Garbage / R8)
[RSP + 0x20] -> Shadow Space 4 (Garbage / R9)
[RSP + 0x28] -> ARGUMENT 5 (Survives intact, pushed by Rust before jumping)
[RSP + 0x30] -> ARGUMENT 6
================================================================================
...          -> Gadget 1 executes "ADD RSP, 0x38" (Cleaning the garbage from above).
                Immediately after, it executes "RET", popping the address at RSP + 0x38 -> Address Gadget 2
================================================================================
[RSP + pos3] -> pos3 (pos4 + offset4 + 8): Address of Gadget 2 (CALL RDI / REG)
                             (The flow lands here. Being a "CALL", it dirties
                              8 bytes, but gives us control back to Rust code) -> dirtying 8 bytes doesn't matter because at the end of the spoofed syscall it gets restored
================================================================================
...          -> Space assigned to the frame of Gadget 2 (offset3 extracted from .pdata)
================================================================================
[RSP + pos2] -> pos2 (pos3 + offset3 + 8): BaseThreadInitThunk + 0x14 (Executes nothing inside here, it is just spoofing)
================================================================================
...          -> Space assigned to the frame of BaseThreadInitThunk (offset2)
================================================================================
[RSP + pos1] -> pos1 (pos2 + offset2 + 8): RtlUserThreadStart + 0x21 (Executes nothing inside here, it is just spoofing)
================================================================================
...          -> Space assigned to the frame of RtlUserThreadStart (offset1)
================================================================================
[RSP + null] -> null_ret_offset (pos1 + offset1 + 8): 0x0000000000000000
                (The EDR reads the 0, assumes it is the legitimate origin
                 of the thread and considers its analysis finished and clean).
================================================================================
High Addresses 0xFFFFFFFFFFFF
~~~
## Extra Features

1. Since the implementation originates from code of the lib I am developing [zada-xor](https://github.com/lcalzada-xor/zada-xor), this technique has been implemented with the greatest possible **opsec**, through **dynamic api resolution via hashes** (homemade algorithm) and has **zero additional dependencies** (with the exception of the chacha20 encryption module).
2. It has **dynamic ssn resolution** which means that the ssn codes of the apis are resolved dynamically and are not hardcoded.
3. I'll think of more things to put here, my mind is blank right now xd.

## Note

This repository is a wrapper of the implementation of this same technique in https://github.com/lcalzada-xor/zada-xor/blob/main/src/techniques/evasion/execution/indirect_syscall.rs

## ⚠️ Disclaimer and Ethical Use

> [!IMPORTANT]
> **This project is strictly for educational, academic research, and defensive security purposes.**
> 
> * **Authorized Use:** The code and concepts demonstrated here are intended solely to be used in controlled environments, research laboratories, and systems where there is explicit authorization from the owners.
> * **Defensive Purpose:** It is designed to help security researchers, malware analysts, and EDR/AV solution developers understand how these resolution techniques operate in order to detect and mitigate them effectively.
> * **Prohibition of Malicious Use:** The author does not promote, support, or condone the use of this software for destructive, intrusive, or malicious purposes. Any improper or illegal use of this tool is the sole responsibility of the end user.**
