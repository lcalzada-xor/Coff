# Coff - Call Stack Spoof with Indirect Syscall for Rust
[![Made with Rust](https://img.shields.io/badge/made_with-Rust-red?logo=rust)](https://www.rust-lang.org/)

[Español](README.es.md) • [English](README.md)

<figure>
  <img width="1916" height="939" alt="Peek 2026-06-23 12-25" src="https://github.com/user-attachments/assets/c973b2b3-4795-4187-bab0-7608e2a38e1c" />
  <figcaption><i>Indirect execution of NtDelayExecution with call stack spoof.</i></figcaption>
</figure>


## Table of Contents

* [Yet another Call Stack Spoof implementation?](#call-stack-spoof)
* [Features](#features)
* [How to use it?](#how-to-use-it)
    * [Cargo.toml](#cargotoml)
    * [Example](#example)
* [Execution Flow of the implementation](#execution-flow-of-the-implementation-highlighted-parts)
* [What does the stack look like before execution?](#what-does-the-stack-look-like-before-the-syscall-execution)
* [Note about the repository](#note)
* [⚠️ Disclaimer](#️-disclaimer-and-ethical-use-disclaimer)
* [Acknowledgements](#acknowledgements)

---

<a name="call-stack-spoof"></a>
## Yet another Call Stack Spoof implementation? -> Result\<New\>

Although the ultimate goal of the implemented technique is the same as other implementations I have researched, such as [SilentMoonWalk](https://github.com/klezVirus/SilentMoonwalk) by [klezVirus](https://github.com/klezVirus) and its children: [Unwinder](https://github.com/Kudaes/Unwinder) by [Kudaes](https://github.com/Kudaes) and [uwd](https://github.com/joaoviictorti/uwd) by [joaoviictorti](https://github.com/joaoviictorti), its architecture is different. The most notable aspect is that it **does not use TLS callbacks** nor does it exploit the unwinding desynchronization with the RBP register via the **UWOP_SET_FPREG** code. 

Instead, it strictly adheres to the Windows x64 ABI, building a contiguous and mathematically perfect synthetic stack that surgically synchronizes with the system's .pdata through a dual use of gadgets (ADD RSP + CALL), achieving a clean and undetectable cut of the trace (Unwind), ending in a NULL to stop the unwinding. (So far it hasn't given me any trouble while testing several functions :) )

## Features

1. Since the origin of this implementation is code from the library I am developing [zada-xor](https://github.com/lcalzada-xor/zada-xor), this technique has been implemented with the highest possible **opsec**.
2. **Dynamic Gadgets**: it has fallbacks in case a specific gadget is not found, trying with another one.
3. Construction of a **synthetic stack** 100% compliant with the **standard structure** expected by the unwinding process.
4. It features **dynamic ssn resolution**, meaning that API SSN codes are resolved dynamically and are not hardcoded.
5. **Dynamic api resolution via hashes** (custom algorithm).
6. **Zero dependencies**, all the code comes from the zada-xor lib.
7. **Manual parsing of unwind codes** implemented from scratch.
8. **Modular** and **clean implementation**, easy to follow.
9. I'll think of more things to put here later, my mind is blank right now xd.

## How to use it?
The current implementation is designed to be **imported as a dependency**. To do this, you need to add the **zada-xor** dependency (the library I am developing) into your **Cargo.toml**:

### Cargo.toml
~~~
[dependencies]
zada-xor = { git = "https://github.com/lcalzada-xor/zada-xor" }
~~~

Once the dependency is included, you will have to **import it** into your code as follows:

~~~
use zada_xor::techniques::evasion::execution::indirect_syscall::*;
use zada_xor::techniques::evasion::api_hashing::unique_hash;

~~~

If you are curious and restless, I encourage you to take a look at other implementations of different techniques I have around there ;).

Finally, the function to use is called indirect syscall (it accepts 6 args - so far I haven't needed more - it can be expanded in the future):

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
            Ok(0) => println!("good"),
            Ok(val) => println!("bad, status: 0x{:X}", val),
            Err(err) => println!("Error executing the syscall: {}", err),
        }
~~~
**Note 1**: If the function you want to call has fewer than 6 arguments, simply pass 0 where there is no arg.

**Note 2**: To **prevent** **debug** messages from appearing, it is recommended to compile with the `--release` flag.

> **OPSEC Recommendation:** Before invoking the function, it is recommended to calculate the hash of its name (for example, using `unique_hash("NtDelayExecution")`) and include it as a *hardcoded* constant in the final code:
>
> ```rust
> const HASH_NT_DELAY_EXECUTION: u32 = 0x323423;
> ```
>
> To maintain rigorous OPSEC, avoid including the string `"NtDelayExecution"` (or whichever API you are going to use) anywhere in the binary, thus preventing it from being detected through static analysis or tools like `strings`.


## Execution Flow of the implementation (highlighted parts)

1. The injector locates NTDLL and Kernel32, dynamically **extracting the SSN** (System Service Number) of the target API (by scanning the function loaded in memory).

<img width="805" height="337" alt="imagen" src="https://github.com/user-attachments/assets/b665fbf4-3c82-4510-8c95-f48c0120ed2a" />


2. Memory is scanned again in **search of the required Gadgets** - The ones used are: **ADD RSP, \{variable\}; RET** and **CALL RDI/RSI/R15/R12** (any of them).

<img width="984" height="160" alt="imagen" src="https://github.com/user-attachments/assets/aedfbf2c-5d10-4db1-a8f7-7b52d34807b4" />

3. The parser reads the **.pdata** of the **Gadgets** and the base Windows functions (**BaseThreadInitThunk**, **RtlUserThreadStart**), extracting the exact size each one will occupy in memory.

<img width="735" height="195" alt="imagen" src="https://github.com/user-attachments/assets/9f5b67f1-f0d3-4d82-ad22-6bf34c2f591a" />


4. The asm! block hijacks the RSP register, **expands the stack** by subtracting the **calculated bytes that the spoofed functions will occupy**, and places the return addresses of these spoofed functions (in the case of BaseThreadInitThunk and RtlUserThreadStart, offsets +0x14 and +0x21 are added for **better opsec**).

<img width="980" height="558" alt="imagen" src="https://github.com/user-attachments/assets/430b4ddc-d643-4e2f-8f3b-655ff2b701b4" />


5. The R10 and EAX registers are set for the **Syscall**, and the **jump** towards NTDLL is executed.

<img width="1012" height="148" alt="imagen" src="https://github.com/user-attachments/assets/227c015b-917c-46f6-9bdb-4d4d5b287d3d" />


6. The **Syscall finishes**, lands on **Gadget 1** (which **cleans** the Shadow Space), bounces to **Gadget 2** (which returns execution **control**), and finally the original **RSP is restored**.

<img width="1094" height="240" alt="imagen" src="https://github.com/user-attachments/assets/23cb4456-7f89-45a6-b9cd-bf0e612e6e72" />


## What does the stack look like before the syscall execution?
~~~
Low Addresses 0x0000000000
================================================================================
[RSP + pos4] -> pos4 (0x00): Gadget 1 Address (ADD RSP, 0x38; RET)
                             (The actual NTDLL Syscall executes RET and lands here)
[RSP + 0x08] -> Shadow Space 1 (Trash / RCX)
[RSP + 0x10] -> Shadow Space 2 (Trash / RDX)
[RSP + 0x18] -> Shadow Space 3 (Trash / R8)
[RSP + 0x20] -> Shadow Space 4 (Trash / R9)
[RSP + 0x28] -> ARGUMENT 5 (Survives intact, pushed by Rust before jumping)
[RSP + 0x30] -> ARGUMENT 6
================================================================================
...          -> Gadget 1 executes "ADD RSP, 0x38" (Cleaning the trash above).
                Immediately after, it executes "RET", popping the address at RSP + 0x38 -> Gadget 2 Dir
================================================================================
[RSP + pos3] -> pos3 (pos4 + offset4 + 8): Gadget 2 Address (CALL RDI / REG)
                             (The flow lands here. Being a "CALL", it dirties
                              8 bytes, but returns control to the Rust code) -> dirtying 8 bytes doesn't matter because it gets restored at the end of the spoofed syscall
================================================================================
...          -> Space assigned to Gadget 2 frame (offset3 extracted from .pdata)
================================================================================
[RSP + pos2] -> pos2 (pos3 + offset3 + 8): BaseThreadInitThunk + 0x14 (Executes nothing inside here, just for spoofing)
================================================================================
...          -> Space assigned to BaseThreadInitThunk frame (offset2)
================================================================================
[RSP + pos1] -> pos1 (pos2 + offset2 + 8): RtlUserThreadStart + 0x21 (Executes nothing inside here, just for spoofing)
================================================================================
...          -> Space assigned to RtlUserThreadStart frame (offset1)
================================================================================
[RSP + null] -> null_ret_offset (pos1 + offset1 + 8): 0x0000000000000000
                (The EDR reads 0, assumes it is the legitimate 
                 origin of the thread, and considers its analysis finished and clean).
================================================================================
High addresses 0xFFFFFFFFFFFF
~~~

## Note

This repository is a wrapper of the implementation of this same technique at https://github.com/lcalzada-xor/zada-xor/blob/main/src/techniques/evasion/execution/indirect_syscall.rs

## ⚠️ Disclaimer and Ethical Use (Disclaimer)

> [!IMPORTANT]
> **This project is intended strictly for educational purposes, academic research, and defensive security.**
> 
> * **Authorized Use:** The code and concepts demonstrated here are only meant to be used in controlled environments, research laboratories, and systems where explicit authorization from the owners has been granted.
> * **Defensive Purpose:** It is designed to help security researchers, malware analysts, and EDR/AV solution developers understand how these resolution techniques operate in order to detect and mitigate them effectively.
> * **Prohibition of Malicious Use:** The author does not promote, support, or condone the use of this software for destructive, intrusive, or malicious purposes. Any improper or illegal use of this tool is the sole responsibility of the end user.

## Acknowledgements

This project would not have been possible without the previous work of great researchers in the community. I want to especially thank:

* **[klezVirus](https://github.com/klezVirus)**: For laying the conceptual foundations with his spectacular work on **[SilentMoonWalk](https://github.com/klezVirus/SilentMoonwalk)**, which served as the primary documentation and theoretical inspiration for this repository.
* **[Kudaes](https://github.com/Kudaes)** (Javier): For his project **[Unwinder](https://github.com/Kudaes/Unwinder)**. His tireless contribution to the Spanish-speaking malware development community and his extremely high-level technical content and talks have been the spark and key motivation to jump into developing and publishing this repository in Rust.
* **[joaoviictorti](https://github.com/joaoviictorti)**: For his implementation **[uwd](https://github.com/joaoviictorti/uwd)**, which served as an excellent reference point to develop the lib.

Thank you for openly sharing knowledge and improving the level of security research!
