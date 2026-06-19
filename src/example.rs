mod ind_spoof;
use crate::ind_spoof::*;
use zada_xor::techniques::evasion::api_hashing::*;
use zada_xor::techniques::evasion::execution::dinamic_ssn::*;

fn main() {
    let segundos = 60;
    let mut delay_interval: i64 = -(segundos * 10_000_000);

    println!("\n--- Get Dynamic SSN ---");
    let ssn_code = match get_dinamic_ssn(unique_hash("NtDelayExecution")) {
        Ok(ssn) => ssn,
        Err(e) => panic!("Error al obtener el SSN: {}", e),
    };
    println!("SSN: {:#x}", ssn_code);

    println!(
        "Iniciando la congelacion de {} segundos indirecta.",
        segundos
    );

    unsafe {
        let status = indirect_syscall_6(
            //ind syscall with call stack spoof
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
    }
}
