# Coff - Call Stack Spoof with Indirect Syscall for Rust

[Español](README.es.md) • [English](README.md)

## ¿Otra implementación mas de Call Stack Spoof? -> Result\<New\>

La técnica implementada si bien su objetivo final es el mismo que implementaciones como SilentMoonWalk, su arquitectura es diferente, lo mas destacable es que no utiliza TLS callbacks ni explota la desincronizacion del unwinding con el registro RBP a través del código UWOP_SET_FPREG. 

En su lugar, se ciñe estrictamente al ABI de Windows x64, construyendo una pila sintética contigua y matemáticamente perfecta que se sincroniza al milímetro con el .pdata del sistema mediante un doble juego de gadgets (ADD RSP + CALL), logrando un corte limpio e indetectable de la traza (Unwind) finalizando en un NULL para detener el unwinding. (De momento no me ha dado problemas probando varias funciones :) )

<figure>
  <img width="1916" height="939" alt="Peek 2026-06-23 12-25" src="https://github.com/user-attachments/assets/c973b2b3-4795-4187-bab0-7608e2a38e1c" />
  <figcaption><i>Ejecución indirecta de NtDelayExecution con call stack spoof.</i></figcaption>
</figure>

## Caracteristicas

1. Dado que la implementacion tiene como origen codigo de la lib que estoy desarrollando [zada-xor](https://github.com/lcalzada-xor/zada-xor), se ha implementado esta técnica con el mayor **opsec** posible.
2. **Gadgets Dinamicos**: tiene fallbacks en caso de que x gadget no se encuentre, se intenta con otro.
3. Construccion de **pila sintetica** 100% acorde a la **estructura estandar** esperada por el unwinding.
4. Tiene **dynamic ssn resolution** lo que significa que los codigos ssn de las apis se resuelven dinámicamente, no estan hardcodeados.
5. **Dynamic api resolution via hashes** (algoritmo casero).
6. **Zero dependencias**, todo el codigo viene de la lib zada-xor.
7. **Parseo de codigos unwind** implementado manualmente.
8. **Modular** y **implementacion limpia**, facil de seguir.
9. Ya se me ocurriran mas cosas que poner aqui, ahora tengo la mente en blanco xd.

## ¿Como usarlo?
La implementacion realizada esta orientada a ser **importada como una dependencia**, para ello es necesario meter en el **Cargo.toml** la dependencia de **zada-xor** (la libreria que estoy desarrollando):

### Cargo.toml
~~~
[dependencies]
zada-xor = { git = "https://github.com/lcalzada-xor/zada-xor" }
~~~

Una vez incluida la dependencia, habrá que **importarla** de la siguiente forma en tu código:

~~~
use zada_xor::techniques::evasion::execution::indirect_syscall::*;
use zada_xor::techniques::evasion::api_hashing::unique_hash;

~~~

Si sois curiosos e inquietos, os animo a hecharle un vistazo a mas implementaciones de otras tecnicas que tengo por ahi ;).

Finalmente la funcion a utilizar se llama indirect syscall (acepta 6 args - de momento no he necesitado mas - puede ser expandible en un futuro):

### Ejemplo

~~~
let status = indirect_syscall_6( // esta funcion implementa call stack spoofing
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
**Nota 1**: Si tu funcion que quieres llamar tiene menos argumentos que 6, basta con meter 0 en donde no haya arg.

**Nota 2**: Para que **no** salgan los mensajes de **debug** se recomienda compilar con el atributo --release.

> **Recomendación de OPSEC:** Antes de invocar la función, se recomienda calcular el hash de su nombre (por ejemplo, mediante `unique_hash("NtDelayExecution")`) e incluirlo como una constante *hardcodeada* en el código final:
>
> ```rust
> const HASH_NT_DELAY_EXECUTION: u32 = 0x323423;
> ```
>
> Para mantener un OPSEC riguroso, evite incluir la cadena de texto `"NtDelayExecution"` (o la api que vayas a utilizar) en cualquier parte del binario, impidiendo así que sea detectada mediante análisis estático o herramientas como `strings`.


## Flujo de Ejecución de la implementación (partes destacadas)

1. El inyector localiza NTDLL y Kernel32, se **extrae dinámicamente el SSN** (System Service Number) de la API objetivo (mediante escaneo de la funcion cargada en memoria).

<img width="805" height="337" alt="imagen" src="https://github.com/user-attachments/assets/b665fbf4-3c82-4510-8c95-f48c0120ed2a" />


2. Se escanea la memoria de nuevo en **busca de los Gadgets** necesarios - Se han utilizado: **ADD RSP, \{variable\}; RET** y **CALL RDI/RSI/R15/R12** (cualquiera de ellos).

<img width="984" height="160" alt="imagen" src="https://github.com/user-attachments/assets/aedfbf2c-5d10-4db1-a8f7-7b52d34807b4" />

3. El parser lee el **.pdata** de los **Gadgets** y de las funciones base de Windows (**BaseThreadInitThunk**, **RtlUserThreadStart**), extrayendo el tamaño exacto que ocupará cada uno en la memoria.

<img width="735" height="195" alt="imagen" src="https://github.com/user-attachments/assets/9f5b67f1-f0d3-4d82-ad22-6bf34c2f591a" />


4. El bloque asm! secuestra el registro RSP, **expande la pila** restando los **bytes calculados que ocuparan las funciones a spoofear** y coloca las direcciones de retorno de estas funciones spoofeadas (en el caso de BaseThreadInitThunk, RtlUserThreadStart se les suma los offsets +0x14 y +0x21 para **mayor opsec**).

<img width="980" height="558" alt="imagen" src="https://github.com/user-attachments/assets/430b4ddc-d643-4e2f-8f3b-655ff2b701b4" />


5. Se establece el registro R10 y el EAX para la **Syscall**, y se ejecuta el **salto** hacia NTDLL.

<img width="1012" height="148" alt="imagen" src="https://github.com/user-attachments/assets/227c015b-917c-46f6-9bdb-4d4d5b287d3d" />


6. La **Syscall termina**, aterriza en el **Gadget 1** (que **limpia** el Shadow Space), rebota en el **Gadget 2** (que devuelve el **control** de ejecución), y finalmente se **restaura el RSP** original.

<img width="1094" height="240" alt="imagen" src="https://github.com/user-attachments/assets/23cb4456-7f89-45a6-b9cd-bf0e612e6e72" />


## ¿Como se ve el stack antes de la ejecucion de la syscall?
~~~
Direcciones Bajas 0x0000000000
================================================================================
[RSP + pos4] -> pos4 (0x00): Dirección de Gadget 1 (ADD RSP, 0x38; RET)
                             (La Syscall real de NTDLL hace RET y aterriza aquí)
[RSP + 0x08] -> Shadow Space 1 (Basura / RCX)
[RSP + 0x10] -> Shadow Space 2 (Basura / RDX)
[RSP + 0x18] -> Shadow Space 3 (Basura / R8)
[RSP + 0x20] -> Shadow Space 4 (Basura / R9)
[RSP + 0x28] -> ARGUMENTO 5 (Sobrevive intacto, empujado por Rust antes de saltar)
[RSP + 0x30] -> ARGUMENTO 6
================================================================================
...          -> El Gadget 1 ejecuta "ADD RSP, 0x38" (Limpiando la basura de arriba).
                Acto seguido ejecuta "RET", sacando la dirección en RSP + 0x38 -> Dir Gadget 2
================================================================================
[RSP + pos3] -> pos3 (pos4 + offset4 + 8): Dirección de Gadget 2 (CALL RDI / REG)
                             (El flujo aterriza aquí. Al ser un "CALL", ensucia
                              8 bytes, pero nos devuelve el control al código Rust) -> da igual ensuciar 8 bytes por que al final de la syscall spoofeada se restaura
================================================================================
...          -> Espacio asignado al frame de Gadget 2 (offset3 extraído del .pdata)
================================================================================
[RSP + pos2] -> pos2 (pos3 + offset3 + 8): BaseThreadInitThunk + 0x14 (No ejecuta nada dentro de aqui, solo es spoofeo)
================================================================================
...          -> Espacio asignado al frame de BaseThreadInitThunk (offset2)
================================================================================
[RSP + pos1] -> pos1 (pos2 + offset2 + 8): RtlUserThreadStart + 0x21 (No ejecuta nada dentro de aqui, solo es spoofeo)
================================================================================
...          -> Espacio asignado al frame de RtlUserThreadStart (offset1)
================================================================================
[RSP + null] -> null_ret_offset (pos1 + offset1 + 8): 0x0000000000000000
                (El EDR lee el 0, asume que es el origen
                 legítimo del hilo y da su análisis por terminado y limpio).
================================================================================
Direcciones altas 0xFFFFFFFFFFFF
~~~

## Note

Este repositorio es un wrapper de la implementacion de esta misma técnica en https://github.com/lcalzada-xor/zada-xor/blob/main/src/techniques/evasion/execution/indirect_syscall.rs

## ⚠️ Descargo de Responsabilidad y Uso Ético (Disclaimer)

> [!IMPORTANT]
> **Este proyecto tiene fines estrictamente educativos, de investigación académica y de seguridad defensiva.**
> 
> * **Uso Autorizado:** El código y los conceptos demostrados aquí están destinados únicamente a ser utilizados en entornos controlados, laboratorios de investigación y sistemas donde se cuente con la autorización explícita de los propietarios.
> * **Finalidad Defensiva:** Está diseñado para ayudar a investigadores de seguridad, analistas de malware y desarrolladores de soluciones EDR/AV a comprender cómo operan estas técnicas de resolución para poder detectarlas y mitigarlas eficazmente.
> * **Prohibición de Uso Malicioso:** El autor no promueve, apoya ni consiente el uso de este software con fines destructivos, intrusivos o maliciosos. Cualquier uso inadecuado o ilegal de esta herramienta es responsabilidad exclusiva del usuario final.
