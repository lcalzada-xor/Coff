# Coff
Call Stack Spoof with Indirect Syscall for Rust

## ¿Otra implementación mas de Call Stack Spoof? -> Result\<No\>

La técnica implementada si bien su objetivo final es el mismo que implementaciones como SilentMoonWalk, su arquitectura es diferente, lo mas destacable es que no utiliza TLS callbacks ni explota la desincronizacion del unwinding con el registro RBP a través del código UWOP_SET_FPREG. 

En su lugar, se ciñe estrictamente al ABI de Windows x64, construyendo una pila sintética contigua y matemáticamente perfecta que se sincroniza al milímetro con el .pdata del sistema mediante un doble juego de gadgets (ADD RSP + CALL), logrando un corte limpio e indetectable de la traza (Unwind) finalizando en un NULL para detener el unwinding. (De momento no me ha dado problemas probando varias funciones :) )

## Flujo de Ejecución de la implementación (partes destacadas)

1. El inyector localiza NTDLL y Kernel32, se **extrae dinámicamente el SSN** (System Service Number) de la API objetivo (mediante escaneo de la funcion cargada en memoria).

2. Se escanea la memoria de nuevo en **busca de los Gadgets** necesarios - Se han utilizado: **ADD RSP, \{variable\}; RET** y **CALL RDI/RSI/R15/R12** (cualquiera de ellos).

3. El parser lee el **.pdata** de los **Gadgets** y de las funciones base de Windows (**BaseThreadInitThunk**, **RtlUserThreadStart**), extrayendo el tamaño exacto que ocupará cada uno en la memoria.

4. El bloque asm! secuestra el registro RSP, **expande la pila** restando los **bytes calculados que ocuparan las funciones a spoofear** y coloca las direcciones de retorno de estas funciones spoofeadas (en el caso de BaseThreadInitThunk, RtlUserThreadStart se les suma los offsets +0x14 y +0x21 para **mayor opsec**).

5. Se altera el StackBase, se establece el registro R10 y el EAX para la **Syscall**, y se ejecuta el **salto** hacia NTDLL.

6. La **Syscall termina**, aterriza en el **Gadget 1** (que **limpia** el Shadow Space), rebota en el **Gadget 2** (que devuelve el **control** de ejecución), y finalmente se **restaura el RSP** original.

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
                Acto seguido ejecuta "RET", sacando la dirección en RSP + 0x38.
================================================================================
[RSP + pos3] -> pos3 (pos4 + offset4 + 8): Dirección de Gadget 2 (CALL RDI / REG)
                             (El flujo aterriza aquí. Al ser un "CALL", ensucia
                              8 bytes, pero nos devuelve el control al código Rust) -> da igual ensuciar 8 bytes por que al final de la syscall spoofeada se restaura
================================================================================
...          -> Espacio asignado al frame de Gadget 2 (offset3 extraído del .pdata)
================================================================================
[RSP + pos2] -> pos2 (pos3 + offset3 + 8): BaseThreadInitThunk + 0x14
================================================================================
...          -> Espacio asignado al frame de BaseThreadInitThunk (offset2)
================================================================================
[RSP + pos1] -> pos1 (pos2 + offset2 + 8): RtlUserThreadStart + 0x21
================================================================================
...          -> Espacio asignado al frame de RtlUserThreadStart (offset1)
                (+ 8 bytes del "POP" virtual calculado por el EDR al desenrollar)
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
