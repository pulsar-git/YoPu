BITS 32
%include "liveit.mac"

 start:
   call delta
 delta:
   pop eax
   mov edx,eax ; edx = relative of delta
   sub eax,delta
   
   mov ecx,[eax+size]
   test ecx,ecx
   jz end
   mov edi,[eax+relative_start_decrypt]
   add edi,edx
   lea esi,[eax+compressed_data]
   push eax
;uncompress...
  push 0xFFFFFFFF ;max dstlen size...to change prolly later!
  push edi
  push ecx
  push esi
  call aP_depack_asm_safe

  pop eax
 end:    
   mov ebx,[eax+relative_EIP]
   add ebx,edx
   jmp ebx 

relative_EIP: dd 0
relative_start_decrypt: dd 0
size: dd 0

;;
;; aPLib compression library  -  the smaller the better :)
;;
;; NASM safe assembler depacker
;;
;; Copyright (c) 1998-2005 by Joergen Ibsen / Jibz
;; All Rights Reserved
;;
;; http://www.ibsensoftware.com/
;;

; =============================================================

%macro getbitM 0
    add    dl, dl
    jnz    short %%stillbitsleft

    sub    dword [esp + 4], byte 1 ; read one byte from source
    jc     return_error            ;

    mov    dl, [esi]
    inc    esi

    add    dl, dl
    inc    dl
%%stillbitsleft:
%endmacro

%macro domatchM 1
    push   ecx
    mov    ecx, [esp + 12 + _dlen$] ; ecx = dstlen
    sub    ecx, [esp + 4]           ; ecx = num written
    cmp    %1, ecx
    pop    ecx
    ja     return_error

    sub    [esp], ecx         ; write ecx bytes to destination
    jc     return_error       ;

    push   esi
    mov    esi, edi
    sub    esi, %1
    rep    movsb
    pop    esi
%endmacro

%macro getgammaM 1
    mov    %1, 1
%%getmore:
    getbitM
    adc    %1, %1
    jc     return_error
    getbitM
    jc     short %%getmore
%endmacro

; =============================================================
aP_depack_asm_safe:
    ; aP_depack_asm_safe(const void *source,
    ;                    unsigned int srclen,
    ;                    void *destination,
    ;                    unsigned int dstlen);

    _ret$  equ 7*4
    _src$  equ 8*4 + 4
    _slen$ equ 8*4 + 8
    _dst$  equ 8*4 + 12
    _dlen$ equ 8*4 + 16

    pushad

    mov    esi, [esp + _src$] ; C calling convention
    mov    eax, [esp + _slen$]
    mov    edi, [esp + _dst$]
    mov    ecx, [esp + _dlen$]

    push   eax
    push   ecx

    test   esi, esi
    jz     return_error

    test   edi, edi
    jz     return_error

    cld
    xor    edx, edx

literal:
    sub    dword [esp + 4], byte 1 ; read one byte from source
    jc     return_error            ;

    mov    al, [esi]
    add    esi, byte 1

    sub    dword [esp], byte 1 ; write one byte to destination
    jc     return_error        ;

    mov    [edi], al
    add    edi, byte 1

    mov    ebx, 2

nexttag:
    getbitM
    jnc    literal

    getbitM
    jnc    codepair

    xor    eax, eax

    getbitM
    jnc    shortmatch

    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    jz     .thewrite

    mov    ebx, [esp + 8 + _dlen$] ; ebx = dstlen
    sub    ebx, [esp]              ; ebx = num written
    cmp    eax, ebx
    ja     return_error

    mov    ebx, edi
    sub    ebx, eax
    mov    al, [ebx]

  .thewrite:
    sub    dword [esp], byte 1 ; write one byte to destination
    jc     return_error        ;

    mov    [edi], al
    inc    edi

    mov    ebx, 2

    jmp    nexttag

codepair:
    getgammaM eax

    sub    eax, ebx

    mov    ebx, 1

    jnz    normalcodepair

    getgammaM ecx

    domatchM ebp

    jmp    nexttag

normalcodepair:
    dec    eax

    test   eax, 0xff000000
    jnz    return_error

    shl    eax, 8

    sub    dword [esp + 4], byte 1 ; read one byte from source
    jc     return_error            ;

    mov    al, [esi]
    inc    esi

    mov    ebp, eax

    getgammaM ecx

    cmp    eax, 32000
    sbb    ecx, byte -1

    cmp    eax, 1280
    sbb    ecx, byte -1

    cmp    eax, 128
    adc    ecx, byte 0

    cmp    eax, 128
    adc    ecx, byte 0

    domatchM eax
    jmp    nexttag

shortmatch:
    sub    dword [esp + 4], byte 1 ; read one byte from source
    jc     return_error            ;

    mov    al, [esi]
    inc    esi

    xor    ecx, ecx
    db     0c0h, 0e8h, 001h
    jz     donedepacking

    adc    ecx, byte 2

    mov    ebp, eax

    domatchM eax

    mov    ebx, 1

    jmp    nexttag

return_error:
    add    esp, byte 8

    popad

    or     eax, byte -1       ; return APLIB_ERROR in eax

    ret 16

donedepacking:
    add    esp, byte 8

    sub    edi, [esp + _dst$]
    mov    [esp + _ret$], edi ; return unpacked length in eax

    popad

    ret 16
compressed_data:


;####################################################
;		 Définition des variables pour le C
;    Ne rien mettre apres, sera supprimé par liveit
;####################################################
live_start
live_def size,4
live_def relative_EIP,4
live_def relative_start_decrypt,4