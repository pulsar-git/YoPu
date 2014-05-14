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
   mov esi,[eax+relative_start_decrypt]
   add esi,edx
   mov ebx,[eax+key]
 decrypt:  
   xor byte [esi+ecx-1],bl
   dec ecx
   jnz decrypt

 end:    
   mov ebx,[eax+relative_goto]
   add ebx,edx
   jmp ebx

relative_goto: dd 0
relative_start_decrypt: dd 0
size: dd 0
key: dd 0


;####################################################
;		 Définition des variables pour le C
;    Ne rien mettre apres, sera supprimé par liveit
;####################################################
live_start
live_def size,4
live_def relative_goto,4
live_def relative_start_decrypt,4
live_def key,4

