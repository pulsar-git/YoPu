BITS 32

%include "liveit.mac"

start:
   call delta
 delta:
   pop eax
   mov edx,eax ; edx = relative of delta
   sub eax,delta
   
   lea ecx,[eax+start_iat]

next_import:
   mov ebx,dword [ecx]
   test ebx,ebx ;ebx = destination
   jz end
   
   mov edi,dword [ecx+4]
   lea edi,[eax+edi]
   cmp byte [edi],1
   jne resolv_lib
   mov edi,dword [edi+1] ; récuperer le pointeur !
continue_lib:
   
   
   mov esi,dword [ecx+8]
	 lea esi,[eax+esi]
   cmp dword [esi],0x20000000
   jge resolv_func
   mov esi,dword [esi] ; récuperer le pointeur !
   jmp resolv_func

continue_func:
	 mov dword [eax+ebx],esi
	 add ecx,0Ch
	 jmp next_import

 end:    
   mov ebx,dword [eax+relative_goto]
	 add eax,ebx
   jmp eax



resolv_lib:
	
	push eax
	push ecx
	push edi
	
	push edi
	mov ecx,[eax+loadLibrary]
	call [eax+ecx]
	
	pop edi
	mov byte [edi],1
	mov dword [edi+1],eax
	mov edi,eax
	pop ecx
	pop eax
	jmp continue_lib

resolv_func:
	push eax
	push ecx
	push esi

	push esi
	push edi
	mov ecx,[eax+getprocadress]
	call [eax+ecx]

	pop esi
	mov esi,eax
	pop ecx
	pop eax
	jmp continue_func


relative_goto: dd 0
loadLibrary: dd 0
getprocadress: dd 0


start_iat:
;iat_stuff

;struc
;
;destination offset
;librairie_id -> offset d'une chaine qui se transforme en dword à la première execution de LoadLibrairieA
;function_id -> offset vers une Chaine ou dword (ordinal)
;
;endstruc


;relative_start_iat exemple
;100 20 100
;200 20 105
;..


;"kernel32.dll",0
;"user 32.dll",0
;"wininet.dll",0
;...
;...

;"MessageBoxA"
;"GetWindowProcA"
;...

;####################################################
;		 Définition des variables pour le C
;    Ne rien mettre apres, sera supprimé par liveit
;####################################################
live_start
live_def relative_goto,4
live_def loadLibrary,4
live_def getprocadress,4