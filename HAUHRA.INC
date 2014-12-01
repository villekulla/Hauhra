IMAGE_DIRECTORY_ENTRY_RELOC_TABLE       equ    0a0h     ;offset from beginning of NT_HEADERS
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_TABLE equ    0c8h     ;offset from beginning of NT_HEADERS

MAX_LEVELS                              equ    257

level_data struct
    findhandler dd ?
level_data ends 

regmap struct
    regEdi  dd ?
    regEsi  dd ?
    regEbp  dd ?
    regEsp  dd ?
    regEbx  dd ?
    regEdx  dd ?
    regEcx  dd ?
    regEax  dd ?
regmap ends

EXCEPTION_REGISTRATION_RECORD struct
    Next     dd ?
    Handler  dd ?
EXCEPTION_REGISTRATION_RECORD ends

sehmap struct
    ExceptionRegistrationRecord  EXCEPTION_REGISTRATION_RECORD <?>
    Registers                    regmap <?>
sehmap ends

kernel32 struct
    kWriteFile            dd ?   
    kUnmapViewOfFile      dd ?
    kSetFileAttributesW   dd ?
    kSetCurrentDirectoryW dd ?
    kMapViewOfFile        dd ?
    kGlobalFree           dd ?
    kGlobalAlloc          dd ?
;   kGetTickCount         dd ?
    kFindNextFileW        dd ?
    kFindFirstFileW       dd ?
    kFindClose            dd ?
    kCreateFileW          dd ?
    kCreateFileMappingW   dd ?
    kCreateFileA          dd ?
    kCloseHandle          dd ?
kernel32 ends

python24 struct
    Py_Initialize             dd ?
    Py_BuildValue             dd ?
    Py_Finalize               dd ?
    Py_DecRef                 dd ?
    PyObject_GetAttrString    dd ?
    PyLong_FromUnsignedLong   dd ?
    PyLong_AsLong             dd ?
;   PyList_SetItem            dd ?
;   PyList_GetItem            dd ?
    PyList_New                dd ?
    PyImport_ImportModule     dd ?
    PyEval_CallObject         dd ?    
python24 ends

pylist_object struct
    ob_refcnt dd ?
    ob_type   dd ?
    ob_size   dd ?
    ob_item   dd ?
    allocated dd ?
pylist_object ends

LIST_ENTRY struct
    FLink  dd ?
    BLink  dd ?
LIST_ENTRY ends

_PEB_LDR_DATA struct
    dwLength                           dd ?
    bInitialized                       dd ?
    dwSsHandle                         dd ?
    dwInLoadOrderModuleList            LIST_ENTRY <?>
    dwInMemoryOrderModuleList          LIST_ENTRY <?>
    dwInInitializationOrderModuleList  LIST_ENTRY <?>
_PEB_LDR_DATA ends

PROCESS_ENVIRONMENT_BLOCK struct
	bInhiritedAddressSpace     db ?
	bReadImageFileExecOptions  db ?
	bBeingDebugged             db ?
	bSpare                     db ?
	hMutant                    dd ?
	dwImageBaseAddress         dd ?
	lpLoaderData               dd ?
	lpProcessParameters        dd ?
PROCESS_ENVIRONMENT_BLOCK ends

WIN32_FIND_DATA struct
    dwFileAttributes dd ?
    ftCreationTime   dq ?
    ftLastAccessTime dq ?
    ftLastWriteTime  dq ?
    nFileSizeHigh    dd ?
    nFileSizeLow     dd ?
    dwReserved0      dd ?
    dwReserved1      dd ?
    cFileName        db 260 dup (?)
    cAlternate       db 0eh dup (?)
WIN32_FIND_DATA ends