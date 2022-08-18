import winim/lean as winimport

    #[
        Windows Undocumented Structures - Windows 7+
    ]#

type
    # https://doxygen.reactos.org/d3/d71/struct__ASSEMBLY__STORAGE__MAP__ENTRY.html
    ASSEMBLY_STORAGE_MAP {.pure.} = object
        Flags*      : winimport.ULONG
        DosPath*    : winimport.UNICODE_STRING
        Handle*     : winimport.HANDLE
    PASSEMBLY_STORAGE_MAP* = ptr ASSEMBLY_STORAGE_MAP

    LDR_DLL_LOAD_REASON* {.pure.} = enum
        LoadReasonUnknown                       = -1
        LoadReasonStaticDependency              = 0
        LoadReasonStaticForwarderDependency     = 1
        LoadReasonDynamicForwarderDependency    = 2
        LoadReasonDelayloadDependency           = 3
        LoadReasonDynamicLoad                   = 4
        LoadReasonAsImageLoad                   = 5
        LoadReasonAsDataLoad                    = 6
        LoadReasonEnclavePrimary                = 7
        LoadReasonEnclaveDependency             = 8

    RTL_BALANCED_NODE_STRUCT1* {.pure.} = object
        Left* : PRTL_BALANCED_NODE
        Right* : PRTL_BALANCED_NODE

    RTL_BALANCED_NODE_UNION1* {.pure, union.} = object
        Children* : array[2, PRTL_BALANCED_NODE]
        Struct1*  : RTL_BALANCED_NODE_STRUCT1

    RTL_BALANCED_NODE_UNION2* {.pure, union.} = object
        Red*        {.bitsize:1.}   : winimport.UCHAR
        Balance*    {.bitsize:2.}   : winimport.UCHAR
        ParentValue*                : winimport.ULONG_PTR

    RTL_BALANCED_NODE* {.pure.} = object
        Union1* : RTL_BALANCED_NODE_UNION1
        Union2* : RTL_BALANCED_NODE_UNION2
    PRTL_BALANCED_NODE* = ptr RTL_BALANCED_NODE

    LDR_DATA_TABLE_ENTRY_UNION_ONE* {.pure, union.} = object
        InInitializationOrderLinks*  : winimport.LIST_ENTRY
        InProgressLinks*             : winimport.LIST_ENTRY
    PLDR_DATA_TABLE_ENTRY_UNION_ONE* = ptr LDR_DATA_TABLE_ENTRY_UNION_ONE

    LDR_DATA_TABLE_ENTRY_STRUCT_ONE* {.pure.} = object
        PackagedBinary* {.bitsize:1.}           : winimport.ULONG
        MarkedForRemoval* {.bitsize:1.}         : winimport.ULONG
        ImageDll* {.bitsize:1.}                 : winimport.ULONG
        LoadNotificationSent* {.bitsize:1.}     : winimport.ULONG
        TelemetryEntryProcessed* {.bitsize:1.}  : winimport.ULONG
        ProcessStaticImport* {.bitsize:1.}      : winimport.ULONG
        InLegacyLists* {.bitsize:1.}            : winimport.ULONG
        InIndexes* {.bitsize:1.}                : winimport.ULONG
        ShimDll* {.bitsize:1.}                  : winimport.ULONG
        InExceptionTable* {.bitsize:1.}         : winimport.ULONG
        ReservedFlags1* {.bitsize:2.}           : winimport.ULONG
        LoadInProgress* {.bitsize:1.}           : winimport.ULONG
        LoadConfigProcessed* {.bitsize:1.}      : winimport.ULONG
        EntryProcessed* {.bitsize:1.}           : winimport.ULONG
        ProtectDelayLoad* {.bitsize:1.}         : winimport.ULONG
        ReservedFlags3* {.bitsize:2.}           : winimport.ULONG
        DontCallForThreads* {.bitsize:1.}       : winimport.ULONG
        ProcessAttachCalled* {.bitsize:1.}      : winimport.ULONG
        ProcessAttachFailed* {.bitsize:1.}      : winimport.ULONG
        CorDeferredValidate* {.bitsize:1.}      : winimport.ULONG
        CorImage* {.bitsize:1.}                 : winimport.ULONG
        DontRelocate {.bitsize:1.}              : winimport.ULONG
        CorILOnly* {.bitsize:1.}                : winimport.ULONG
        ChpeImage* {.bitsize:1.}                : winimport.ULONG
        ReservedFlags5* {.bitsize:2.}           : winimport.ULONG
        Redirected* {.bitsize:1.}               : winimport.ULONG
        ReservedFlags6* {.bitsize:2.}           : winimport.ULONG
        CompatDatabaseProcessed* {.bitsize:1.}  : winimport.ULONG

    LDR_DATA_TABLE_ENTRY_UNION_TWO* {.pure, union.} = object
        FlagGroup*   : array[4, winimport.UCHAR]
        Flags*       : winimport.ULONG
        Struct*      : LDR_DATA_TABLE_ENTRY_STRUCT_ONE            
    PLDR_DATA_TABLE_ENTRY_UNION_TWO* = ptr LDR_DATA_TABLE_ENTRY_UNION_TWO
    
    LDR_DATA_TABLE_ENTRY* {.pure.} = object
        InLoadOrderLinks*               : winimport.LIST_ENTRY
        InMemoryOrderLinks*             : winimport.LIST_ENTRY
        Union_1*                        : LDR_DATA_TABLE_ENTRY_UNION_ONE
        DLLBase*                        : winimport.PVOID
        EntryPoint*                     : winimport.PVOID
        SizeOfImage*                    : winimport.ULONG
        FullDllName*                    : winimport.UNICODE_STRING
        BaseDllName*                    : winimport.UNICODE_STRING
        Union_2*                        : LDR_DATA_TABLE_ENTRY_UNION_TWO
        ObsoleteLoadCount               : winimport.USHORT
        TlsIndex*                       : winimport.USHORT
        HashLinks*                      : winimport.LIST_ENTRY
        TimeDateStamp*                  : winimport.ULONG
        EntryPointActivationContext*    : winimport.PVOID
        Lock*                           : winimport.PVOID
        DdgagNode*                      : winimport.PVOID       # PLDR_DDAG_NODE
        NodeModuleLink*                 : winimport.LIST_ENTRY
        LoadContext*                    : winimport.PVOID       # PLDRP_LOAD_CONTEXT
        ParentDllBase                   : winimport.PVOID
        SwitchBackContext*              : winimport.PVOID
        BaseAddressIndexNode*           : RTL_BALANCED_NODE
        MappingInfoIndexNode*           : RTL_BALANCED_NODE
        OriginalBase*                   : winimport.ULONG_PTR
        LoadTime*                       : winimport.LARGE_INTEGER
        BaseNameHashValue*              : winimport.ULONG
        LoadReason*                     : LDR_DLL_LOAD_REASON
        ImplicitPathOptions*            : winimport.ULONG
        ReferenceCount*                 : winimport.ULONG
        DependentLoadFlags*             : winimport.ULONG
        SigningLevel*                   : winimport.UCHAR
    PLDR_DATA_TABLE_ENTRY* = ptr LDR_DATA_TABLE_ENTRY

    PEB_LDR_DATA* {.pure.} = object
        Length*                             : winimport.ULONG
        Initialized*                        : winimport.BOOLEAN
        SsHandle*                           : winimport.PVOID
        InLoadOrderModuleList*              : winimport.LIST_ENTRY
        InMemoryOrderModuleList*            : winimport.LIST_ENTRY
        InInitializationOrderModuleList*    : winimport.LIST_ENTRY
        EntryInProgress*                    : winimport.PVOID
        ShutdownInProgress*                 : winimport.BOOLEAN
        ShutdownThreadId*                   : winimport.HANDLE
    PPEB_LDR_DATA* = ptr PEB_LDR_DATA

    PEB* {.pure.} = object
        InheritedAddressSpace*                  : winimport.BOOLEAN
        ReadImageFileExecOptions*               : winimport.BOOLEAN
        BeingDebugged*                          : winimport.BOOLEAN
        PebUnion1*                              : winimport.UCHAR
        Padding0*                               : array[4, winimport.UCHAR]
        Mutant*                                 : winimport.HANDLE
        ImageBaseAddress*                       : winimport.PVOID
        Ldr*                                    : PPEB_LDR_DATA                             
        ProcessParameters*                      : winimport.PRTL_USER_PROCESS_PARAMETERS  
        SubSystemData*                          : winimport.PVOID                         
        ProcessHeap*                            : winimport.HANDLE                        
        FastPebLock*                            : winimport.PVOID          # PRTL_CRITICAL_SECTION
        AtlThunkSListPtr*                       : winimport.PVOID                         
        IFEOKey*                                : winimport.PVOID                         
        PebUnion2*                              : winimport.ULONG                         
        Padding1*                               : array[4, winimport.UCHAR]               
        KernelCallBackTable*                    : ptr winimport.PVOID                     
        SystemReserved*                         : winimport.ULONG                         
        AltThunkSListPtr32*                     : winimport.ULONG                         
        ApiSetMap*                              : winimport.PVOID                         
        TlsExpansionCounter*                    : winimport.ULONG                         
        Padding2*                               : array[4, winimport.UCHAR]               
        TlsBitmap*                              : winimport.PVOID                         
        TlsBitmapBits*                          : array[2, winimport.ULONG]               
        ReadOnlyShareMemoryBase*                : winimport.PVOID                         
        SharedData*                             : winimport.PVOID                         
        ReadOnlyStaticServerData*               : ptr winimport.PVOID                     
        AnsiCodePageData*                       : winimport.PVOID                         
        OemCodePageData*                        : winimport.PVOID                         
        UnicodeCaseTableData*                   : winimport.PVOID                         
        NumberOfProcessors*                     : winimport.ULONG                         
        NtGlobalFlag*                           : winimport.ULONG                         
        CriticalSectionTimeout*                 : winimport.LARGE_INTEGER                 
        HeapSegmentReserve*                     : winimport.ULONG_PTR                     
        HeapSegmentCommit*                      : winimport.ULONG_PTR                     
        HeapDeCommitTotalFreeThreshold*         : winimport.ULONG_PTR                     
        HeapDeCommitFreeBlockThreshold*         : winimport.ULONG_PTR                     
        NumberOfHeaps*                          : winimport.ULONG                         
        MaximumNumberOfHeaps*                   : winimport.ULONG                         
        ProcessHeaps*                           : ptr winimport.PVOID                     
        GdiSharedHandleTable*                   : winimport.PVOID                         
        ProcessStarterHelper*                   : winimport.PVOID                         
        GdiDCAttributeList*                     : winimport.ULONG                         
        Padding3*                               : array[4, winimport.UCHAR]               
        LoaderLock*                             : winimport.PVOID           # PRTL_CRITICAL_SECTION
        OSMajorVersion*                         : winimport.ULONG
        OSMinorVersion*                         : winimport.ULONG
        OSBuildNumber*                          : winimport.USHORT
        OSCSDVersion*                           : winimport.USHORT
        OSPlatformId*                           : winimport.ULONG
        ImageSubsystem*                         : winimport.ULONG
        ImageSubsystemMajorVersion*             : winimport.ULONG
        ImageSubsystemMinorVersion*             : winimport.ULONG
        Padding4                                : array[4, winimport.UCHAR]
        ActiveProcessAffinityMask*              : winimport.PVOID            # KAFFINITY
        GdiHandleBuffer                         : array[0x3c, winimport.ULONG]
        PostProcessInitRoutine*                 : winimport.VOID
        TlsExpansionBitmap*                     : winimport.PVOID
        TlsExpansionBitmapBits*                 : array[0x20, winimport.ULONG]
        SessionId*                              : winimport.ULONG
        Padding5*                               : array[4, winimport.UCHAR]
        AppCompatFlags*                         : winimport.ULARGE_INTEGER
        AppCompatFlagsUser*                     : winimport.ULARGE_INTEGER
        ShimData*                               : winimport.PVOID
        AppCompatInfo*                          : winimport.PVOID
        CSDVersion*                             : winimport.UNICODE_STRING
        ActivationContextData*                  : winimport.PVOID             # PACTIVATION_CONTEXT_DATA 
        ProcessAssemblyStorageMap*              : winimport.PVOID             # PASSEMBLY_STORAGE_MAP
        SystemDefaultActivationContextData*     : winimport.PVOID             # PACTIVATION_CONTEXT_DATA
        SystemAssemblyStorageMap*               : winimport.PVOID             # PASSEMBLY_STORAGE_MAP
        MinimumStackCommit*                     : winimport.ULONG_PTR
        Sparepointers*                          : array[4, winimport.PVOID]
        SpareUlongs*                            : array[5, winimport.ULONG]
        WerRegistrationData*                    : winimport.PVOID
        WerShipAssertPtr*                       : winimport.PVOID
        Unused*                                 : winimport.PVOID
        ImageHeaderHash*                        : winimport.PVOID
        TracingFlags*                           : winimport.ULONG
        CsrServerReadOnlySharedMemoryBase*      : winimport.ULONGLONG
        TppWorkerpListLock*                     : winimport.ULONG
        TppWorkerpList*                         : winimport.LIST_ENTRY
        WaitOnAddressHashTable*                 : array[0x80, winimport.PVOID]
        TelemtryCoverageHeader*                 : winimport.PVOID
        CloudFileFlags*                         : winimport.ULONG
        CloudFileDiagFlags*                     : winimport.ULONG
        PlaceholderCompatabilityMode*           : winimport.CHAR
        PlaceholderCompatabilityModeReserved*   : array[7, winimport.CHAR]
        LeapSecondData*                         : winimport.PVOID
        LeapSecondFlags*                        : winimport.ULONG
        NtGlobalFlag2*                          : winimport.ULONG
    PPEB* = ptr PEB

    TEB* {.pure.} = object
        NtTib*                                  : winimport.NT_TIB
        EnvironmentPointer*                     : winimport.PVOID
        ClientId*                               : winimport.CLIENT_ID
        ActiveRpcHandle*                        : winimport.PVOID
        ThreadLocalStoragePointer*              : winimport.PVOID
        ProcessEnvironmentBlock*                : PEB
        LastErrorValue*                         : winimport.ULONG
        CountOfOwnedCriticalSections*           : winimport.ULONG
        CsrClientThread*                        : winimport.PVOID
        Win32ThreadInfo*                        : winimport.PVOID
        User32Reserved*                         : array[0x1A, winimport.ULONG]
        UserReserved*                           : array[5, winimport.ULONG]
        WOW32Reserved*                          : winimport.PVOID
        CurrentLocale*                          : winimport.ULONG
        FpSoftwareStatusRegister*               : winimport.ULONG
        ReservedForDebuggerInstrumentation*     : array[0x10, winimport.PVOID]
    PTEB* = ptr TEB