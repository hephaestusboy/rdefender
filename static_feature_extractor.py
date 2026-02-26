import pefile
import os
import math
import re
from collections import Counter, defaultdict

SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")

# =========================================================
# CROSS-PLATFORM DIGITAL SIGNATURE SETUP
# =========================================================

# 1. Try to load Linux/Cross-Platform library (Signify 0.9.2+ Syntax)
try:
    from signify.authenticode import AuthenticodeFile, AuthenticodeVerificationResult
    SIGNIFY_AVAILABLE = True
except ImportError:
    SIGNIFY_AVAILABLE = False

# 2. Try to load Native Windows API (Only runs if on Windows!)
if os.name == 'nt':
    import ctypes
    from ctypes import wintypes
    
    WINTRUST_ACTION_GENERIC_VERIFY_V2 = ctypes.c_buffer(
        b'\x00\xaa\xc5\x6c\xce\x11\xd1\x11\x8c\x7a\x00\xc0\x4f\xc2\x95\xee'
    )
    WTD_UI_NONE = 2
    WTD_REVOKE_NONE = 0
    WTD_CHOICE_FILE = 1
    WTD_STATEACTION_IGNORE = 0
    WTD_UICONTEXT_EXECUTE = 0

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.c_void_p) # SAFELY FIXED TO ctypes.c_void_p
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p)
        ]

# =========================================================
# FEATURE DEFINITIONS
# =========================================================

API_GROUPS = {
    "API_PROC_CREATE": ["CreateProcess", "NtCreateProcess"],
    "API_PROC_TERMINATE": ["NtTerminateProcess"],
    "API_THREAD_CREATE": ["CreateThread", "RtlCreateUserThread"],
    "API_THREAD_SUSPEND_RESUME": ["NtSuspendThread", "NtResumeThread"],
    "API_REMOTE_THREAD": ["CreateRemoteThread"],
    "API_PROCESS_ENUM": ["Process32First", "Process32Next"],
    "API_THREAD_ENUM": ["Thread32First", "Thread32Next"],
    "API_MEMORY_ALLOC": ["NtAllocateVirtualMemory"],
    "API_MEMORY_PROTECT": ["VirtualProtect", "NtProtectVirtualMemory"],
    "API_MEMORY_READ": ["ReadProcessMemory", "NtReadVirtualMemory"],
    "API_MEMORY_WRITE": ["WriteProcessMemory", "NtWriteVirtualMemory"],
    "API_SECTION_MAP": ["NtMapViewOfSection"],
    "API_SECTION_UNMAP": ["NtUnmapViewOfSection"],
    "API_DLL_LOAD": ["LdrLoadDll", "LoadLibrary"],
    "API_DLL_UNLOAD": ["LdrUnloadDll", "FreeLibrary"],
    "API_GET_PROC_ADDR": ["GetProcAddress", "LdrGetProcedureAddress"],
    "API_EXCEPTION_HANDLER": ["SetUnhandledExceptionFilter"],
    "API_CONTEXT_MANIPULATION": ["NtGetContextThread", "NtSetContextThread"],

    "API_CRYPTO_CONTEXT": ["CryptAcquireContext"],
    "API_CRYPTO_KEY_GEN": ["CryptGenKey"],
    "API_CRYPTO_KEY_EXPORT": ["CryptExportKey"],
    "API_CRYPTO_HASH": ["CryptCreateHash", "CryptHashData"],
    "API_CRYPTO_ENCRYPT": ["CryptEncrypt"],
    "API_CRYPTO_DECRYPT": ["CryptDecrypt"],
    "API_CERT_OPEN_STORE": ["CertOpenStore"],
    "API_CERT_CONTROL": ["CertControlStore"],
    "API_CERT_SYSTEM_STORE": ["CertOpenSystemStore"],
    "API_DATA_DECOMPRESSION": ["RtlDecompressBuffer"],

    "API_FILE_CREATE": ["CreateFile"],
    "API_FILE_OPEN": ["NtOpenFile"],
    "API_FILE_READ": ["ReadFile"],
    "API_FILE_WRITE": ["WriteFile"],
    "API_FILE_DELETE": ["DeleteFile"],
    "API_FILE_RENAME": ["MoveFile"],
    "API_FILE_ATTRIBUTES": ["GetFileAttributes"],
    "API_FILE_SIZE_QUERY": ["GetFileSize"],
    "API_DIRECTORY_ENUM": ["FindFirstFile"],
    "API_DIRECTORY_CREATE": ["CreateDirectory"],
    "API_DIRECTORY_DELETE": ["RemoveDirectory"],
    "API_TEMP_PATH_ACCESS": ["GetTempPath"],

    "API_SOCKET_CREATE": ["socket"],
    "API_SOCKET_CONNECT": ["connect"],
    "API_SOCKET_BIND_LISTEN": ["bind", "listen"],
    "API_SOCKET_SEND": ["send"],
    "API_SOCKET_RECV": ["recv"],
    "API_SOCKET_CLOSE": ["closesocket"],
    "API_DNS_QUERY": ["DnsQuery"],
    "API_HTTP_OPEN": ["InternetOpen"],
    "API_HTTP_REQUEST": ["HttpSendRequest"],
    "API_HTTP_STATUS_QUERY": ["InternetQueryOption"],

    "API_DEBUG_DETECTION": ["IsDebuggerPresent"],
    "API_DELAY_EXECUTION": ["Sleep"],
    "API_KEYBOARD_STATE": ["GetAsyncKeyState"],
    "API_WINDOW_ENUMERATION": ["EnumWindows"],
    "API_HOOK_INSTALL": ["SetWindowsHookEx"],
    "API_ERROR_MODE_CONTROL": ["SetErrorMode"],

    "API_SYSTEM_INFO": ["GetSystemInfo"],
    "API_DISK_SPACE_QUERY": ["GetDiskFreeSpace"],
    "API_VOLUME_ENUM": ["GetVolumePath"],
    "API_ADAPTER_INFO": ["GetAdaptersInfo"],
    "API_USERNAME_QUERY": ["GetUserName"],
    "API_COMPUTER_NAME_QUERY": ["GetComputerName"],
    # Add these specifically for ransomware/malware behavior
    "API_PRIVILEGE_ESC": ["AdjustTokenPrivileges", "OpenProcessToken", "SeDebugPrivilege"],
    "API_MUTEX": ["CreateMutex", "OpenMutex", "ReleaseMutex"],
    "API_SYSTEM_SHUTDOWN": ["InitiateSystemShutdown", "ExitWindowsEx", "NtShutdownSystem"],
}

DROP_GROUPS = {
    "DROP_EXECUTABLE_FILES": [".exe", ".dll", ".sys", ".bin"],
    "DROP_ENCRYPTED_EXTENSIONS": ["encrypted", "toxcrypt"],
    "DROP_ARCHIVES": [".zip", ".rar", ".7z"],
    "DROP_DOCUMENT_FILES": [".doc", ".pdf", ".xls"],
    "DROP_MEDIA_FILES": [".jpg", ".png", ".mp3"],
    "DROP_SCRIPT_FILES": [".js", ".vbs", ".bat"],
    "DROP_LIBRARY_FILES": [".dll", ".ocx"],
    "DROP_CONFIG_FILES": [".ini", ".cfg"],
    "DROP_TEMP_FILES": [".tmp", ".dat"],
    "DROP_RANDOM_NAMED_FILES": ["{"],
}

# =============================
# Utility functions
# =============================

def verify_digital_signature(filepath):
    """
    Checks if a file has a cryptographically valid digital signature.
    Uses Native Windows API if on Windows, falls back to 'signify' on Linux.
    """
    # STRATEGY A: Native Windows Verification (Fastest, OS-level trust)
    if os.name == 'nt':
        try:
            file_info = WINTRUST_FILE_INFO()
            file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            file_info.pcwszFilePath = filepath
            file_info.hFile = None
            file_info.pgKnownSubject = None

            wintrust_data = WINTRUST_DATA()
            wintrust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            wintrust_data.pPolicyCallbackData = None
            wintrust_data.pSIPClientData = None
            wintrust_data.dwUIChoice = WTD_UI_NONE
            wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE
            wintrust_data.dwUnionChoice = WTD_CHOICE_FILE
            wintrust_data.pFile = ctypes.pointer(file_info)
            wintrust_data.dwStateAction = WTD_STATEACTION_IGNORE
            wintrust_data.dwProvFlags = 0
            wintrust_data.dwUIContext = WTD_UICONTEXT_EXECUTE
            wintrust_data.pSignatureSettings = None

            wintrust = ctypes.windll.wintrust
            wintrust.WinVerifyTrust.argtypes = [
                wintypes.HWND, ctypes.c_void_p, ctypes.POINTER(WINTRUST_DATA)
            ]
            wintrust.WinVerifyTrust.restype = wintypes.LONG

            status = wintrust.WinVerifyTrust(None, WINTRUST_ACTION_GENERIC_VERIFY_V2, ctypes.pointer(wintrust_data))
            return 1 if status == 0 else 0
        except Exception:
            pass 

    # STRATEGY B: Pure Python Verification via Signify (For Linux/Fedora)
    if SIGNIFY_AVAILABLE:
        try:
            with open(filepath, "rb") as f:
                signed_file = AuthenticodeFile.from_stream(f)
                status, err = signed_file.explain_verify()
                if status == AuthenticodeVerificationResult.OK:
                    return 1
                return 0
        except Exception:
            return 0
            
    # If neither is available or both fail
    return 0

def check_security_directory(pe):
    """
    Checks if the PE file has a Security Directory entry (Authenticode block).
    """
    try:
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4] 
        if security_dir.VirtualAddress != 0 and security_dir.Size > 0:
            return 1
    except Exception:
        pass
    return 0


def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    entropy = 0.0
    length = len(data)
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy

def extract_strings(filepath, min_len=5):
    with open(filepath, "rb") as f:
        data = f.read()
    pattern = rb"[ -~]{%d,}" % min_len
    return [s.decode(errors="ignore") for s in re.findall(pattern, data)]

def safe_pe_load(filepath):
    try:
        return pefile.PE(filepath, fast_load=True)
    except Exception:
        return None

def extract_imports(pe):
    apis = set()
    try:
        pe.parse_data_directories()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        apis.add(imp.name.decode(errors="ignore"))
    except Exception:
        pass
    return apis

# =============================
# MAIN FEATURE EXTRACTION
# =============================

def extract_features_from_binary(filepath):

    with open(filepath, "rb") as f:
        magic = f.read(2)

    if magic != b"MZ":
        raise ValueError("Not PE file")

    features = defaultdict(int)

    # ---- RAW BINARY ----
    with open(filepath, "rb") as f:
        data = f.read()

    features["FILE_ENTROPY"] = shannon_entropy(data)

    strings = extract_strings(filepath)
    joined = " ".join(strings).lower()

    # =============================
    # NEW: DIGITAL SIGNATURE FEATURES
    # =============================
    pe = safe_pe_load(filepath)
    
    if pe:
        features["HAS_DIGITAL_SIGNATURE"] = check_security_directory(pe)
        features["IS_SIGNATURE_VALID"] = verify_digital_signature(filepath)
    else:
        features["HAS_DIGITAL_SIGNATURE"] = 0
        features["IS_SIGNATURE_VALID"] = 0

    # =============================
    # RANSOM STRING FEATURES
    # =============================
    features["RANSOM_NOTE_STRINGS"] = int(
        any(x in joined for x in [
            "your files have been encrypted",
            "pay ransom",
            "bitcoin address",
            "decrypt your files"
        ])
    )

    features["CRYPTO_FILE_EXTENSION_STRINGS"] = int(
        any(x in joined for x in [".locked", ".crypted", ".encrypted", ".enc"])
    )

    features["WALLPAPER_CHANGE_STRINGS"] = int(
        any(x in joined for x in ["systemparametersinfo", "setwallpaper"])
    )
    # =============================
    # RANSOM STRING FEATURES
    # =============================
    # [Keep your existing string checks...]

    # THE SILVER BULLET: Shadow copy and recovery manipulation
    features["SHADOW_COPY_DELETION_STRINGS"] = int(
        any(x in joined for x in [
            "vssadmin", "delete shadows", "wbadmin", "bcdedit", 
            "recoveryenabled", "ignoreallfailures", "wmic shadowcopy"
        ])
    )

    # =============================
    # PE ANALYSIS
    # =============================
    # =============================
    # PE ANALYSIS
    # =============================
    if pe:
        imports = extract_imports(pe)
        imports_lower = [i.lower() for i in imports]
        features["NUM_IMPORTS"] = len(imports)

        # ---------- API GROUPS ----------
        for fname, apis in API_GROUPS.items():
            features[fname] = int(any(
                api.lower() in imp
                for api in apis
                for imp in imports_lower
            ))

        # SAFELY GET SECTIONS FIRST
        try:
            sections = pe.sections
        except AttributeError:
            sections = []

        # =============================
        # NEW: SUBSYSTEM & OVERLAY FEATURES
        # =============================
        try:
            subsystem = pe.OPTIONAL_HEADER.Subsystem
            features["IS_GUI_APP"] = int(subsystem == 2)
            features["IS_CONSOLE_APP"] = int(subsystem == 3)
        except Exception:
            features["IS_GUI_APP"] = 0
            features["IS_CONSOLE_APP"] = 0

        try:
            overlay_offset = pe.get_overlay_data_start_offset()
            features["HAS_OVERLAY"] = int(overlay_offset is not None)
        except Exception:
            features["HAS_OVERLAY"] = 0

        # =============================
        # ADVANCED ENTROPY & PACKER FEATURES
        # =============================
        features["VIRTUAL_RAW_SIZE_ANOMALY"] = 0
        
        if sections:
            # 1. Check for Virtual vs Raw Size Anomaly
            for s in sections:
                virt_size = s.Misc_VirtualSize
                raw_size = s.SizeOfRawData
                if raw_size > 0 and (virt_size / raw_size) > 5.0:
                    features["VIRTUAL_RAW_SIZE_ANOMALY"] = 1
                    break

            # 2. Entropy Calculations
            entropies = [s.get_entropy() for s in sections]

            features["AVG_SECTION_ENTROPY"] = sum(entropies) / len(entropies)
            features["MAX_SECTION_ENTROPY"] = max(entropies)
            features["MIN_SECTION_ENTROPY"] = min(entropies)

            mean = features["AVG_SECTION_ENTROPY"]
            features["SECTION_ENTROPY_STD"] = math.sqrt(
                sum((e - mean) ** 2 for e in entropies) / len(entropies)
            )

            features["NUM_HIGH_ENTROPY_SECTIONS"] = sum(e > 7.2 for e in entropies)
            features["HAS_HIGH_ENTROPY_SECTION"] = int(features["NUM_HIGH_ENTROPY_SECTIONS"] > 0)

            text_entropy = 0
            rsrc_entropy = 0

            for s in sections:
                name = s.Name.decode(errors="ignore").lower()
                if ".text" in name:
                    text_entropy = s.get_entropy()
                if ".rsrc" in name:
                    rsrc_entropy = s.get_entropy()

            features["TEXT_SECTION_ENTROPY"] = text_entropy
            features["RSRC_SECTION_ENTROPY"] = rsrc_entropy

        # =============================
        # PACKING / STRUCTURAL FEATURES
        # =============================
        features["LOW_IMPORT_COUNT"] = int(features["NUM_IMPORTS"] < 20)
        features["SMALL_IMPORT_TABLE"] = int(features["NUM_IMPORTS"] < 10)
        
        # Safe fallback if sections exist
        if sections:
            features["HIGH_ENTROPY_PACKING"] = int(features["MAX_SECTION_ENTROPY"] > 7.5)
            features["FEW_SECTIONS"] = int(len(sections) <= 3)

            # Large resource section
            rsrc_size = 0
            for s in sections:
                if ".rsrc" in s.Name.decode(errors="ignore").lower():
                    rsrc_size = s.SizeOfRawData
            features["LARGE_RESOURCE_SECTION"] = int(rsrc_size > 500000)

            # Entry point anomaly
            try:
                entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                text_section = next(
                    (s for s in sections if ".text" in s.Name.decode(errors="ignore").lower()),
                    None
                )
                if text_section:
                    start = text_section.VirtualAddress
                    end = start + text_section.Misc_VirtualSize
                    features["ENTRYPOINT_OUTSIDE_TEXT"] = int(not(start <= entry <= end))
            except:
                features["ENTRYPOINT_OUTSIDE_TEXT"] = 0

            # Suspicious section names
            suspicious = ["upx", "packed", "aspack", "mpress"]
            features["UNUSUAL_SECTION_NAMES"] = int(
                any(any(x in s.Name.decode(errors="ignore").lower() for x in suspicious)
                    for s in sections)
            )
        else:
            features["HIGH_ENTROPY_PACKING"] = 0
            features["FEW_SECTIONS"] = 0
            features["LARGE_RESOURCE_SECTION"] = 0
            features["ENTRYPOINT_OUTSIDE_TEXT"] = 0
            features["UNUSUAL_SECTION_NAMES"] = 0

    else:
        # SAFE DEFAULTS IF NOT PE
        features["NUM_IMPORTS"] = 0
        features["IS_GUI_APP"] = 0
        features["IS_CONSOLE_APP"] = 0
        features["HAS_OVERLAY"] = 0
        features["VIRTUAL_RAW_SIZE_ANOMALY"] = 0

    # =============================
    # REGISTRY HEURISTICS
    # =============================
    features["REG_AUTORUN_MOD"] = int("run\\" in joined)
    features["REG_SERVICE_CREATE_DELETE"] = int("service" in joined)
    features["REG_SERVICE_START_STOP"] = int("startservice" in joined)
    features["REG_KEY_CREATE"] = int("regcreatekey" in joined)
    features["REG_KEY_DELETE"] = int("regdeletekey" in joined)
    features["REG_VALUE_SET"] = int("regsetvalue" in joined)
    features["REG_VALUE_DELETE"] = int("regdeletevalue" in joined)
    features["REG_ENUM_KEYS"] = int("regenumkey" in joined)
    features["REG_CLSID_ACTIVITY"] = int("clsid" in joined)
    features["REG_FILE_ASSOC_CHANGE"] = int(".exe\\" in joined)
    features["REG_SECURITY_POLICY"] = int("safeboot" in joined)
    features["REG_USER_PROFILE_MOD"] = int("current_user" in joined)

    # =============================
    # ANOMALY FLAGS
    # =============================
    features["ANOMALY_INDICATOR"] = int(features["FILE_ENTROPY"] > 7.5)
    features["EXCEPTION_TRIGGERED"] = int("exception" in joined)

    return dict(features)