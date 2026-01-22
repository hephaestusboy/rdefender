import pefile
import os
import math
import re
from collections import Counter, defaultdict

SUPPORTED_EXTENSIONS = (".exe", ".dll", ".sys", ".bin")

# =============================
# Utility functions
# =============================

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
# API GROUP DEFINITIONS
# =============================

API_GROUPS = {
    # A. Process & Memory
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

    # B. Crypto
    "API_CRYPTO_CONTEXT": ["CryptAcquireContext"],
    "API_CRYPTO_KEY_GEN": ["CryptGenKey"],
    "API_CRYPTO_KEY_EXPORT": ["CryptExportKey"],
    "API_CRYPTO_HASH": ["CryptCreateHash", "CryptHashData"],
    "API_CRYPTO_ENCRYPT": ["CryptEncrypt"],
    "API_CRYPTO_DECRYPT": ["CryptDecrypt", "CryptDecodeObject"],
    "API_CERT_OPEN_STORE": ["CertOpenStore"],
    "API_CERT_CONTROL": ["CertControlStore"],
    "API_CERT_SYSTEM_STORE": ["CertOpenSystemStore"],
    "API_DATA_DECOMPRESSION": ["RtlDecompressBuffer"],

    # C. File system
    "API_FILE_CREATE": ["NtCreateFile", "CreateFile"],
    "API_FILE_OPEN": ["NtOpenFile"],
    "API_FILE_READ": ["NtReadFile", "ReadFile"],
    "API_FILE_WRITE": ["NtWriteFile", "WriteFile"],
    "API_FILE_DELETE": ["NtDeleteFile", "DeleteFile"],
    "API_FILE_RENAME": ["MoveFile", "SetFilePointer"],
    "API_FILE_ATTRIBUTES": ["GetFileAttributes", "SetFileAttributes"],
    "API_FILE_SIZE_QUERY": ["GetFileSize"],
    "API_DIRECTORY_ENUM": ["FindFirstFile"],
    "API_DIRECTORY_CREATE": ["CreateDirectory"],
    "API_DIRECTORY_DELETE": ["RemoveDirectory"],
    "API_TEMP_PATH_ACCESS": ["GetTempPath"],

    # D. Network
    "API_SOCKET_CREATE": ["socket", "WSASocket"],
    "API_SOCKET_CONNECT": ["connect"],
    "API_SOCKET_BIND_LISTEN": ["bind", "listen"],
    "API_SOCKET_SEND": ["send", "WSASend"],
    "API_SOCKET_RECV": ["recv", "WSARecv"],
    "API_SOCKET_CLOSE": ["closesocket"],
    "API_DNS_QUERY": ["DnsQuery", "gethostbyname", "getaddrinfo"],
    "API_HTTP_OPEN": ["InternetOpen"],
    "API_HTTP_REQUEST": ["HttpOpenRequest", "HttpSendRequest"],
    "API_HTTP_STATUS_QUERY": ["InternetQueryOption"],

    # E. Anti-analysis
    "API_DEBUG_DETECTION": ["IsDebuggerPresent"],
    "API_DELAY_EXECUTION": ["NtDelayExecution", "Sleep"],
    "API_KEYBOARD_STATE": ["GetAsyncKeyState", "GetKeyState"],
    "API_WINDOW_ENUMERATION": ["EnumWindows", "FindWindow"],
    "API_HOOK_INSTALL": ["SetWindowsHookEx"],
    "API_ERROR_MODE_CONTROL": ["SetErrorMode"],

    # H. System
    "API_SYSTEM_INFO": ["GetSystemInfo", "GetNativeSystemInfo"],
    "API_DISK_SPACE_QUERY": ["GetDiskFreeSpace"],
    "API_VOLUME_ENUM": ["GetVolumePath"],
    "API_ADAPTER_INFO": ["GetAdaptersInfo", "GetAdaptersAddresses"],
    "API_USERNAME_QUERY": ["GetUserName"],
    "API_COMPUTER_NAME_QUERY": ["GetComputerName"],
}

# =============================
# DROP GROUPS (bin included)
# =============================

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
# MAIN FEATURE EXTRACTION
# =============================

def extract_features_from_binary(filepath):
    # --- PE magic check ---
    try:
        with open(filepath, "rb") as f:
            magic = f.read(2)
    except Exception as e:
        raise ValueError(f"Cannot read file: {filepath} ({e})")

    if magic != b"MZ":
        ext = os.path.splitext(filepath)[1].lower()
        raise ValueError(f"Not a PE file: {filepath} (ext={ext})")

    features = defaultdict(int)


    # ---- RAW BINARY ----
    with open(filepath, "rb") as f:
        data = f.read()

    #features["FILE_SIZE"] = len(data)
    features["FILE_ENTROPY"] = shannon_entropy(data)

    strings = extract_strings(filepath)
    joined = " ".join(strings).lower()

    # ---- DROP FEATURES ----
    for fname, patterns in DROP_GROUPS.items():
        features[fname] = int(any(p in joined for p in patterns))

    # ---- PE FEATURES (only if valid PE) ----
    pe = safe_pe_load(filepath)
    if pe:
        imports = extract_imports(pe)
        imports_lower = [i.lower() for i in imports]
        features["NUM_IMPORTS"] = len(imports)
        for fname, apis in API_GROUPS.items():
            features[fname] = int(any(
                api.lower() in imp
                for api in apis
                for imp in imports_lower
            ))

        sections = pe.sections
        #features["NUM_SECTIONS"] = len(sections)
        features["AVG_SECTION_ENTROPY"] = (
            sum(s.get_entropy() for s in sections) / max(1, len(sections))
        )
        features["HAS_HIGH_ENTROPY_SECTION"] = int(
            any(s.get_entropy() > 7.2 for s in sections)
        )

    else:
        # ---- BIN fallback (safe defaults) ----
        #features["NUM_SECTIONS"] = 0
        features["AVG_SECTION_ENTROPY"] = 0.0
        features["HAS_HIGH_ENTROPY_SECTION"] = int(features["FILE_ENTROPY"] > 7.5)
        features["NUM_IMPORTS"] = 0


    # ---- Registry heuristics ----
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
    features["REG_USER_PROFILE_MOD"] = int("current_uaser" in joined)

    # ---- Anomaly flags ----
    features["ANOMALY_INDICATOR"] = int(features["FILE_ENTROPY"] > 7.5)
    features["EXCEPTION_TRIGGERED"] = int("exception" in joined)

    return dict(features)


# =============================
# Example
# =============================

if __name__ == "__main__":
    sample = "Ransomware.Petya/4c1dc737915d76b7ce579abddaba74ead6fdb5b519a1ea45308b8c49b950655c.bin"  # exe / dll / sys / bin
    feats = extract_features_from_binary(sample)
    for k in sorted(feats.keys()):
        print(f"{k}: {feats[k]}")
