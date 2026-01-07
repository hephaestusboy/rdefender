import numpy as np

# -----------------------------
# Helper: sum features safely
# -----------------------------
def sum_features(row, keys):
    return sum(row.get(k, 0) for k in keys)


def bin_feature(row, keys):
    return int(any(row.get(k, 0) for k in keys))


# -----------------------------
# Feature extractor
# -----------------------------
def extract_features(row):
    features = {}

    # === A. Process, Memory & Execution APIs (18) ===
    features["API_PROC_CREATE"] = sum_features(row, [
        "API:CreateProcessInternalW", "API:NtCreateProcessEx"
    ])

    features["API_PROC_TERMINATE"] = sum_features(row, [
        "API:NtTerminateProcess"
    ])

    features["API_THREAD_CREATE"] = sum_features(row, [
        "API:CreateThread", "API:RtlCreateUserThread"
    ])

    features["API_THREAD_SUSPEND_RESUME"] = sum_features(row, [
        "API:NtSuspendThread", "API:NtResumeThread"
    ])

    features["API_REMOTE_THREAD"] = bin_feature(row, [
        "API:CreateRemoteThread"
    ])

    features["API_PROCESS_ENUM"] = sum_features(row, [
        "API:Process32FirstW", "API:Process32NextW"
    ])

    features["API_THREAD_ENUM"] = sum_features(row, [
        "API:Thread32First", "API:Thread32Next"
    ])

    features["API_MEMORY_ALLOC"] = sum_features(row, [
        "API:NtAllocateVirtualMemory"
    ])

    features["API_MEMORY_PROTECT"] = sum_features(row, [
        "API:VirtualProtectEx", "API:NtProtectVirtualMemory"
    ])

    features["API_MEMORY_READ"] = sum_features(row, [
        "API:ReadProcessMemory", "API:NtReadVirtualMemory"
    ])

    features["API_MEMORY_WRITE"] = sum_features(row, [
        "API:WriteProcessMemory", "API:NtWriteVirtualMemory"
    ])

    features["API_SECTION_MAP"] = sum_features(row, [
        "API:NtMapViewOfSection"
    ])

    features["API_SECTION_UNMAP"] = sum_features(row, [
        "API:NtUnmapViewOfSection"
    ])

    features["API_DLL_LOAD"] = sum_features(row, [
        "API:LdrLoadDll"
    ])

    features["API_DLL_UNLOAD"] = sum_features(row, [
        "API:LdrUnloadDll"
    ])

    features["API_GET_PROC_ADDR"] = sum_features(row, [
        "API:LdrGetProcedureAddress"
    ])

    features["API_EXCEPTION_HANDLER"] = sum_features(row, [
        "API:SetUnhandledExceptionFilter",
        "API:RtlAddVectoredExceptionHandler"
    ])

    features["API_CONTEXT_MANIPULATION"] = sum_features(row, [
        "API:NtGetContextThread", "API:NtSetContextThread"
    ])

    # === B. Cryptography & Encoding APIs (10) ===
    features["API_CRYPTO_CONTEXT"] = sum_features(row, [
        "API:CryptAcquireContextA", "API:CryptAcquireContextW"
    ])

    features["API_CRYPTO_KEY_GEN"] = sum_features(row, [
        "API:CryptGenKey"
    ])

    features["API_CRYPTO_KEY_EXPORT"] = sum_features(row, [
        "API:CryptExportKey"
    ])

    features["API_CRYPTO_HASH"] = sum_features(row, [
        "API:CryptCreateHash", "API:CryptHashData"
    ])

    features["API_CRYPTO_ENCRYPT"] = sum_features(row, [
        "API:CryptEncrypt"
    ])

    features["API_CRYPTO_DECRYPT"] = sum_features(row, [
        "API:CryptDecodeObjectEx"
    ])

    features["API_CERT_OPEN_STORE"] = sum_features(row, [
        "API:CertOpenStore"
    ])

    features["API_CERT_CONTROL"] = sum_features(row, [
        "API:CertControlStore"
    ])

    features["API_CERT_SYSTEM_STORE"] = sum_features(row, [
        "API:CertOpenSystemStoreA", "API:CertOpenSystemStoreW"
    ])

    features["API_DATA_DECOMPRESSION"] = sum_features(row, [
        "API:RtlDecompressBuffer"
    ])

    # === C. File System APIs (12) ===
    features["API_FILE_CREATE"] = sum_features(row, [
        "API:NtCreateFile"
    ])

    features["API_FILE_OPEN"] = sum_features(row, [
        "API:NtOpenFile"
    ])

    features["API_FILE_READ"] = sum_features(row, [
        "API:NtReadFile"
    ])

    features["API_FILE_WRITE"] = sum_features(row, [
        "API:NtWriteFile"
    ])

    features["API_FILE_DELETE"] = sum_features(row, [
        "API:NtDeleteFile", "API:DeleteFileW"
    ])

    features["API_FILE_RENAME"] = sum_features(row, [
        "API:SetFilePointer", "API:SetFilePointerEx"
    ])

    features["API_FILE_ATTRIBUTES"] = sum_features(row, [
        "API:GetFileAttributesW", "API:SetFileAttributesW"
    ])

    features["API_FILE_SIZE_QUERY"] = sum_features(row, [
        "API:GetFileSize", "API:GetFileSizeEx"
    ])

    features["API_DIRECTORY_ENUM"] = sum_features(row, [
        "API:FindFirstFileExA", "API:FindFirstFileExW"
    ])

    features["API_DIRECTORY_CREATE"] = sum_features(row, [
        "API:CreateDirectoryW"
    ])

    features["API_DIRECTORY_DELETE"] = sum_features(row, [
        "API:RemoveDirectoryA", "API:RemoveDirectoryW"
    ])

    features["API_TEMP_PATH_ACCESS"] = sum_features(row, [
        "API:GetTempPathW"
    ])

    # === D. Network APIs (10) ===
    features["API_SOCKET_CREATE"] = sum_features(row, [
        "API:socket", "API:WSASocketA", "API:WSASocketW"
    ])

    features["API_SOCKET_CONNECT"] = sum_features(row, [
        "API:connect"
    ])

    features["API_SOCKET_BIND_LISTEN"] = sum_features(row, [
        "API:bind", "API:listen"
    ])

    features["API_SOCKET_SEND"] = sum_features(row, [
        "API:send", "API:WSASend"
    ])

    features["API_SOCKET_RECV"] = sum_features(row, [
        "API:recv", "API:WSARecv"
    ])

    features["API_SOCKET_CLOSE"] = sum_features(row, [
        "API:closesocket"
    ])

    features["API_DNS_QUERY"] = sum_features(row, [
        "API:DnsQuery_W", "API:gethostbyname", "API:getaddrinfo"
    ])

    features["API_HTTP_OPEN"] = sum_features(row, [
        "API:InternetOpenA", "API:InternetOpenW"
    ])

    features["API_HTTP_REQUEST"] = sum_features(row, [
        "API:HttpOpenRequestA", "API:HttpOpenRequestW",
        "API:HttpSendRequestA", "API:HttpSendRequestW"
    ])

    features["API_HTTP_STATUS_QUERY"] = sum_features(row, [
        "API:InternetQueryOptionA"
    ])

    # === E. Anti-analysis (6) ===
    features["API_DEBUG_DETECTION"] = bin_feature(row, [
        "API:IsDebuggerPresent"
    ])

    features["API_DELAY_EXECUTION"] = sum_features(row, [
        "API:NtDelayExecution"
    ])

    features["API_KEYBOARD_STATE"] = sum_features(row, [
        "API:GetAsyncKeyState", "API:GetKeyState"
    ])

    features["API_WINDOW_ENUMERATION"] = sum_features(row, [
        "API:EnumWindows", "API:FindWindowA", "API:FindWindowW"
    ])

    features["API_HOOK_INSTALL"] = sum_features(row, [
        "API:SetWindowsHookExA", "API:SetWindowsHookExW"
    ])

    features["API_ERROR_MODE_CONTROL"] = sum_features(row, [
        "API:SetErrorMode"
    ])

    # === F. Registry (12) ===
    features["REG_AUTORUN_MOD"] = bin_feature(row, [
        "REG:DELETED:HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "REG:DELETED:HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    ])

    features["REG_SERVICE_CREATE_DELETE"] = bin_feature(row, [
        "API:CreateServiceA", "API:CreateServiceW", "API:DeleteService"
    ])

    features["REG_SERVICE_START_STOP"] = bin_feature(row, [
        "API:StartServiceW", "API:ControlService"
    ])

    features["REG_KEY_CREATE"] = bin_feature(row, [
        "API:RegCreateKeyExA", "API:RegCreateKeyExW"
    ])

    features["REG_KEY_DELETE"] = bin_feature(row, [
        "API:RegDeleteKeyA", "API:RegDeleteKeyW"
    ])

    features["REG_VALUE_SET"] = bin_feature(row, [
        "API:RegSetValueExA", "API:RegSetValueExW"
    ])

    features["REG_VALUE_DELETE"] = bin_feature(row, [
        "API:RegDeleteValueA", "API:RegDeleteValueW"
    ])

    features["REG_ENUM_KEYS"] = bin_feature(row, [
        "API:RegEnumKeyExA", "API:RegEnumKeyExW"
    ])

    features["REG_CLSID_ACTIVITY"] = bin_feature(row, [
        "REG:DELETED:HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\"
    ])

    features["REG_FILE_ASSOC_CHANGE"] = bin_feature(row, [
        "REG:DELETED:HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\."
    ])

    features["REG_SECURITY_POLICY"] = bin_feature(row, [
        "REG:DELETED:HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\SafeBoot"
    ])

    features["REG_USER_PROFILE_MOD"] = bin_feature(row, [
        "REG:DELETED:HKEY_CURRENT_USER\\Software"
    ])

    # === G. DROP groups (10) ===
    features["DROP_EXECUTABLE_FILES"] = bin_feature(row, [
        "DROP:exe", "DROP:Exe", "DROP:dll", "DROP:sys"
    ])

    features["DROP_ENCRYPTED_EXTENSIONS"] = bin_feature(row, [
        "DROP:encrypted", "DROP:toxcrypt"
    ])

    features["DROP_ARCHIVES"] = bin_feature(row, [
        "DROP:zip", "DROP:rar", "DROP:7z"
    ])

    features["DROP_DOCUMENT_FILES"] = bin_feature(row, [
        "DROP:doc", "DROP:pdf", "DROP:xls"
    ])

    features["DROP_MEDIA_FILES"] = bin_feature(row, [
        "DROP:jpg", "DROP:png", "DROP:mp3"
    ])

    features["DROP_SCRIPT_FILES"] = bin_feature(row, [
        "DROP:js", "DROP:vbs", "DROP:bat"
    ])

    features["DROP_LIBRARY_FILES"] = bin_feature(row, [
        "DROP:dll", "DROP:ocx"
    ])

    features["DROP_CONFIG_FILES"] = bin_feature(row, [
        "DROP:ini", "DROP:cfg"
    ])

    features["DROP_TEMP_FILES"] = bin_feature(row, [
        "DROP:tmp", "DROP:dat"
    ])

    features["DROP_RANDOM_NAMED_FILES"] = bin_feature(row, [
        "DROP:{cc46080e-4c33-4981-859a-bba2f780f31e}"
    ])

    # === H. System info (6) ===
    features["API_SYSTEM_INFO"] = sum_features(row, [
        "API:GetSystemInfo", "API:GetNativeSystemInfo"
    ])

    features["API_DISK_SPACE_QUERY"] = sum_features(row, [
        "API:GetDiskFreeSpaceW", "API:GetDiskFreeSpaceExW"
    ])

    features["API_VOLUME_ENUM"] = sum_features(row, [
        "API:GetVolumePathNameW"
    ])

    features["API_ADAPTER_INFO"] = sum_features(row, [
        "API:GetAdaptersInfo", "API:GetAdaptersAddresses"
    ])

    features["API_USERNAME_QUERY"] = sum_features(row, [
        "API:GetUserNameA", "API:GetUserNameW"
    ])

    features["API_COMPUTER_NAME_QUERY"] = sum_features(row, [
        "API:GetComputerNameA", "API:GetComputerNameW"
    ])

    # === I. Anomaly flags (2) ===
    features["ANOMALY_INDICATOR"] = row.get("API:__anomaly__", 0)
    features["EXCEPTION_TRIGGERED"] = row.get("API:__exception__", 0)

    return features
