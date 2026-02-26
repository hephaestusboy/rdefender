FEATURE_SCHEMA = [
    # --- A1. Structural Statistic Indicators ---
    "NUM_IMPORTS",
    "FILE_ENTROPY",
    "AVG_SECTION_ENTROPY",
    "HAS_HIGH_ENTROPY_SECTION",

    # --- B. Anti-Analysis ---
    "API_DEBUG_DETECTION",
    "API_DELAY_EXECUTION",
    "API_KEYBOARD_STATE",
    "API_WINDOW_ENUMERATION",
    "API_HOOK_INSTALL",
    "API_ERROR_MODE_CONTROL",

    # --- C. System Context ---
    "API_SYSTEM_INFO",
    "API_DISK_SPACE_QUERY",
    "API_VOLUME_ENUM",
    "API_ADAPTER_INFO",
    "API_USERNAME_QUERY",
    "API_COMPUTER_NAME_QUERY",

    # --- D. Benign File Activity Indicators ---
    "API_FILE_OPEN",
    "API_FILE_READ",
    "API_DIRECTORY_ENUM",
    "API_FILE_ATTRIBUTES",

    # --- E. Network Context Indicators ---
    "API_DNS_QUERY",
    "API_SOCKET_RECV",
    "API_HTTP_STATUS_QUER",

    # --- F. Anomaly Flags ---
    "ANOMALY_INDICATOR",
    "EXCEPTION_TRIGGERED",
]
