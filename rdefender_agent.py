import os
import sys
import time
import stat
import shutil
import warnings
import logging
import base64
import json
import hashlib
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- THE ABSOLUTE NUCLEAR OPTION FOR WARNINGS ---
os.environ["PYTHONWARNINGS"] = "ignore"
os.environ["LOKY_MAX_CPU_COUNT"] = "1"
os.environ["JOBLIB_MULTIPROCESSING"] = "0"

# Forcefully mute all warnings globally before sklearn imports
warnings.filterwarnings("ignore")
warnings.simplefilter(action='ignore', category=UserWarning)
warnings.simplefilter(action='ignore', category=FutureWarning)

# Mute standard loggers
logging.getLogger('joblib').setLevel(logging.ERROR)


# --- CRITICAL CPU FIX: STOP C++ BACKEND MULTITHREADING & SPAM ---
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"
os.environ["LOKY_MAX_CPU_COUNT"] = "1" # Stops Joblib loky backend errors
os.environ["JOBLIB_MULTIPROCESSING"] = "0"

# Silence background noise aggressively
warnings.filterwarnings("ignore")
os.environ["PYTHONWARNINGS"] = "ignore"
import logging
logging.getLogger('joblib').setLevel(logging.ERROR) # Mute Scikit-Learn Parallel spam

import joblib
import numpy as np

# User Custom Modules
from static_feature_extractor import extract_features_from_binary
from feature_vectorizer import vectorize_features
from model_feature_groups import MODEL1_INDICES, MODEL2_INDICES
from feature_schema import FEATURE_SCHEMA

# ==========================================
# CONFIGURATION
# ==========================================
LOG_FILE = "rdefender_events.log"
QUARANTINE_ROOT = "C:\\RDefender_Quarantine"
QUARANTINE_MALWARE = os.path.join(QUARANTINE_ROOT, "Malware")
QUARANTINE_SUSPICIOUS = os.path.join(QUARANTINE_ROOT, "Suspicious")
TARGET_WATCH_DIR = "C:\\" # Change this to the folder you want to monitor

MALWARE_THRESHOLD = 0.65       
SUSPICIOUS_THRESHOLD = 0.30    
SUPPORTED_EXTENSIONS = (".exe", ".sys", ".dll") 

SILVER_BULLETS = [
    "IS_SIGNATURE_VALID", 
    "SHADOW_COPY_DELETION_STRINGS", 
    "VIRTUAL_RAW_SIZE_ANOMALY", 
    "FILE_ENTROPY"
]
SILVER_INDICES = [FEATURE_SCHEMA.index(f) for f in SILVER_BULLETS]

# ==========================================
# QUARANTINE SYSTEM
# ==========================================

QUARANTINE_METADATA_FILE = os.path.join(QUARANTINE_ROOT, "metadata.json")

def load_quarantine_metadata():
    """Load metadata mapping from JSON file."""
    if os.path.exists(QUARANTINE_METADATA_FILE):
        try:
            with open(QUARANTINE_METADATA_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_quarantine_metadata(metadata):
    """Save metadata mapping to JSON file."""
    os.makedirs(QUARANTINE_ROOT, exist_ok=True)
    try:
        with open(QUARANTINE_METADATA_FILE, 'w') as f:
            json.dump(metadata, f, indent=2)
    except:
        pass

def encode_original_path(filepath):
    """Encode original filepath in base64 for storage in metadata."""
    return base64.b64encode(filepath.encode()).decode()

def decode_original_path(encoded):
    """Decode original filepath from metadata."""
    try:
        return base64.b64decode(encoded.encode()).decode()
    except:
        return None

def quarantine_file(filepath, label):
    """Safely moves files into designated folders based on severity."""
    max_retries = 8
    retry_delay = 1.5

    # Determine which vault to use
    target_dir = QUARANTINE_MALWARE if label == "MALWARE" else QUARANTINE_SUSPICIOUS

    try:
        # EXIST_OK=TRUE prevents crashes when multiple threads try to make the folder at once
        os.makedirs(target_dir, exist_ok=True)
        os.makedirs(QUARANTINE_ROOT, exist_ok=True)

        filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f") # Added microsecond for concurrent safety
        
        # Use short filename: original_name.timestamp.quarantine
        safe_filename = f"{os.path.splitext(filename)[0]}.{timestamp}.quarantine"
        quarantine_path = os.path.join(target_dir, safe_filename)

        # --- THE RETRY LOOP ---
        for attempt in range(max_retries):
            try:
                shutil.move(filepath, quarantine_path)
                print(f"\033[91m🛡️  ACTION: {filename} moved to {label} vault!\033[0m")
                
                # Store original path in metadata
                metadata = load_quarantine_metadata()
                metadata[safe_filename] = {
                    "original_path": filepath,
                    "timestamp": timestamp,
                    "severity": label
                }
                save_quarantine_metadata(metadata)
                
                return quarantine_path
            except PermissionError:
                print(f"\033[93m⚠️  File locked, retrying quarantine (Attempt {attempt+1}/{max_retries})...\033[0m")
                time.sleep(retry_delay)

        # --- IF MOVE FAILS ---
        print("\033[93m⚠️  Attempting active file permission lockdown...\033[0m")
        try:
            os.chmod(filepath, stat.S_IREAD | stat.S_IWRITE)
            os.chmod(filepath, 0)
            return "LOCKED_BUT_DEFANGED"
        except Exception as chmod_err:
             return None

    except Exception as e:
        print(f"\033[95m❌ QUARANTINE ERROR: {str(e)}\033[0m")
        return None

# ==========================================
# MACHINE LEARNING ENGINE
# ==========================================
class MLScannerEngine:
    """Loads models once into RAM and handles the math for live files."""
    def __init__(self):
        print("🧠 Loading R-Defender ML Engine into RAM...")
        
        # Handle PyInstaller bundle path
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
        
        self.models = {
            "rf_behav": joblib.load(os.path.join(base_path, "rf_behavior_model.joblib")),
            "rf_art": joblib.load(os.path.join(base_path, "rf_artifact_model.joblib")),
            "xgb_behav": joblib.load(os.path.join(base_path, "xgb_behavior_model.joblib")),
            "xgb_art": joblib.load(os.path.join(base_path, "xgb_artifact_model.joblib")),
            "fusion": joblib.load(os.path.join(base_path, "fusion_model.joblib")),
        }
        print("✅ Models loaded successfully.")

    def build_fusion_features(self, p_rf_b, p_rf_a, p_xgb_b, p_xgb_a, raw_vec):
        probs = np.array([p_rf_b, p_rf_a, p_xgb_b, p_xgb_a])
        avg_behavior = (p_rf_b + p_xgb_b) / 2
        avg_artifact = (p_rf_a + p_xgb_a) / 2
        disagreement = abs(avg_behavior - avg_artifact)
        prob_entropy = -(probs * np.log(probs + 1e-9) + (1 - probs) * np.log(1 - probs + 1e-9)).mean()

        high_artifact_stealth = 1.0 if (avg_artifact > 0.7 and avg_behavior < 0.2) else 0.0
        high_behavior_stealth = 1.0 if (avg_behavior > 0.7 and avg_artifact < 0.2) else 0.0
        joint_conf = avg_artifact * avg_behavior

        rf_diff = p_rf_a - p_rf_b
        xgb_diff = p_xgb_a - p_xgb_b
        max_sig = np.max(probs)
        min_sig = np.min(probs)
        
        raw_silver = np.array(raw_vec)[SILVER_INDICES]

        return np.array([[
            p_rf_b, p_rf_a, p_xgb_b, p_xgb_a,            
            avg_behavior, avg_artifact,                  
            disagreement, prob_entropy,                  
            high_artifact_stealth, high_behavior_stealth,                       
            joint_conf, rf_diff, xgb_diff,                            
            max_sig, min_sig,                            
            raw_silver[0], raw_silver[1],                
            raw_silver[2], raw_silver[3]                 
        ]])

    def scan_file(self, filepath):
        """Attempts to scan the file. Includes retry logic for Windows file locks."""
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                feats = extract_features_from_binary(filepath)
                
                raw_shadow = feats.get("SHADOW_COPY_DELETION_STRINGS", 0)
                raw_entropy = feats.get("FILE_ENTROPY", 0.0)
                raw_anomaly = feats.get("VIRTUAL_RAW_SIZE_ANOMALY", 0)
                raw_signed = feats.get("IS_SIGNATURE_VALID", 0) 
                
                raw_vec = vectorize_features(feats)
                vec_np = np.array(raw_vec)
                
                vec1 = vec_np[MODEL1_INDICES].reshape(1, -1)
                vec2 = vec_np[MODEL2_INDICES].reshape(1, -1)
                
                # FORCE Scikit-Learn to use a single thread for inference so it doesn't fight our UI Queue


                # FORCE Scikit-Learn to use a single thread and SILENCE the UserWarnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore") # Mutes all warnings inside this block
                    with joblib.parallel_backend('threading', n_jobs=1):
                        pb_rf = self.models["rf_behav"].predict_proba(vec1)[0][1]
                        pa_rf = self.models["rf_art"].predict_proba(vec2)[0][1]
                        pb_xgb = self.models["xgb_behav"].predict_proba(vec1)[0][1]
                        pa_xgb = self.models["xgb_art"].predict_proba(vec2)[0][1]
                        
                        fusion_in = self.build_fusion_features(pb_rf, pa_rf, pb_xgb, pa_xgb, raw_vec)
                        final_prob = self.models["fusion"].predict_proba(fusion_in)[0][1]

                if final_prob >= MALWARE_THRESHOLD: 
                    label = "MALWARE"
                else:
                    extreme_artifact = (pa_xgb > 0.85) and ((pb_rf + pb_xgb)/2 < 0.20) and raw_signed == 0
                    consensus_suspicion = (pb_rf > 0.40 and pa_rf > 0.40 and pb_xgb > 0.40 and pa_xgb > 0.40)
                    
                    if raw_shadow == 1 or extreme_artifact or consensus_suspicion:
                        label = "MALWARE"
                        final_prob = max(final_prob, 0.70) 
                    elif final_prob >= SUSPICIOUS_THRESHOLD: 
                        label = "SUSPICIOUS"
                    else:
                        label = "CLEAN"

                if label == "MALWARE":
                    if raw_signed == 1 and final_prob < 0.98:
                        label = "SUSPICIOUS" 
                    elif raw_entropy > 6.8 and raw_shadow == 0 and final_prob < 0.95:
                        label = "SUSPICIOUS"

                return label, final_prob

            except PermissionError:
                time.sleep(0.2)
            except Exception as e:
                return "ERROR", str(e)
                
        return "ERROR", "File locked by another process after 3 retries."