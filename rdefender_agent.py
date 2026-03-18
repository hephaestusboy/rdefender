import os
import sys
import time
import shutil
import warnings
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- CRITICAL CPU FIX: STOP C++ BACKEND MULTITHREADING ---
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

# Silence background noise
warnings.filterwarnings("ignore", category=UserWarning)
os.environ["PYTHONWARNINGS"] = "ignore"

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
QUARANTINE_DIR = "C:\\RDefender_Quarantine"
TARGET_WATCH_DIR = "C:\\Users\\Public\\Downloads" # Change this to the folder you want to monitor

MALWARE_THRESHOLD = 0.65       
SUSPICIOUS_THRESHOLD = 0.30    
SUPPORTED_EXTENSIONS = (".exe", ".sys", ".bin", ".dll") 

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
def quarantine_file(filepath):
    """Safely moves and defangs malicious files."""
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)
            
        filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Defang the file by changing its extension so Windows can't run it
        safe_filename = f"{filename}.{timestamp}.quarantine"
        quarantine_path = os.path.join(QUARANTINE_DIR, safe_filename)
        
        # Move the file out of the user's reach
        shutil.move(filepath, quarantine_path)
        
        print(f"\033[91m🛡️  ACTION TAKEN: {filename} has been securely quarantined!\033[0m")
        return quarantine_path
        
    except PermissionError:
        print(f"\033[93m⚠️  QUARANTINE FAILED: {filepath} is locked by another process.\033[0m")
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
        self.models = {
            "rf_behav": joblib.load("rf_behavior_model.joblib"),
            "rf_art": joblib.load("rf_artifact_model.joblib"),
            "xgb_behav": joblib.load("xgb_behavior_model.joblib"),
            "xgb_art": joblib.load("xgb_artifact_model.joblib"),
            "fusion": joblib.load("fusion_model.joblib"),
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
                time.sleep(0.5)
            except Exception as e:
                return "ERROR", str(e)
                
        return "ERROR", "File locked by another process after 3 retries."

# ==========================================
# FILE SYSTEM WATCHDOG
# ==========================================
class RDefenderHandler(FileSystemEventHandler):
    def __init__(self, scanner_engine):
        self.scanner = scanner_engine

    def log_event(self, event_type, path, label="INFO", score=0.0):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if label == "MALWARE":
            color_prefix = "\033[91m🚨 "
        elif label == "SUSPICIOUS":
            color_prefix = "\033[93m⚠️  "
        elif label == "CLEAN":
            color_prefix = "\033[92m✅ "
        else:
            color_prefix = "\033[90m"   

        filename = os.path.basename(path)
        
        if label in ["MALWARE", "SUSPICIOUS", "CLEAN"]:
            message = f"{color_prefix}[{label}] {filename} ({score*100:.1f}%) \033[0m"
            log_msg = f"{timestamp} | {label} | {score:.4f} | {path}"
        else:
            message = f"{color_prefix}[{event_type}] {filename} \033[0m"
            log_msg = f"{timestamp} | {event_type} | N/A | {path}"

        print(message)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_msg + "\n")

    def on_created(self, event):
        if event.is_directory:
            return
            
        filepath = event.src_path
        
        if LOG_FILE.lower() in filepath.lower():
            return
        if not filepath.lower().endswith(SUPPORTED_EXTENSIONS):
            return

        self.log_event("SCANNING...", filepath)
        label, score_or_err = self.scanner.scan_file(filepath)
        
        if label == "ERROR":
            print(f"\033[95m❌ [ERROR] {os.path.basename(filepath)}: {score_or_err}\033[0m")
        else:
            self.log_event("SCANNED", filepath, label, score_or_err)
            
            # 🛡️ THE QUARANTINE TRIGGER
            if label == "MALWARE":
                quarantine_file(filepath)

# ==========================================
# MAIN EXECUTION
# ==========================================
def main():
    print("==================================================")
    print("🔥 R-Defender Live Agent Starting...")
    print("==================================================")

    scanner = MLScannerEngine()
    
    event_handler = RDefenderHandler(scanner)
    observer = Observer()

    if os.path.exists(TARGET_WATCH_DIR):
        print(f"👀 Monitoring active on: {TARGET_WATCH_DIR}")
        observer.schedule(event_handler, TARGET_WATCH_DIR, recursive=True)
        observer.start()
    else:
        print(f"❌ Target path not found: {TARGET_WATCH_DIR}")
        print(f"Please create the folder or change TARGET_WATCH_DIR in the script.")
        return

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping agent...")
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()