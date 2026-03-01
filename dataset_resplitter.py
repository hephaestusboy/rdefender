import os
import shutil
import random
import warnings
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor # For multicore I/O

# ==========================================
# CONFIGURATION
# ==========================================
TRAIN_MALWARE_DIR = "samples/ransomware"
TRAIN_BENIGN_DIR = "samples/benign1"
TEST_MALWARE_DIR = "samples/test/ransomware"
TEST_BENIGN_DIR = "samples/test/benign"

TRAIN_RATIO = 0.87
RANDOM_SEED = 666    

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def gather_files(directories):
    files = []
    for d in directories:
        if os.path.exists(d):
            for root, _, filenames in os.walk(d):
                for f in filenames:
                    files.append(os.path.join(root, f))
    return files

# ==========================================
# MULTICORE MOVE LOGIC
# ==========================================
def move_single_file(file_info):
    """Worker function to move one file."""
    src, target_dir = file_info
    target_path = os.path.join(target_dir, os.path.basename(src))
    
    # Only move if it's not already in the correct directory
    if os.path.abspath(src) == os.path.abspath(target_path):
        return False

    # Handle filename collisions
    if os.path.exists(target_path):
        base, ext = os.path.splitext(target_path)
        target_path = f"{base}_{random.randint(1000, 9999)}{ext}"
    
    try:
        shutil.move(src, target_path)
        return True
    except Exception:
        return False

def parallel_move(file_list, target_dir, desc):
    """Manages the thread pool for file moves."""
    tasks = [(f, target_dir) for f in file_list]
    
    # Use ThreadPoolExecutor for I/O bound move operations
    with ThreadPoolExecutor() as executor:
        # list() forces the generator to execute, tqdm shows progress
        results = list(tqdm(executor.map(move_single_file, tasks), 
                            total=len(tasks), desc=desc, unit="file"))
    return sum(results)

def master_resplit():
    print("=========================================================")
    print(" 🔄 MULTICORE DATASET RE-SPLITTER")
    print("=========================================================")

    # 1. Ensure directories
    for d in [TRAIN_MALWARE_DIR, TRAIN_BENIGN_DIR, TEST_MALWARE_DIR, TEST_BENIGN_DIR]:
        ensure_dir(d)

    # 2. Gather files
    all_malware = gather_files([TRAIN_MALWARE_DIR, TEST_MALWARE_DIR])
    all_benign = gather_files([TRAIN_BENIGN_DIR, TEST_BENIGN_DIR])

    print(f"📦 Found {len(all_malware)} Malware & {len(all_benign)} Benign files.")

    # 3. Shuffle
    random.seed(RANDOM_SEED)
    random.shuffle(all_malware)
    random.shuffle(all_benign)

    # 4. Split
    m_idx = int(len(all_malware) * TRAIN_RATIO)
    b_idx = int(len(all_benign) * TRAIN_RATIO)

    train_mal = all_malware[:m_idx]
    test_mal  = all_malware[m_idx:]
    train_ben = all_benign[:b_idx]
    test_ben  = all_benign[b_idx:]

    # 5. Parallel Execution
    print("\n🚚 Routing files using Multicore I/O...")
    parallel_move(train_mal, TRAIN_MALWARE_DIR, "Routing Train Malware")
    parallel_move(test_mal, TEST_MALWARE_DIR, "Routing Test Malware ")
    parallel_move(train_ben, TRAIN_BENIGN_DIR, "Routing Train Benign ")
    parallel_move(test_ben, TEST_BENIGN_DIR, "Routing Test Benign  ")

    # 6. Cleanup
    print("\n🧹 Cleaning dataset caches...")
    for c in ["cached_dataset.npz", "feature_cache.pkl"]:
        if os.path.exists(c):
            os.remove(c)
            print(f"   🗑️  Deleted {c}")

    print("\n✅ RE-SPLIT COMPLETE")
    print(f"Malware: {len(train_mal)} Train / {len(test_mal)} Test")
    print(f"Benign : {len(train_ben)} Train / {len(test_ben)} Test")

if __name__ == "__main__":
    master_resplit()