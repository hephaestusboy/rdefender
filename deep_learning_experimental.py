import os
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from tqdm import tqdm
from torch.utils.data import Subset


# ==========================================
# CONFIGURATION
# ==========================================
MAX_SEQ_LENGTH = 250000  # Extracting the first 250KB of each file
BATCH_SIZE = 32
EPOCHS = 15

TRAIN_MALWARE_DIR = "samples/ransomware"
TRAIN_BENIGN_DIR = "samples/benign1"
TEST_MALWARE_DIR = "samples/test/ransomware"
TEST_BENIGN_DIR = "samples/test/benign"

# ==========================================
# 1. DATA PIPELINE
# ==========================================
def load_raw_bytes(filepath):
    """Reads raw bytes and pads/truncates to MAX_SEQ_LENGTH."""
    try:
        with open(filepath, 'rb') as f:
            raw = f.read(MAX_SEQ_LENGTH)
        
        byte_arr = np.frombuffer(raw, dtype=np.uint8)
        
        if len(byte_arr) < MAX_SEQ_LENGTH:
            pad_len = MAX_SEQ_LENGTH - len(byte_arr)
            byte_arr = np.pad(byte_arr, (0, pad_len), 'constant', constant_values=0)
            
        return byte_arr
    except Exception:
        return None

def process_directory(mal_dir, ben_dir, desc):
    """Loads files from specific directories."""
    mal_files = [os.path.join(mal_dir, f) for f in os.listdir(mal_dir) if os.path.isfile(os.path.join(mal_dir, f))]
    ben_files = [os.path.join(ben_dir, f) for f in os.listdir(ben_dir) if os.path.isfile(os.path.join(ben_dir, f))]
    
    all_files = [(p, 1) for p in mal_files] + [(p, 0) for p in ben_files]
    
    X, y = [], []
    for path, label in tqdm(all_files, desc=desc):
        bytes_arr = load_raw_bytes(path)
        if bytes_arr is not None:
            X.append(bytes_arr)
            y.append(label)
            
    return np.array(X), np.array(y)

class MalwareDataset(Dataset):
    """PyTorch Dataset Wrapper"""
    def __init__(self, X, y):
        # Keep X as a tiny uint8 numpy array in system RAM (Only takes ~4.5 GB)
        self.X = X 
        # y is just 0s and 1s, so it's tiny (only takes ~76 KB). Safe to convert now.
        self.y = torch.tensor(y, dtype=torch.float32).unsqueeze(1) 

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        # LAZY CONVERSION: Only convert the requested 32 files to 64-bit tensors 
        # right before handing them to the GPU. Saves 28 GB of RAM!
        x_tensor = torch.tensor(self.X[idx], dtype=torch.long)
        return x_tensor, self.y[idx]

# ==========================================
# 2. MALCONV-LITE ARCHITECTURE
# ==========================================

class MalConvLite(nn.Module):
    def __init__(self):
        super(MalConvLite, self).__init__()
        # 1. Map 256 byte values to 8-dimensional vectors
        self.embedding = nn.Embedding(num_embeddings=256, embedding_dim=8)
        
        # 2. Sweep across the byte vectors looking for patterns
        self.conv1d = nn.Conv1d(in_channels=8, out_channels=64, kernel_size=128, stride=16)
        self.relu = nn.ReLU()
        
        # 3. Dense classification layers
        self.fc1 = nn.Linear(64, 64)
        self.dropout = nn.Dropout(0.5)
        self.fc2 = nn.Linear(64, 1) # Output a single raw score (logit)

    def forward(self, x):
        x = self.embedding(x)
        # PyTorch Conv1d expects shape (batch, channels, length)
        x = x.transpose(1, 2) 
        
        x = self.conv1d(x)
        x = self.relu(x)
        
        # Global Max Pooling: Extract the strongest signal
        x, _ = torch.max(x, dim=2) 
        
        x = self.fc1(x)
        x = self.relu(x)
        x = self.dropout(x)
        x = self.fc2(x)
        return x

# ==========================================
# 3. MAIN EXECUTION & TRAINING LOOP
# ==========================================
# ==========================================
# 3. MAIN EXECUTION & TRAINING LOOP
# ==========================================

def main():
    print("=========================================================")
    print(" 🧬 PYTORCH RAW-BYTE DEEP LEARNING (MalConv-Lite)")
    print("=========================================================")

    # Setup hardware acceleration
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"⚡ Using Hardware Device: {device}\n")

    # 1. Load Data (Once, and only once)
    X_train_full, y_train_full = process_directory(TRAIN_MALWARE_DIR, TRAIN_BENIGN_DIR, "Loading Train Data")
    X_test, y_test = process_directory(TEST_MALWARE_DIR, TEST_BENIGN_DIR, "Loading Test Data ")
    
    # Wrap the full 4.8GB array in our Dataset class
    full_train_dataset = MalwareDataset(X_train_full, y_train_full)
    test_dataset = MalwareDataset(X_test, y_test)

    # 2. Zero-Copy Train/Val Split (Saves ~5GB of RAM!)
    num_train = len(full_train_dataset)
    indices = list(range(num_train))
    np.random.seed(42)
    np.random.shuffle(indices)
    
    # 15% for validation
    split = int(np.floor(0.15 * num_train))
    val_idx, train_idx = indices[:split], indices[split:]

    # Create subsets that reference the original data instead of copying it
    train_dataset = Subset(full_train_dataset, train_idx)
    val_dataset = Subset(full_train_dataset, val_idx)

    # Wrap in PyTorch DataLoaders
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

    # Free up the unneeded raw numpy references to be safe
    del X_train_full, y_train_full, X_test, y_test

    # 3. Initialize Model, Loss, and Optimizer
    model = MalConvLite().to(device)
    criterion = nn.BCEWithLogitsLoss() 
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    # 4. The Training Loop
    print("\n🚀 Training CNN on raw hexadecimal structures...")
    
    best_val_loss = float('inf')
    patience = 3
    patience_counter = 0

    for epoch in range(EPOCHS):
        # --- TRAINING PHASE ---
        model.train()
        train_loss = 0.0
        
        for batch_X, batch_y in tqdm(train_loader, desc=f"Epoch {epoch+1}/{EPOCHS} [Train]"):
            batch_X, batch_y = batch_X.to(device), batch_y.to(device)
            
            optimizer.zero_grad()           
            outputs = model(batch_X)        
            loss = criterion(outputs, batch_y) 
            loss.backward()                 
            optimizer.step()                
            
            train_loss += loss.item()

        # --- VALIDATION PHASE ---
        model.eval()
        val_loss = 0.0
        with torch.no_grad(): 
            for batch_X, batch_y in val_loader:
                batch_X, batch_y = batch_X.to(device), batch_y.to(device)
                outputs = model(batch_X)
                loss = criterion(outputs, batch_y)
                val_loss += loss.item()

        avg_train_loss = train_loss / len(train_loader)
        avg_val_loss = val_loss / len(val_loader)
        print(f"   -> Train Loss: {avg_train_loss:.4f} | Val Loss: {avg_val_loss:.4f}")

        # --- EARLY STOPPING ---
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            patience_counter = 0
            torch.save(model.state_dict(), "best_malconv.pth")
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"🛑 Early stopping triggered. Restoring best weights.")
                break

    # 5. Evaluate on True Hold-Out Test Set
    print("\n🔬 Generating Final Predictions on True Test Set...")
    model.load_state_dict(torch.load("best_malconv.pth", weights_only=True))
    model.eval()
    
    all_preds = []
    
    # Extract the actual labels from the test subset for metric calculation
    # (Since we deleted y_test to save memory, we rebuild it from the dataset)
    true_labels = [test_dataset[i][1].item() for i in range(len(test_dataset))]

    with torch.no_grad():
        for batch_X, _ in tqdm(test_loader, desc="Testing"):
            batch_X = batch_X.to(device)
            logits = model(batch_X)
            probs = torch.sigmoid(logits)
            preds = (probs > 0.5).cpu().numpy().astype(int)
            all_preds.extend(preds)

    print("\n==================== DEEP LEARNING RESULTS ====================")
    print(f"Accuracy      : {accuracy_score(true_labels, all_preds):.3f}")
    print(f"Recall        : {recall_score(true_labels, all_preds):.3f}")
    print(f"Precision     : {precision_score(true_labels, all_preds):.3f}")
    print(f"F1 Score      : {f1_score(true_labels, all_preds):.3f}")
    print("===============================================================\n")

if __name__ == "__main__":
    main()