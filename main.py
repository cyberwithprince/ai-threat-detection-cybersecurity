import os
import sys
import subprocess
import venv
import platform

# 1. Check Python version
MIN_VERSION = (3, 11)
MAX_VERSION = (3, 12)
def check_python_version():
    version = sys.version_info
    if not (version.major == 3 and MIN_VERSION <= (version.major, version.minor) < MAX_VERSION):
        print(f"[ERROR] Python 3.11.x is required (>=3.11,<3.12). Current: {platform.python_version()}")
        sys.exit(1)
    print(f"[INFO] Python version OK: {platform.python_version()}")

# 2. Create virtual environment if not exists
def create_venv():
    venv_dir = "venv"
    if not os.path.exists(venv_dir):
        print("[INFO] Creating virtual environment...")
        venv.create(venv_dir, with_pip=True)
    else:
        print("[INFO] Virtual environment already exists.")
    return venv_dir

# Check if venv is valid (has python and pip)
def is_venv_valid(venv_dir):
    python_path = os.path.join(venv_dir, "Scripts", "python.exe") if os.name == "nt" else os.path.join(venv_dir, "bin", "python")
    pip_path = os.path.join(venv_dir, "Scripts", "pip.exe") if os.name == "nt" else os.path.join(venv_dir, "bin", "pip")
    return os.path.exists(python_path) and os.path.exists(pip_path)

# 3. Install requirements
def install_requirements(venv_dir):
    pip_path = os.path.join(venv_dir, "Scripts", "pip.exe") if os.name == "nt" else os.path.join(venv_dir, "bin", "pip")
    python_path = os.path.join(venv_dir, "Scripts", "python.exe") if os.name == "nt" else os.path.join(venv_dir, "bin", "python")
    print("[INFO] Installing requirements...")
    # Upgrade pip using python -m pip
    subprocess.check_call([python_path, "-m", "pip", "install", "--upgrade", "pip"])
    subprocess.check_call([pip_path, "install", "-r", "requirements.txt"])

# Check if required libraries are installed
def check_libraries(venv_dir):
    python_path = os.path.join(venv_dir, "Scripts", "python.exe") if os.name == "nt" else os.path.join(venv_dir, "bin", "python")
    try:
        subprocess.check_call([python_path, "-c", "import flask, xgboost, joblib, jupyter, scapy, shap"])
        print("[INFO] Required libraries are installed.")
        return True
    except subprocess.CalledProcessError:
        print("[ERROR] Required libraries are missing. Please check requirements.txt and re-install.")
        return False

# Check if model files exist
def check_models():
    model_files = [
        os.path.join("model", "xgboost_classifier.pkl"),
        os.path.join("model", "xgboost_attack_cat.pkl"),
        os.path.join("model", "scaler.pkl"),
        os.path.join("model", "attack_cat_encoder.pkl")
    ]
    missing = [f for f in model_files if not os.path.exists(f)]
    if missing:
        print("[ERROR] Missing model files:")
        for f in missing:
            print(f"  - {f}")
        return False
    print("[INFO] All required model files are present.")
    return True
# 4. Run the notebook (model_training_and_evaluation.ipynb)
def run_notebook(venv_dir):
    python_path = os.path.join(venv_dir, "Scripts", "python.exe") if os.name == "nt" else os.path.join(venv_dir, "bin", "python")
    print("[INFO] Running model_training_and_evaluation.ipynb...")
    subprocess.check_call([
        python_path, "-m", "jupyter", "nbconvert", "--to", "notebook", "--execute",
        "--inplace", "notebooks/model_training_and_evaluation.ipynb"
    ])

# 5. Start the dashboard (Flask app)
def start_dashboard(venv_dir):
    python_path = os.path.join(venv_dir, "Scripts", "python.exe") if os.name == "nt" else os.path.join(venv_dir, "bin", "python")
    print("[INFO] Starting dashboard (Flask app)...")
    subprocess.check_call([python_path, "dashboard/app.py"])

if __name__ == "__main__":
    check_python_version()
    venv_dir = create_venv()
    if not is_venv_valid(venv_dir):
        print("[ERROR] Virtual environment is not valid. Please recreate it.")
        sys.exit(1)
    install_requirements(venv_dir)
    if not check_libraries(venv_dir):
        sys.exit(1)
    # Ensure jupyter and nbconvert are installed before running the notebook
    python_path = os.path.join(venv_dir, "Scripts", "python.exe") if os.name == "nt" else os.path.join(venv_dir, "bin", "python")
    subprocess.check_call([python_path, "-m", "pip", "install", "jupyter", "nbconvert"])
    print("[INFO] Running the notebook to generate models...")
    run_notebook(venv_dir)
    if not check_models():
        print("[ERROR] Models are still missing after running the notebook. Please check for errors.")
        sys.exit(1)
    start_dashboard(venv_dir)
