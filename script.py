import os
from Registry import Registry # Requires 'pip install python-registry'

# Define the necessary registry files
REQUIRED_HIVES = ["SOFTWARE", "SAM", "SYSTEM"]

def get_path(name: str) -> str:
    """Gets and validates the path for a hive file."""
    while True:
        path = input(f"Enter path to '{name}' hive: ")
        path = path.strip('"') # Remove quotes from 'Copy as path'
        if os.path.exists(path) and os.path.isfile(path):
            return path
        else:
            print(f"Error: File not found at '{path}'. Try again.")

def analyze_apps(path: str):
    """Extracts installed applications from the SOFTWARE hive."""
    print("\n--- INSTALLED APPLICATIONS ---")
    try:
        reg = Registry.Registry(path)
        keys = [r"Microsoft\Windows\CurrentVersion\Uninstall", r"Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]
        apps = []
        
        for key_path in keys:
            try:
                for subkey in reg.open(key_path).subkeys():
                    name = subkey.value("DisplayName").value() if "DisplayName" in subkey.values() else subkey.name()
                    version = subkey.value("DisplayVersion").value() if "DisplayVersion" in subkey.values() else "N/A"
                    publisher = subkey.value("Publisher").value() if "Publisher" in subkey.values() else "N/A"
                    apps.append(f"{name} (Version: {version}, Publisher: {publisher})")
            except: pass
        
        for app in sorted(list(set(apps))):
            print(f"- {app}")
            
    except Exception as e:
        print(f"[ERROR] SOFTWARE analysis failed: {e}")

def analyze_users(path: str):
    """Extracts user accounts from the SAM hive."""
    print("\n--- USER ACCOUNTS ---")
    try:
        reg = Registry.Registry(path)
        names_key = reg.open(r"SAM\Domains\Account\Users\Names")
        users = []
        
        for subkey in names_key.subkeys():
            rid_hex = subkey.name()
            username = subkey.value("Name").value()
            users.append(f"{username} (RID: {int(rid_hex, 16)})")
        
        for user in sorted(users):
            print(f"- {user}")
            
    except Exception as e:
        print(f"[ERROR] SAM analysis failed: {e}")

def analyze_usb(path: str):
    """Extracts connected USB device history from the SYSTEM hive."""
    print("\n--- USB DEVICE HISTORY ---")
    try:
        reg = Registry.Registry(path)
        usb_key = reg.open(r"ControlSet001\Enum\USBSTOR")
        devices = []
        
        for vendor_key in usb_key.subkeys():
            for serial_key in vendor_key.subkeys():
                name = serial_key.value("FriendlyName").value() if "FriendlyName" in serial_key.values() else serial_key.name()
                devices.append(f"{name} (Serial: {serial_key.name()})")
        
        for device in sorted(list(set(devices))):
            print(f"- {device}")
            
    except Exception as e:
        print(f"[ERROR] SYSTEM analysis failed: {e}")

def main():
    print("--- MINIMAL FORENSIC HIVE ANALYZER ---")
    
    # 1. Collect paths
    hive_paths = {name: get_path(name) for name in REQUIRED_HIVES}
        
    # 2. Run analysis
    analyze_apps(hive_paths["SOFTWARE"])
    analyze_users(hive_paths["SAM"])
    analyze_usb(hive_paths["SYSTEM"])
    print("\n--- ANALYSIS COMPLETE ---")

if __name__ == "__main__":
    main()