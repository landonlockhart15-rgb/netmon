import psutil

def find_open_files():
    found = False
    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmd = " ".join(p.info.get('cmdline') or [])
            if 'open-webui' in p.info['name'].lower() or 'open-webui' in cmd.lower() or 'python' in p.info['name'].lower():
                # Get open files
                files = p.open_files()
                for f in files:
                    if 'webui.db' in f.path:
                        found = True
                        print(f"Process PID {p.info['pid']} ({p.info['name']}) has open db file:")
                        print(f"  {f.path}")
        except Exception as e:
            pass
            
    if not found:
        print("No open webui.db file found in any running process.")

if __name__ == "__main__":
    find_open_files()
