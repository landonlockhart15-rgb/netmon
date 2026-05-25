import os
import sys
import tempfile
import hashlib
from datetime import datetime, timezone

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import SessionLocal
from models.tables import SecurityToolRun, SecurityFile, SecurityToolOutputChunk, SecurityAIExplanation
from security.wsl import check_wsl, check_all_tools
from security.common import create_security_run
from security.john import run_john
from security.hydra import run_hydra
from security.metasploit import run_metasploit
from security.aircrack import run_wifi_capture, run_aircrack
from security.tshark_ext import run_tshark_capture, run_tshark_analyze

def print_banner(msg):
    print("\n" + "=" * 60)
    print(f" {msg}")
    print("=" * 60)

def main():
    print_banner("SECURITY LAB INTEGRATION TEST SUITE")
    
    # 1. WSL Check
    wsl_status = check_wsl()
    print(f"WSL Installed: {wsl_status['wsl_installed']}")
    print(f"Kali Present: {wsl_status['kali_present']}")
    print(f"Distros: {wsl_status.get('distros', [])}")
    
    if not wsl_status['wsl_installed'] or not wsl_status['kali_present']:
        print("Error: WSL or Kali distribution not available. Exiting.")
        sys.exit(1)
        
    tool_check = check_all_tools()
    print("\nTool Checks:")
    for tool, status in tool_check.items():
        print(f" - {tool}: Installed={status['installed']}, Version={status.get('version')}")
        
    db = SessionLocal()
    try:
        # 2. Prepare test wordlist
        # We will check if we can write a simple wordlist file for cracking
        wordlist_content = "password\n123456\nadmin\nsecret\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wl_file:
            wl_file.write(wordlist_content)
            wl_path = wl_file.name
        
        # Prepare test md5 hash of '123456'
        hash_content = "test_user:e10adc3949ba59abbe56e057f20f883e\n" # md5 of 123456
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as hash_file:
            hash_file.write(hash_content)
            hash_path = hash_file.name
            
        print(f"\nCreated temp files:\n - Wordlist: {wl_path}\n - Hash file: {hash_path}")
        
        # Register them in database
        wl_record = SecurityFile(
            file_type="wordlist",
            original_name="test_wordlist.txt",
            storage_path=wl_path,
            sha256=hashlib.sha256(wordlist_content.encode()).hexdigest(),
            size_bytes=len(wordlist_content)
        )
        hash_record = SecurityFile(
            file_type="hash",
            original_name="test_hash.txt",
            storage_path=hash_path,
            sha256=hashlib.sha256(hash_content.encode()).hexdigest(),
            size_bytes=len(hash_content)
        )
        db.add(wl_record)
        db.add(hash_record)
        db.commit()
        db.refresh(wl_record)
        db.refresh(hash_record)
        
        # 3. Test John the Ripper
        print_banner("TESTING: John the Ripper (Password Cracking)")
        run_id = create_security_run(
            db, tool="john", tab="password_test",
            target="test_hash.txt", target_type="file",
            is_attack_tool=True, authorization_confirmed=True
        )
        print(f"Created run ID {run_id} for John. Executing...")
        run_john(
            run_id=run_id,
            hash_file_path=hash_record.storage_path,
            wordlist_file_path=wl_record.storage_path,
            format_name="raw-md5",
            max_runtime_seconds=30
        )
        
        # Verify run
        run_record = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id).first()
        print(f"John run status: {run_record.status}, risk level: {run_record.risk_level}")
        chunks = db.query(SecurityToolOutputChunk).filter(SecurityToolOutputChunk.run_id == run_id).all()
        print(f"Output chunk count: {len(chunks)}")
        ai_exp = db.query(SecurityAIExplanation).filter(SecurityAIExplanation.run_id == run_id).first()
        print(f"AI explanation generated: {ai_exp is not None}")
        if ai_exp:
            print(f"AI Summary preview: {ai_exp.summary_text[:120]}...")
            
        # 4. Test Hydra
        print_banner("TESTING: Hydra (Login Brute Force)")
        run_id = create_security_run(
            db, tool="hydra", tab="password_test",
            target="127.0.0.1", target_type="device_ip",
            is_attack_tool=True, authorization_confirmed=True
        )
        print(f"Created run ID {run_id} for Hydra. Executing against 127.0.0.1 (closed/refused service)...")
        # Run against ssh service on 127.0.0.1 (SSH is likely closed, should exit with connection refused/fail gracefully)
        run_hydra(
            run_id=run_id,
            target="127.0.0.1",
            service="ssh",
            username="admin",
            password_file_path=wl_record.storage_path,
            max_parallel_tasks=1,
            timeout_seconds=30
        )
        run_record = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id).first()
        print(f"Hydra run status: {run_record.status}, risk level: {run_record.risk_level}")
        ai_exp = db.query(SecurityAIExplanation).filter(SecurityAIExplanation.run_id == run_id).first()
        print(f"AI explanation generated: {ai_exp is not None}")
        if ai_exp:
            print(f"AI Summary preview: {ai_exp.summary_text[:120]}...")

        # 5. Test Metasploit
        print_banner("TESTING: Metasploit (Exploit Framework)")
        run_id = create_security_run(
            db, tool="metasploit", tab="exploit_test",
            target="127.0.0.1", target_type="device_ip",
            is_attack_tool=True, authorization_confirmed=True
        )
        print(f"Created run ID {run_id} for Metasploit. Executing tcp portscan module...")
        # Use auxiliary/scanner/portscan/tcp on port 1 so it completes immediately
        run_metasploit(
            run_id=run_id,
            target="127.0.0.1",
            module_name="auxiliary/scanner/portscan/tcp",
            options={"PORTS": "1", "TIMEOUT": "50"},
            timeout_seconds=60
        )
        run_record = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id).first()
        print(f"Metasploit run status: {run_record.status}, risk level: {run_record.risk_level}")
        ai_exp = db.query(SecurityAIExplanation).filter(SecurityAIExplanation.run_id == run_id).first()
        print(f"AI explanation generated: {ai_exp is not None}")
        if ai_exp:
            print(f"AI Summary preview: {ai_exp.summary_text[:120]}...")

        # 6. Test tshark capture and analyze
        print_banner("TESTING: tshark (Traffic Capture and Analysis)")
        # Capture
        run_id_cap = create_security_run(
            db, tool="tshark", tab="packet_capture",
            target="lo", target_type="interface",
            is_attack_tool=False, authorization_confirmed=True
        )
        print(f"Created run ID {run_id_cap} for tshark capture. Executing for 3s...")
        run_tshark_capture(
            run_id=run_id_cap,
            interface="lo",
            duration_seconds=3,
            timeout_seconds=20
        )
        run_record = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id_cap).first()
        print(f"tshark capture status: {run_record.status}")
        
        # Analyze using the captured file or mock file
        # We can analyze the file generated by the capture if it succeeded.
        # Since it captured on loopback in WSL, the pcap is saved at /tmp/netmon_tshark_{run_id_cap}.pcap inside WSL.
        # We need to map that path or create a local mock pcap to test analyze.
        # Let's see if we can create a dummy file record or query the path.
        run_id_ana = create_security_run(
            db, tool="tshark", tab="packet_capture",
            target=f"netmon_tshark_{run_id_cap}.pcap", target_type="file",
            is_attack_tool=False, authorization_confirmed=True
        )
        print(f"Created run ID {run_id_ana} for tshark analyze. Executing...")
        run_tshark_analyze(
            run_id=run_id_ana,
            pcap_file_path=f"C:\\Projects\\netmon\\data\\dummy_nonexistent.pcap", # tshark will fail to open it, which tests error path
            timeout_seconds=20
        )
        run_record = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id_ana).first()
        print(f"tshark analyze status: {run_record.status}")
        ai_exp = db.query(SecurityAIExplanation).filter(SecurityAIExplanation.run_id == run_id_ana).first()
        print(f"AI explanation generated: {ai_exp is not None}")
        if ai_exp:
            print(f"AI Summary preview: {ai_exp.summary_text[:120]}...")

        # 7. Test Aircrack Wifi Capture and Crack
        print_banner("TESTING: Aircrack (Wi-Fi Security)")
        run_id_wf_cap = create_security_run(
            db, tool="aircrack", tab="wifi_test",
            target="lo", target_type="interface",
            is_attack_tool=True, authorization_confirmed=True
        )
        print(f"Created run ID {run_id_wf_cap} for aircrack wifi capture. Executing (2s duration)...")
        # Run wifi capture (may fail/warn if interface doesn't support monitor mode, which tests warning paths)
        run_wifi_capture(
            run_id=run_id_wf_cap,
            interface="lo",
            duration_seconds=2,
            timeout_seconds=15
        )
        run_record = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id_wf_cap).first()
        print(f"Aircrack wifi capture status: {run_record.status}")
        
        run_id_wf_crack = create_security_run(
            db, tool="aircrack-ng", tab="wifi_test",
            target="wifi_crack", target_type="file",
            is_attack_tool=True, authorization_confirmed=True
        )
        print(f"Created run ID {run_id_wf_crack} for aircrack cracking. Executing...")
        run_aircrack(
            run_id=run_id_wf_crack,
            capture_file_path=f"C:\\Projects\\netmon\\data\\dummy_nonexistent.cap", # expected to fail, testing error handling
            wordlist_file_path=wl_record.storage_path,
            timeout_seconds=15
        )
        run_record = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id_wf_crack).first()
        print(f"Aircrack cracking status: {run_record.status}")
        ai_exp = db.query(SecurityAIExplanation).filter(SecurityAIExplanation.run_id == run_id_wf_crack).first()
        print(f"AI explanation generated: {ai_exp is not None}")
        if ai_exp:
            print(f"AI Summary preview: {ai_exp.summary_text[:120]}...")

        # Cleanup temp database records we created
        print_banner("CLEANING UP TEST RECORDS")
        db.delete(wl_record)
        db.delete(hash_record)
        db.commit()
        print("Cleaned up temp SecurityFile records successfully.")
        
        # Delete temp files on disk
        for p in [wl_path, hash_path]:
            if os.path.exists(p):
                os.unlink(p)
        print("Cleaned up temp disk files successfully.")

    except Exception as e:
        print(f"Exception during testing: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    main()
