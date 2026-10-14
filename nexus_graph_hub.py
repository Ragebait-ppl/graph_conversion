#!/usr/bin/env python3
"""
===============================================================================
  NEXUS GRAPH ENGINE: INTERACTIVE FORENSICS & GRAPH PIPELINE HUB
===============================================================================
A sleek, interactive command center for orchestrating host telemetry collection,
data sanitization, homogeneous graph construction, and browser visualization.
"""

import os
import sys
import time
import subprocess
import webbrowser
import ctypes
from pathlib import Path

# Enable UTF-8 console output on Windows
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ANSI Color Palettes for High-Tech Console Aesthetic
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    GREEN   = "\033[92m"
    AMBER   = "\033[93m"
    RED     = "\033[91m"
    PURPLE  = "\033[95m"
    WHITE   = "\033[97m"

def is_admin() -> bool:
    """Checks whether the current terminal process has administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def clear_screen():
    """Clears terminal screen across platforms."""
    os.system("cls" if os.name == "nt" else "clear")

def print_banner():
    """Displays the stylized Nexus cyber-forensics header."""
    banner = f"""
{Color.CYAN}  _   _ _______  ___   _ ____     ____ ____      _    ____  _   _ 
 | \\ | | ____\\ \\/ / | | / ___|   / ___|  _ \\    / \\  |  _ \\| | | |
 |  \\| |  _|  \\  /| | | \\___ \\  | |  _| |_) |  / _ \\ | |_) | |_| |
 | |\\  | |___ /  \\| |_| |___) | | |_| |  _ <  / ___ \\|  __/|  _  |
 |_| \\_|_____/_/\\_\\\\___/|____/   \\____|_| \\_\\/_/   \\_\\_|   |_| |_|{Color.RESET}
 {Color.PURPLE}--- Windows Host Forensics & GNN Homogeneous Graph Hub ---{Color.RESET}
"""
    print(banner)

def print_system_status():
    """Renders pre-flight system health and local artifact availability."""
    admin_status = f"{Color.GREEN}Elevated (Administrator - SeDebugPrivilege Available){Color.RESET}" if is_admin() else f"{Color.AMBER}Standard User (Elevate terminal for full kernel scanning){Color.RESET}"
    
    bin_exists = os.path.exists(os.path.join("bin", "telemetry_engine.exe"))
    bin_status = f"{Color.GREEN}Ready ({os.path.join('bin', 'telemetry_engine.exe')}){Color.RESET}" if bin_exists else f"{Color.RED}Not Compiled (Run Option 7){Color.RESET}"
    
    raw_exists = os.path.exists("telemetry.json")
    csv_exists = os.path.exists("telemetry_graph_nodes.csv") and os.path.exists("telemetry_graph_weighted_edges.csv")
    graph_exists = os.path.exists("homogeneous_graph_view.html") and os.path.exists("homogeneous_pyg_data.pt")
    
    data_status = f"{Color.GREEN}Active Data Present{Color.RESET}" if raw_exists else f"{Color.DIM}No Snapshot (Ready to Collect){Color.RESET}"
    graph_status = f"{Color.GREEN}Built & Ready{Color.RESET}" if graph_exists else f"{Color.DIM}Not Generated Yet{Color.RESET}"

    print(f" {Color.BOLD}[System Pre-Flight Check]{Color.RESET}")
    print(f"  * Privilege:      {admin_status}")
    print(f"  * C++ Collector:  {bin_status}")
    print(f"  * Raw Telemetry:  {data_status}")
    print(f"  * Dynamic Graph:  {graph_status}")
    print(f"{Color.DIM} -------------------------------------------------------------{Color.RESET}")

def run_command(cmd, step_name: str) -> bool:
    """Executes a command with a clean progress display and timing."""
    print(f"\n{Color.CYAN}[*] Starting: {step_name}...{Color.RESET}")
    print(f"{Color.DIM}    Executing: {' '.join(cmd) if isinstance(cmd, list) else cmd}{Color.RESET}\n")
    start = time.time()
    try:
        ret = subprocess.run(cmd, check=True)
        elapsed = time.time() - start
        print(f"\n{Color.GREEN}[+] {step_name} completed successfully in {elapsed:.2f}s.{Color.RESET}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n{Color.RED}[-] Error during {step_name} (Exit code: {e.returncode}).{Color.RESET}")
        return False
    except FileNotFoundError as e:
        print(f"\n{Color.RED}[-] Command not found: {e}{Color.RESET}")
        return False

def compile_collector():
    """Compiles the C++20 telemetry engine using build.bat or g++."""
    clear_screen()
    print_banner()
    print(f"{Color.BOLD}=== Step 7: Compiling Native C++20 Telemetry Engine ==={Color.RESET}")
    if os.name == "nt" and os.path.exists("build.bat"):
        run_command(["build.bat"], "C++ Engine Compilation (build.bat)")
    else:
        cmd = [
            "g++", "-std=c++20", "-O2", "-Wall", "-Wextra", "-Iinclude",
            "src/main.cpp", "src/privilege.cpp", "src/process_collector.cpp",
            "src/memory_scanner.cpp", "src/network_mapper.cpp", "src/json_serializer.cpp",
            "-lws2_32", "-liphlpapi", "-lpsapi", "-ladvapi32",
            "-o", "bin/telemetry_engine.exe"
        ]
        os.makedirs("bin", exist_ok=True)
        run_command(cmd, "C++ Engine Compilation (g++)")
    input(f"\n{Color.CYAN}Press Enter to return to menu...{Color.RESET}")

def prompt_collection_flags() -> list:
    """Prompts the user to configure multi-threading and privacy sanitization."""
    print(f"\n {Color.BOLD}[Telemetry Engine Configuration]{Color.RESET}")
    print(f"  {Color.CYAN}[1] High-Speed Multi-Threaded Engine (Parallel CPU Core Scanning){Color.RESET} {Color.GREEN}[Recommended - ~4-5x faster]{Color.RESET}")
    print(f"  {Color.CYAN}[2] Classic Single-Threaded Engine (Sequential Baseline){Color.RESET}")
    mode = input(f"  Select execution mode [1/2, default: 1]: ").strip()

    print(f"\n {Color.BOLD}[Forensic Privacy & Data Scrubbing]{Color.RESET}")
    print(f"  {Color.CYAN}[1] Sanitized Forensics (Mask user directories & remote WAN IPs){Color.RESET} {Color.GREEN}[Recommended for Sharing/Git]{Color.RESET}")
    print(f"  {Color.CYAN}[2] Raw Forensics (Preserve exact system user paths & external IPs){Color.RESET}")
    privacy = input(f"  Select privacy filter [1/2, default: 1]: ").strip()

    cmd_flags = ["-o", "telemetry.json"]
    if mode == "2":
        cmd_flags.append("--single")
    else:
        cmd_flags.append("--parallel")

    if privacy != "2":
        cmd_flags.append("--sanitize")

    return cmd_flags

def collect_telemetry():
    """Runs the native telemetry engine to capture live system state."""
    clear_screen()
    print_banner()
    print(f"{Color.BOLD}=== Phase 1: Native Host Telemetry Collection ==={Color.RESET}")
    bin_path = os.path.join("bin", "telemetry_engine.exe")
    if not os.path.exists(bin_path):
        print(f"{Color.RED}[!] Telemetry binary not found at: {bin_path}{Color.RESET}")
        compile_now = input("Would you like to compile it now? (y/n): ").strip().lower()
        if compile_now == "y":
            compile_collector()
            if not os.path.exists(bin_path):
                return
        else:
            return

    flags = prompt_collection_flags()
    run_command([bin_path] + flags, "Host Telemetry Snapshot")
    input(f"\n{Color.CYAN}Press Enter to return to menu...{Color.RESET}")

def clean_and_organize():
    """Runs organize_and_clean_telemetry.py to structure nodes and edges into CSVs."""
    clear_screen()
    print_banner()
    print(f"{Color.BOLD}=== Phase 2: Telemetry Sanitization & CSV Structuring ==={Color.RESET}")
    if not os.path.exists("telemetry.json"):
        print(f"{Color.AMBER}[!] telemetry.json not found.{Color.RESET}")
        ans = input("Would you like to collect live telemetry first? (y/n): ").strip().lower()
        if ans == "y":
            collect_telemetry()
            if not os.path.exists("telemetry.json"):
                return
        else:
            return

    run_command([sys.executable, "organize_and_clean_telemetry.py"], "CSV Node/Edge Structuring")
    input(f"\n{Color.CYAN}Press Enter to return to menu...{Color.RESET}")

def generate_graph():
    """Runs generate_homogeneous_graph.py to create homogeneous tensor and HTML view."""
    clear_screen()
    print_banner()
    print(f"{Color.BOLD}=== Phase 3: Homogeneous Graph Conversion & GNN Readying ==={Color.RESET}")
    if not (os.path.exists("telemetry_graph_nodes.csv") and os.path.exists("telemetry_graph_weighted_edges.csv")):
        print(f"{Color.AMBER}[!] Required CSV files missing.{Color.RESET}")
        clean_and_organize()
        if not (os.path.exists("telemetry_graph_nodes.csv") and os.path.exists("telemetry_graph_weighted_edges.csv")):
            return

    success = run_command([sys.executable, "generate_homogeneous_graph.py"], "Homogeneous Graph Conversion")
    if success:
        open_browser = input(f"\n{Color.GREEN}Graph built! Open interactive visualizer in browser now? (y/n): {Color.RESET}").strip().lower()
        if open_browser == "y":
            launch_visualizer(pause=False)
    input(f"\n{Color.CYAN}Press Enter to return to menu...{Color.RESET}")

def run_end_to_end():
    """Executes the full pipeline sequentially from collection to visualization."""
    clear_screen()
    print_banner()
    print(f"{Color.BOLD}{Color.GREEN}=== Autonomous End-to-End Execution ==={Color.RESET}")
    
    bin_path = os.path.join("bin", "telemetry_engine.exe")
    if not os.path.exists(bin_path):
        print(f"{Color.CYAN}[*] Compiling binary first...{Color.RESET}")
        if os.name == "nt" and os.path.exists("build.bat"):
            subprocess.run(["build.bat"], check=True)
        else:
            compile_collector()

    flags = prompt_collection_flags()
    if not run_command([bin_path] + flags, "1. Live Host Telemetry Snapshot"):
        input("Press Enter to return..."); return

    if not run_command([sys.executable, "organize_and_clean_telemetry.py"], "2. Telemetry Parsing & CSV Structuring"):
        input("Press Enter to return..."); return

    if not run_command([sys.executable, "generate_homogeneous_graph.py"], "3. Homogeneous Graph & PyG Tensor Generation"):
        input("Press Enter to return..."); return

    launch_visualizer(pause=False)
    input(f"\n{Color.GREEN}[+] Complete pipeline executed successfully! Press Enter to return to menu...{Color.RESET}")

def launch_visualizer(pause: bool = True):
    """Opens homogeneous_graph_view.html in default web browser."""
    html_file = "homogeneous_graph_view.html"
    if not os.path.exists(html_file):
        print(f"\n{Color.AMBER}[!] Visualizer not generated yet. Run Phase 3 first.{Color.RESET}")
    else:
        abs_path = os.path.abspath(html_file)
        print(f"\n{Color.GREEN}[+] Launching browser: {abs_path}{Color.RESET}")
        webbrowser.open(f"file:///{abs_path}")
    
    if pause:
        input(f"\n{Color.CYAN}Press Enter to return to menu...{Color.RESET}")

def display_forensic_triage():
    """Innovative forensic summary extracting high-risk nodes and graph metrics."""
    clear_screen()
    print_banner()
    print(f"{Color.BOLD}=== Instant Forensic Triage & Graph Insights ==={Color.RESET}\n")

    nodes_file = "homogeneous_nodes.csv"
    edges_file = "homogeneous_edges.csv"

    if not (os.path.exists(nodes_file) and os.path.exists(edges_file)):
        print(f"{Color.AMBER}[!] Homogeneous graph tables not found. Run Option 1 or 4 first.{Color.RESET}")
        input(f"\n{Color.CYAN}Press Enter to return...{Color.RESET}")
        return

    try:
        import pandas as pd
        nodes_df = pd.read_csv(nodes_file)
        edges_df = pd.read_csv(edges_file)

        total_nodes = len(nodes_df)
        total_edges = len(edges_df)

        proc_count = len(nodes_df[nodes_df["node_type"] == "process"])
        mem_count = len(nodes_df[nodes_df["node_type"] == "memory_region"])
        sock_count = len(nodes_df[nodes_df["node_type"] == "socket"])

        high_risk_mem = nodes_df[nodes_df["subcategory"] == "high_risk_memory"]
        sys_procs = nodes_df[nodes_df["subcategory"] == "system_process"]
        user_procs = nodes_df[nodes_df["subcategory"] == "user_process"]

        rel_counts = edges_df["relationship"].value_counts().to_dict()

        print(f" {Color.BOLD}[1. Graph Topology Overview]{Color.RESET}")
        print(f"  * Total Vertices (|V|):   {Color.CYAN}{total_nodes}{Color.RESET} (0 to {total_nodes - 1} contiguous integer index)")
        print(f"  * Directed Edges (|E|):   {Color.CYAN}{total_edges}{Color.RESET}")
        print(f"  * Feature Tensor Shape:   {Color.CYAN}[{total_nodes}, 16]{Color.RESET} (Continuous Normalized)")
        print(f"  * PyG Data Tensor:        {Color.GREEN}Available (homogeneous_pyg_data.pt){Color.RESET}\n")

        print(f" {Color.BOLD}[2. Entity Classification Breakdown]{Color.RESET}")
        print(f"  - System Core Processes:  {Color.BLUE}{len(sys_procs)}{Color.RESET}")
        print(f"  - User / App Processes:   {Color.CYAN}{len(user_procs)}{Color.RESET}")
        print(f"  - Unbacked Executable Mem:{Color.AMBER}{mem_count}{Color.RESET} (Total Pages Scanned)")
        print(f"  - Network Sockets:        {Color.GREEN}{sock_count}{Color.RESET} (TCP/UDP Endpoints)\n")

        print(f" {Color.BOLD}[3. Directed Relationship Breakdown]{Color.RESET}")
        for rel, count in rel_counts.items():
            color = Color.PURPLE if rel == "spawns" else (Color.RED if rel == "has_memory" else Color.CYAN)
            print(f"  - Edge '{rel}': {color}{count}{Color.RESET} connections")

        print(f"\n {Color.BOLD}[4. High-Risk Security Flags (Potential In-Memory Threats)]{Color.RESET}")
        if len(high_risk_mem) == 0:
            print(f"  {Color.GREEN}[OK] Zero high-risk unbacked executable memory pages detected.{Color.RESET}")
        else:
            print(f"  {Color.RED}[!] FLAGGED {len(high_risk_mem)} High-Risk Memory Pages (Entropy H >= 6.5 or RWX permissions):{Color.RESET}")
            for _, row in high_risk_mem.head(6).iterrows():
                print(f"      * [{row['node_idx']}] PID {row['pid']} - {row['clean_label']} (Risk: {row['risk_level']})")
            if len(high_risk_mem) > 6:
                print(f"      ... and {len(high_risk_mem) - 6} more flagged regions.")

    except Exception as e:
        print(f"{Color.RED}[-] Failed to parse graph metrics: {e}{Color.RESET}")

    input(f"\n{Color.CYAN}Press Enter to return to menu...{Color.RESET}")

def main_menu():
    """Main menu interaction loop."""
    while True:
        clear_screen()
        print_banner()
        print_system_status()

        print(f" {Color.BOLD}[Menu Navigation Options]{Color.RESET}\n")
        print(f"  {Color.GREEN}{Color.BOLD}[1]{Color.RESET} {Color.GREEN}Run Autonomous End-to-End Pipeline (Collect -> Clean -> Graph -> View){Color.RESET}")
        print(f"  {Color.CYAN}[2]{Color.RESET} Phase 1: Live Telemetry Collection (C++20 Native Engine)")
        print(f"  {Color.CYAN}[3]{Color.RESET} Phase 2: Telemetry Data Cleaning & CSV Structuring")
        print(f"  {Color.CYAN}[4]{Color.RESET} Phase 3: Homogeneous Graph Conversion & GNN Tensor Export")
        print(f"  {Color.CYAN}[5]{Color.RESET} Launch Interactive Graph Visualizer in Browser")
        print(f"  {Color.AMBER}[6]{Color.RESET} Instant Security Triage & Graph Topology Insights")
        print(f"  {Color.PURPLE}[7]{Color.RESET} Recompile Native C++ Telemetry Collector")
        print(f"  {Color.RED}[0]{Color.RESET} Exit\n")

        choice = input(f" {Color.BOLD}Enter option [0-7]: {Color.RESET}").strip()

        if choice == "1":
            run_end_to_end()
        elif choice == "2":
            collect_telemetry()
        elif choice == "3":
            clean_and_organize()
        elif choice == "4":
            generate_graph()
        elif choice == "5":
            launch_visualizer()
        elif choice == "6":
            display_forensic_triage()
        elif choice == "7":
            compile_collector()
        elif choice == "0" or choice.lower() in ["exit", "q", "quit"]:
            print(f"\n{Color.CYAN}[*] Exiting Nexus Graph Hub. Goodbye!{Color.RESET}\n")
            break
        else:
            print(f"\n{Color.RED}[!] Invalid choice. Please enter a number between 0 and 7.{Color.RESET}")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{Color.AMBER}[*] Operation cancelled by user. Exiting...{Color.RESET}\n")
        sys.exit(0)
