import os
import sys
import argparse
import subprocess

def _ensure_virtualenv():
    # Skip check if compiled as a standalone PyInstaller binary
    if getattr(sys, 'frozen', False):
        return
        
    # Get project root folder containing this file
    base_dir = os.path.dirname(os.path.abspath(__file__))
    venv_dir = os.path.join(base_dir, '.venv')
    
    if not os.path.isdir(venv_dir):
        return
        
    # Verify if active interpreter path resides inside the .venv directory
    is_in_venv = venv_dir.lower() in sys.executable.lower()
    
    if not is_in_venv:
        # Resolve path to the local virtualenv python binary
        if os.name == 'nt':  # Windows
            venv_python = os.path.join(venv_dir, 'Scripts', 'python.exe')
        else:  # macOS / Linux
            venv_python = os.path.join(venv_dir, 'bin', 'python')
            
        if os.path.exists(venv_python):
            print(f"[*] Local virtual environment detected at {venv_python}")
            print("[*] Re-executing cli.py using venv python interpreter...")
            sys.exit(subprocess.call([venv_python] + sys.argv))

_ensure_virtualenv()

from colorama import init, Fore, Style
from analyzer import EmailAnalyzer

# Initialize colorama
init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}======================================================================
     EMAIL SECURITY ANALYST'S ASSISTANT (Human-in-the-Loop)
======================================================================{Style.RESET_ALL}
"""
    print(banner)

def get_multiline_input():
    print(f"{Fore.YELLOW}Paste the full raw email headers and body below.")
    print(f"{Fore.YELLOW}When you are done, type {Fore.GREEN}{Style.BRIGHT}DONE{Fore.YELLOW} on a new line and press Enter:")
    print("-" * 50)
    lines = []
    while True:
        try:
            line = input()
            if line.strip() == "DONE":
                break
            lines.append(line)
        except EOFError:
            break
    print("-" * 50)
    return "\n".join(lines)

def get_eml_file_input():
    while True:
        path = input(f"\nEnter the path to the {Fore.CYAN}.eml{Style.RESET_ALL} file (or 'B' to go back): ").strip()
        if path.upper() == 'B':
            return None
        
        # Strip quotes if the user dragged and dropped the file
        path = path.strip('"').strip("'")
        
        if os.path.exists(path) and os.path.isfile(path):
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            except Exception as e:
                print(f"{Fore.RED}Error reading file: {e}")
        else:
            print(f"{Fore.RED}File not found. Please verify the path.")

def analyze_and_report(raw_content, analyzer):
    """Analyzes the raw email content and reports security findings inside the terminal."""
    # Run analysis
    print(f"\n{Fore.CYAN}Analyzing email content... Please wait...")
    result = analyzer.analyze_email(raw_content)
    
    # Display security report
    print(f"\n{Fore.WHITE}{Style.BRIGHT}==========================================")
    print(f"{Fore.WHITE}{Style.BRIGHT}            SECURITY ANALYSIS             ")
    print(f"{Fore.WHITE}{Style.BRIGHT}==========================================")
    
    # Subject and Sender
    print(f"{Fore.WHITE}{Style.BRIGHT}Subject: {Style.RESET_ALL}{result['metadata']['subject']}")
    print(f"{Fore.WHITE}{Style.BRIGHT}From:    {Style.RESET_ALL}{result['metadata']['from']}")
    
    # Origin routing
    if 'origin' in result:
        print(f"{Fore.WHITE}{Style.BRIGHT}Origin IP: {Fore.CYAN}{result['origin']['ip']}")
        print(f"{Fore.WHITE}{Style.BRIGHT}Location:  {Fore.CYAN}{result['origin']['location']}")
    
    # Assessment
    score_pct = result['confidence'] * 100
    if result['assessment'] == "POTENTIAL PHISHING":
        print(f"\n{Fore.RED}{Style.BRIGHT}System Assessment: [WARN] POTENTIAL PHISHING ({score_pct:.0f}% confidence)")
    elif result['assessment'] == "SPAM DETECTED":
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}System Assessment: [WARN] SPAM DETECTED ({score_pct:.0f}% confidence)")
    else:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}System Assessment: [OK] SAFE ({score_pct:.0f}% confidence)")
        
    # Reasoning
    if result['reasons']:
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}Reasoning / Indicators:")
        for reason in result['reasons']:
            print(f" * {reason}")
    else:
        print(f"\n{Fore.GREEN}No suspicious heuristics or ML indicators flagged.")
        
    # Defanged Links
    links = result['heuristics']['defanged_links']
    if links:
        print(f"\n{Fore.WHITE}{Style.BRIGHT}Defanged Links ({len(links)}):")
        for idx, link in enumerate(links, 1):
            anchor_part = f" [Anchor text: '{link['anchor']}']" if link['anchor'] else ""
            print(f" {idx}. {Fore.LIGHTBLACK_EX}{link['defanged']}{Style.RESET_ALL}{anchor_part}")
            
    # Attachments
    attachments = result['attachments']
    if attachments:
        print(f"\n{Fore.WHITE}{Style.BRIGHT}Attachments ({len(attachments)}):")
        for idx, att in enumerate(attachments, 1):
            size_kb = att['size'] / 1024.0
            print(f" {idx}. {Fore.LIGHTMAGENTA_EX}{att['filename']}{Style.RESET_ALL} ({size_kb:.1f} KB)")
            print(f"    SHA-256 Hash: {Fore.CYAN}{att['sha256']}")
            
    print(f"{Fore.WHITE}{Style.BRIGHT}==========================================")
    
    # Human in the Loop Feedback
    prediction = result['ml']['prediction']
    confidence = result['ml']['confidence']
    
    while True:
        verdict = input(f"\n{Fore.GREEN}{Style.BRIGHT}Do you want to flag this as Safe (S) or Malicious (M)? {Style.RESET_ALL}").strip().upper()
        if verdict in ('S', 'M'):
            human_verdict = "Safe" if verdict == 'S' else "Malicious"
            break
        print(f"{Fore.RED}Invalid input. Enter 'S' for Safe or 'M' for Malicious.")
        
    # Check if human verdict differs from the ML prediction
    if human_verdict != prediction:
        print(f"\n{Fore.YELLOW}[WARN] Verdict mismatch! You marked this email as '{human_verdict}', but the ML model predicted '{prediction}'.")
        print(f"{Fore.YELLOW}Logging email to feedback log...")
        
        if analyzer.log_feedback(result['metadata'], prediction, confidence, human_verdict):
            print(f"{Fore.GREEN}[OK] Logged feedback to feedback_log.csv")
            
            # Prompt to retrain
            retrain_choice = input(f"{Fore.CYAN}Would you like to retrain the classifier model right now? (Y/N): {Style.RESET_ALL}").strip().upper()
            if retrain_choice == 'Y':
                if analyzer.retrain_model():
                    print(f"{Fore.GREEN}[OK] Model retrained successfully!")
                else:
                    print(f"{Fore.RED}[ERROR] Retraining failed.")
        else:
            print(f"{Fore.RED}[ERROR] Failed to write feedback log.")
    else:
        print(f"\n{Fore.GREEN}[OK] Verdict matches model prediction. No log entry required.")

def run_cli():
    """Runs the terminal analyst tool with interactive choices."""
    analyzer = EmailAnalyzer()
    print_banner()
    while True:
        print(f"\n{Fore.WHITE}{Style.BRIGHT}Choose an input option:")
        print(f"1. Paste Raw Email Text (Headers + Body)")
        print(f"2. Load EML File from Path")
        print(f"3. Retrain Classifier (Force update from feedback log)")
        print(f"4. Exit")
        
        choice = input(f"{Fore.GREEN}Enter choice (1-4): {Style.RESET_ALL}").strip()
        
        raw_content = ""
        if choice == '1':
            raw_content = get_multiline_input()
            if not raw_content.strip():
                print(f"{Fore.RED}Input was empty. Returning to menu.")
                continue
        elif choice == '2':
            raw_content = get_eml_file_input()
            if raw_content is None:
                continue
        elif choice == '3':
            print(f"\n{Fore.YELLOW}Retraining classifier from feedback log...")
            if analyzer.retrain_model():
                print(f"{Fore.GREEN}[OK] Model retrained successfully and state updated.")
            else:
                print(f"{Fore.RED}[ERROR] Retraining failed. (Verify feedback_log.csv exists and contains data).")
            continue
        elif choice == '4':
            print(f"{Fore.CYAN}Goodbye!")
            break
        else:
            print(f"{Fore.RED}Invalid option. Please enter 1, 2, 3, or 4.")
            continue
            
        analyze_and_report(raw_content, analyzer)

def main():
    """CLI Argument Parser configuration setup."""
    parser = argparse.ArgumentParser(description="Email Security Analyst Assistant CLI Utility")
    
    # Configure arguments
    parser.add_argument(
        '-f', '--file', 
        type=str, 
        help='Path to a local raw .eml file to analyze directly'
    )
    parser.add_argument(
        '-t', '--text', 
        type=str, 
        help='Direct raw email string/content to analyze directly'
    )
    
    args = parser.parse_args()
    analyzer = EmailAnalyzer()

    # Direct Analysis Mode (via EML File argument)
    if args.file:
        file_path = args.file.strip('"').strip("'")
        if os.path.exists(file_path) and os.path.isfile(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    raw_content = f.read()
                analyze_and_report(raw_content, analyzer)
            except Exception as e:
                print(f"{Fore.RED}Error loading specified file: {e}")
                sys.exit(1)
        else:
            print(f"{Fore.RED}File not found at: {file_path}")
            sys.exit(1)
            
    # Direct Analysis Mode (via raw text argument)
    elif args.text:
        analyze_and_report(args.text, analyzer)
        
    # Interactive selection menu fallback
    else:
        run_cli()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.CYAN}Exiting CLI. Goodbye!")
        sys.exit(0)