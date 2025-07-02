import sys
import platform
import shutil
import subprocess
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn
from rich.table import Table
import time
import os

console = Console()

# List of required tools and their install commands per OS
REQUIRED_TOOLS = [
    'nmap', 'nc', 'traceroute', 'enum4linux', 'snmpwalk', 'nikto', 'gobuster', 'dirb',
    'hping3', 'proxychains', 'aircrack-ng', 'kismet', 'arp-scan', 'ffuf', 'tor',
    'whois', 'sslscan', 'wpscan', 'searchsploit', 'gvm-cli', 'whatweb', 'wafw00f', 'feroxbuster', 'droopescan', 'joomscan',
    'linpeas', 'winpeas', 'pspy', 'linenum', 'unix-privesc-check', 'windows-privesc-check'
]
PYTHON_MODULES = ['scapy', 'requests', 'dns']

# Tools not supported on Windows
UNSUPPORTED_ON_WINDOWS = [
    'enum4linux', 'snmpwalk', 'dirb', 'hping3', 'proxychains', 'kismet', 'arp-scan',
    'linpeas', 'linenum', 'unix-privesc-check'
]

# List of tools that may require manual/interactive install
INTERACTIVE_TOOLS = {
    'kismet': {
        'post_install': [
            'Add your user to the kismet group: sudo usermod -aG kismet $USER',
            'Log out and log back in for group changes to take effect.'
        ],
        'note': 'Kismet may prompt for which user(s) to add to the kismet group during installation.'
    },
    # Add more tools here as needed
}

# Mapping of Python modules to apt package names
PYTHON_MODULE_APT = {
    'scapy': 'python3-scapy',
    'requests': 'python3-requests',
    'dns': 'python3-dnspython',
    # Add more mappings as needed
}

INSTALL_COMMANDS = {
    'linux': {
        'nmap': 'sudo apt install -y nmap',
        'nc': 'sudo apt install -y netcat',
        'traceroute': 'sudo apt install -y traceroute',
        'enum4linux': 'sudo apt install -y enum4linux',
        'snmpwalk': 'sudo apt install -y snmp',
        'nikto': 'sudo apt install -y nikto',
        'gobuster': 'sudo apt install -y gobuster',
        'dirb': 'sudo apt install -y dirb',
        'hping3': 'sudo apt install -y hping3',
        'proxychains': 'sudo apt install -y proxychains4',
        'aircrack-ng': 'sudo apt install -y aircrack-ng',
        'kismet': 'sudo apt install -y kismet',
        'arp-scan': 'sudo apt install -y arp-scan',
        'ffuf': 'sudo apt install -y ffuf',
        'tor': 'sudo apt install -y tor',
        'whois': 'sudo apt install -y whois',
        'sslscan': 'sudo apt install -y sslscan',
        'wpscan': 'sudo gem install wpscan',
        'searchsploit': 'sudo apt install -y exploitdb',
        'gvm-cli': 'sudo apt install -y gvm',
        'whatweb': 'sudo apt install -y whatweb',
        'wafw00f': 'sudo apt install -y wafw00f',
        'feroxbuster': 'sudo apt install -y feroxbuster',
        'droopescan': 'sudo apt install -y droopescan',
        'joomscan': 'sudo apt install -y joomscan',
        'linpeas': 'curl -s https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh -o /usr/local/bin/linpeas && chmod +x /usr/local/bin/linpeas',
        'winpeas': 'curl -s -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -o /usr/local/bin/winpeas.exe',
        'pspy': 'curl -s -L https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /usr/local/bin/pspy64 && chmod +x /usr/local/bin/pspy64',
        'linenum': 'curl -s https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o /usr/local/bin/linenum && chmod +x /usr/local/bin/linenum',
        'unix-privesc-check': 'sudo apt install -y unix-privesc-check',
        'windows-privesc-check': 'curl -s https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/unix-privesc-check -o /usr/local/bin/windows-privesc-check && chmod +x /usr/local/bin/windows-privesc-check',
    },
    'darwin': {  # macOS
        'nmap': 'brew install nmap',
        'nc': 'brew install netcat',
        'traceroute': 'brew install traceroute',
        'enum4linux': 'brew install enum4linux',
        'snmpwalk': 'brew install net-snmp',
        'nikto': 'brew install nikto',
        'gobuster': 'brew install gobuster',
        'dirb': 'brew install dirb',
        'hping3': 'brew install hping',
        'proxychains': 'brew install proxychains-ng',
        'aircrack-ng': 'brew install aircrack-ng',
        'kismet': 'brew install kismet',
        'arp-scan': 'brew install arp-scan',
        'ffuf': 'brew install ffuf',
        'tor': 'brew install tor',
        'whois': 'brew install whois',
        'sslscan': 'brew install sslscan',
        'wpscan': 'brew install wpscan',
        'searchsploit': 'brew install exploitdb',
        'gvm-cli': 'brew install gvm',
        'whatweb': 'brew install whatweb',
        'wafw00f': 'brew install wafw00f',
        'feroxbuster': 'brew install feroxbuster',
        'droopescan': 'brew install droopescan',
        'joomscan': 'brew install joomscan',
        'linpeas': 'curl -s https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh -o /usr/local/bin/linpeas && chmod +x /usr/local/bin/linpeas',
        'winpeas': 'curl -s -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -o /usr/local/bin/winpeas.exe',
        'pspy': 'curl -s -L https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /usr/local/bin/pspy64 && chmod +x /usr/local/bin/pspy64',
        'linenum': 'curl -s https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o /usr/local/bin/linenum && chmod +x /usr/local/bin/linenum',
        'unix-privesc-check': 'brew install unix-privesc-check',
        'windows-privesc-check': 'curl -s https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/unix-privesc-check -o /usr/local/bin/windows-privesc-check && chmod +x /usr/local/bin/windows-privesc-check',
    },
    'windows': {
        'nmap': 'choco install nmap -y',
        'nc': 'choco install netcat -y',
        'tracert': 'built-in',
        'nikto': 'choco install nikto -y',
        'gobuster': 'choco install gobuster -y',
        'aircrack-ng': 'choco install aircrack-ng -y',
        'ffuf': 'choco install ffuf -y',
        'tor': 'choco install tor -y',
        'whois': 'choco install whois -y',
        'sslscan': 'choco install sslscan -y',
        'whatweb': 'choco install whatweb -y',
        'winpeas': 'curl -s -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -o C:\\Windows\\System32\\winpeas.exe',
        'pspy': 'curl -s -L https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64.exe -o C:\\Windows\\System32\\pspy64.exe',
        'windows-privesc-check': 'curl -s https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/master/unix-privesc-check -o C:\\Windows\\System32\\windows-privesc-check.exe',
        # wpscan, searchsploit, gvm-cli may require manual install or are not available on Windows
    }
}

# Detect OS
system = platform.system().lower()
if system.startswith('linux'):
    os_type = 'linux'
elif system == 'darwin':
    os_type = 'darwin'
elif system == 'windows':
    os_type = 'windows'
else:
    console.print(f"[red]Unsupported OS: {system}[/red]")
    sys.exit(1)

# Adjust for Windows traceroute
if os_type == 'windows':
    REQUIRED_TOOLS = [t if t != 'traceroute' else 'tracert' for t in REQUIRED_TOOLS]

missing_tools = []
missing_modules = []
unsupported_tools = []
installed_tools = []

# Exclude unsupported tools from progress bar total
checkable_tools = [t for t in REQUIRED_TOOLS if not (os_type == 'windows' and t in UNSUPPORTED_ON_WINDOWS)]
total_checks = len(checkable_tools) + len(PYTHON_MODULES)

console.print("[bold cyan]Checking dependencies...[/bold cyan]")
with Progress(TextColumn("{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total}")) as progress:
    task = progress.add_task("Checking system tools...", total=total_checks)
    for tool in REQUIRED_TOOLS:
        if os_type == 'windows' and tool in UNSUPPORTED_ON_WINDOWS:
            console.print(f"[yellow]! {tool} (unsupported on Windows)[/yellow]")
            unsupported_tools.append(tool)
            continue  # Do not advance progress for unsupported tools
        if shutil.which(tool):
            console.print(f"[green]✔ {tool}[/green]")
            installed_tools.append(tool)
        else:
            console.print(f"[red]✖ {tool} (not found)[/red]")
            missing_tools.append(tool)
        progress.advance(task)
    for mod in PYTHON_MODULES:
        try:
            __import__(mod)
            console.print(f"[green]✔ Python module: {mod}[/green]")
        except ImportError:
            console.print(f"[red]✖ Python module: {mod} (not found)[/red]")
            missing_modules.append(mod)
        progress.advance(task)

# Summary Table
summary_table = Table(title="Dependency Check Summary", show_lines=True)
summary_table.add_column("Status", style="bold")
summary_table.add_column("Tool/Module")

for tool in installed_tools:
    summary_table.add_row("[green]Installed[/green]", tool)
for tool in missing_tools:
    summary_table.add_row("[red]Missing[/red]", tool)
for tool in unsupported_tools:
    summary_table.add_row("[yellow]Unsupported[/yellow]", tool)
for mod in PYTHON_MODULES:
    if mod in missing_modules:
        summary_table.add_row("[red]Missing[/red]", f"Python: {mod}")
    else:
        summary_table.add_row("[green]Installed[/green]", f"Python: {mod}")

console.print(summary_table)

# Add a user-friendly note for netcat/nc on Windows
if os_type == 'windows' and shutil.which('nc') is None:
    console.print("[yellow]Note: 'nc' (netcat) may require manual install or use of an alternative on Windows. Try 'ncat' from Nmap or install netcat via Chocolatey.[/yellow]")

# Add user-friendly notes for tools that may require manual install or are not available on Windows
if os_type == 'windows':
    for tool in ['wpscan', 'searchsploit', 'gvm-cli', 'wafw00f', 'feroxbuster', 'droopescan', 'joomscan']:
        if shutil.which(tool) is None:
            console.print(f"[yellow]Note: '{tool}' may require manual install or is not natively available on Windows. Consider using WSL or a Linux VM for full functionality.[/yellow]")

if not missing_tools and not missing_modules and not unsupported_tools:
    console.print("[bold green]All dependencies satisfied![/bold green]")
    sys.exit(0)

console.print("\n[bold yellow]Some required tools are missing or unsupported.[/bold yellow]")
if missing_tools:
    console.print("[yellow]Missing system tools:[/yellow] " + ", ".join(missing_tools))
if missing_modules:
    console.print("[yellow]Missing Python modules:[/yellow] " + ", ".join(missing_modules))
if unsupported_tools:
    console.print("[yellow]Unsupported on this OS:[/yellow] " + ", ".join(unsupported_tools))
    console.print("[bold yellow]Features requiring these tools will be disabled.[/bold yellow]")

# Only prompt to install if there are installable missing tools
installable_tools = [t for t in missing_tools if t in INSTALL_COMMANDS[os_type]]
if installable_tools or missing_modules:
    install = console.input("\n[bold]Would you like to install the missing tools now? (Y/n): [/bold]").strip().lower()
    if install and install != 'y':
        console.print("[bold red]Warning: Some features will be unavailable. Continue at your own risk.[/bold red]")
        sys.exit(1)

    # Helper: Detect dpkg/apt errors in output
    DPKG_ERROR_HINTS = [
        'dpkg-divert: error',
        'dpkg: error processing archive',
        'Error: Sub-process /usr/bin/dpkg returned an error code',
        'Errors were encountered while processing:',
        'is a disabled or a static unit not running',
        'returned error exit status',
        'unable to lock the administration directory',
        'You might want to run',
    ]

    def check_for_dpkg_errors(output_lines):
        for line in output_lines:
            for hint in DPKG_ERROR_HINTS:
                if hint in line:
                    return True
        return False

    # Helper: Try to install pip if missing (Linux only)
    def ensure_pip():
        if os_type == 'linux':
            try:
                import pip
                return True
            except ImportError:
                console.print("[yellow]pip not found. Attempting to install python3-pip...[/yellow]")
                try:
                    proc = subprocess.Popen('sudo apt update && sudo apt install -y python3-pip', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    for line in proc.stdout:
                        console.print(line.rstrip())
                    proc.wait()
                    if proc.returncode == 0:
                        console.print("[green]✔ python3-pip installed[/green]")
                        return True
                    else:
                        console.print("[red]✖ Failed to install python3-pip (exit code {proc.returncode})[/red]")
                except Exception as e:
                    console.print(f"[red]✖ Failed to install python3-pip: {e}[/red]")
        return False

    # Before installing Python modules, ensure pip is present
    if missing_modules:
        pip_ok = True
        try:
            import pip
        except ImportError:
            pip_ok = ensure_pip()
        if not pip_ok:
            console.print("[bold red]pip is required to install Python modules. Please install python3-pip and rerun the checker.[/bold red]")
            sys.exit(1)

    # Install missing system tools
    with Progress(TextColumn("{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total}")) as progress:
        task = progress.add_task("Installing system tools...", total=len(installable_tools) + len(missing_modules))
        for tool in installable_tools:
            # Skip install if already present
            if shutil.which(tool):
                console.print(f"[green]✔ {tool} already installed, skipping.[/green]")
                progress.advance(task)
                continue
            cmd = INSTALL_COMMANDS[os_type].get(tool)
            if not cmd or cmd == 'built-in':
                console.print(f"[yellow]Skipping {tool} (no install command or built-in)[/yellow]")
                progress.advance(task)
                continue
            console.print(f"[cyan]Installing {tool}...[/cyan]")
            # Warn if not admin on Windows
            if os_type == 'windows' and not is_admin():
                console.print(f"[bold red]Warning: Installing {tool} may require running this script as Administrator![/bold red]")
            try:
                # Use streaming logic only for interactive/slow tools
                if tool in INTERACTIVE_TOOLS:
                    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    start_time = time.time()
                    timeout = 120  # 2 minutes per tool
                    output_lines = []
                    while True:
                        if proc.poll() is not None:
                            break
                        line = proc.stdout.readline()
                        if line:
                            console.print(line.rstrip())
                            output_lines.append(line.rstrip())
                        if time.time() - start_time > timeout:
                            proc.kill()
                            console.print(f"[red]✖ Timeout installing {tool}[/red]")
                            if tool in INTERACTIVE_TOOLS:
                                console.print(f"[yellow]The installation of {tool} may require manual input (e.g., group membership). Please install it manually using:[/yellow]")
                                console.print(f"[white]sudo apt-get install {tool}[/white]")
                                if INTERACTIVE_TOOLS[tool].get('note'):
                                    console.print(f"[yellow]{INTERACTIVE_TOOLS[tool]['note']}[/yellow]")
                                if INTERACTIVE_TOOLS[tool].get('post_install'):
                                    console.print("[bold cyan]Post-install instructions:[/bold cyan]")
                                    for step in INTERACTIVE_TOOLS[tool]['post_install']:
                                        console.print(f"[white]- {step}[/white]")
                            else:
                                console.print(f"[yellow]If the install hangs, try installing {tool} manually in your terminal.[/yellow]")
                            break
                    # Print any remaining output
                    for line in proc.stdout:
                        console.print(line.rstrip())
                        output_lines.append(line.rstrip())
                    if check_for_dpkg_errors(output_lines):
                        console.print("\n[bold red]Your system's package manager (APT/dpkg) is currently broken.[/bold red]")
                        console.print("This is a system-level issue that prevents installing any new software, including Python modules and security tools.")
                        console.print("\n[bold yellow]To fix this, please run the following commands in your terminal:[/bold yellow]")
                        console.print("""
[white]sudo dpkg --configure -a
sudo apt-get install -f
sudo apt-get update
sudo apt-get upgrade[/white]
""")
                        console.print("If you see errors about diversions (e.g., /lib32), also run:")
                        console.print("""
[white]sudo dpkg-divert --remove /lib32
sudo apt-get install --reinstall base-files[/white]
""")
                        console.print("After fixing the package manager, rerun this tool to continue the setup.")
                        sys.exit(1)
                    if proc.returncode == 0:
                        console.print(f"[green]✔ {tool} installed[/green]")
                        if tool in INTERACTIVE_TOOLS:
                            if INTERACTIVE_TOOLS[tool].get('post_install'):
                                console.print("[bold cyan]Post-install instructions for {tool}:[/bold cyan]".format(tool=tool))
                                for step in INTERACTIVE_TOOLS[tool]['post_install']:
                                    console.print(f"[white]- {step}[/white]")
                    else:
                        console.print(f"[red]✖ Failed to install {tool} (exit code {proc.returncode})[/red]")
                        console.print(f"[yellow]If you installed {tool} manually, make sure it is in your PATH. Try running '{tool} --help' in your terminal. Some tools may require additional steps or a different package name.[/yellow]")
                else:
                    # Fast path for most tools
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
                    if result.stdout:
                        for line in result.stdout.splitlines():
                            console.print(line)
                    if result.stderr:
                        for line in result.stderr.splitlines():
                            console.print(f"[red]{line}[/red]")
                    if result.returncode == 0:
                        console.print(f"[green]✔ {tool} installed[/green]")
                    else:
                        console.print(f"[red]✖ Failed to install {tool} (exit code {result.returncode})[/red]")
                        console.print(f"[yellow]If you installed {tool} manually, make sure it is in your PATH. Try running '{tool} --help' in your terminal. Some tools may require additional steps or a different package name.[/yellow]")
                progress.advance(task)
            except Exception as e:
                console.print(f"[red]✖ Failed to install {tool}: {e}[/red]")
                console.print(f"[yellow]If you installed {tool} manually, make sure it is in your PATH. Try running '{tool} --help' in your terminal. Some tools may require additional steps or a different package name.[/yellow]")
            progress.advance(task)
        for mod in missing_modules:
            console.print(f"[cyan]Installing Python module: {mod}...[/cyan]")
            try:
                proc = subprocess.Popen([sys.executable, '-m', 'pip', 'install', mod], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                start_time = time.time()
                timeout = 120
                pip_output = []
                while True:
                    if proc.poll() is not None:
                        break
                    line = proc.stdout.readline()
                    if line:
                        console.print(line.rstrip())
                        pip_output.append(line.rstrip())
                    if time.time() - start_time > timeout:
                        proc.kill()
                        console.print(f"[red]✖ Timeout installing {mod}[/red]")
                        break
                for line in proc.stdout:
                    console.print(line.rstrip())
                    pip_output.append(line.rstrip())
                # Check for externally-managed-environment error
                if any('externally managed' in l.lower() or 'externally-managed-environment' in l.lower() for l in pip_output):
                    apt_pkg = PYTHON_MODULE_APT.get(mod)
                    if apt_pkg and os_type == 'linux':
                        console.print(f"[yellow]System Python is externally managed. Attempting to install {mod} via apt as {apt_pkg}...[/yellow]")
                        apt_cmd = f'sudo apt-get install -y {apt_pkg}'
                        try:
                            apt_proc = subprocess.Popen(apt_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                            for apt_line in apt_proc.stdout:
                                console.print(apt_line.rstrip())
                            apt_proc.wait()
                            if apt_proc.returncode == 0:
                                console.print(f"[green]✔ {mod} installed via apt as {apt_pkg}[/green]")
                            else:
                                console.print(f"[red]✖ Failed to install {mod} via apt (exit code {apt_proc.returncode})[/red]")
                                console.print(f"[yellow]You can try manually: sudo apt-get install {apt_pkg}[/yellow]")
                        except Exception as e:
                            console.print(f"[red]✖ Failed to install {mod} via apt: {e}[/red]")
                            console.print(f"[yellow]You can try manually: sudo apt-get install {apt_pkg}[/yellow]")
                    else:
                        console.print(f"[red]✖ {mod} cannot be installed via pip in an externally managed environment.[/red]")
                        console.print(f"[yellow]Try installing it via your package manager, e.g.: sudo apt-get install python3-{mod}[/yellow]")
                elif proc.returncode == 0:
                    console.print(f"[green]✔ {mod} installed[/green]")
                else:
                    console.print(f"[red]✖ Failed to install {mod} (exit code {proc.returncode})[/red]")
            except Exception as e:
                console.print(f"[red]✖ Failed to install {mod}: {e}[/red]")
            progress.advance(task)

console.print("[bold green]\nDependency check and installation complete![/bold green]")
if unsupported_tools:
    console.print("[bold yellow]The following features will be disabled due to unsupported tools: " + ", ".join(unsupported_tools) + "[/bold yellow]")

def is_admin():
    if os.name == 'nt':
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        return os.geteuid() == 0 