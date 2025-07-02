"""
Service Enumeration Module

This module handles service enumeration (banner grabbing, version detection) for the AI-powered ethical hacking tool.
"""

import subprocess
from modules import report_utils

def run(target, report_path=None, level='basic'):
    """Run service enumeration at the specified level and append results as a section in the unified report."""
    if report_path is None:
        report_path = report_utils.get_report_name(cve_id=None)
    report_utils.init_report(report_path, target)
    print(f"[ServiceEnum] Running service enumeration on: {target} (level: {level})")
    findings = {}
    commands = []
    notable = []
    recommendations = []
    raw_output = {}

    # --- BASIC LEVEL ---
    methodology = [
        "Performed service and version detection using Nmap (-sV).",
    ]
    nmap_sv_cmd = ['nmap', '-sV', target]
    try:
        nmap_sv_out = subprocess.check_output(nmap_sv_cmd, stderr=subprocess.STDOUT, text=True)
        findings['nmap_service_version'] = nmap_sv_out
        raw_output['nmap_service_version'] = nmap_sv_out
        commands.append(' '.join(nmap_sv_cmd))
        if 'open' in nmap_sv_out:
            notable.append("Services detected on open ports.")
    except Exception as e:
        findings['nmap_service_version'] = f"Error: {e}"
        raw_output['nmap_service_version'] = str(e)

    # --- INTERMEDIATE LEVEL ---
    if level in ['intermediate', 'advanced', 'stealth']:
        methodology.append("Banner grabbing on common ports using Netcat and Telnet.")
        # Example: banner grabbing for top ports (22, 80, 443, 21, 25, 110, 143)
        common_ports = [22, 80, 443, 21, 25, 110, 143]
        for port in common_ports:
            nc_cmd = ['nc', '-nv', target, str(port)]
            try:
                nc_out = subprocess.run(nc_cmd, input='\n', capture_output=True, text=True, timeout=5)
                banner = nc_out.stdout.strip() or nc_out.stderr.strip()
                findings[f'nc_banner_{port}'] = banner
                raw_output[f'nc_banner_{port}'] = banner
                commands.append(' '.join(nc_cmd))
                if banner:
                    notable.append(f"Banner detected on port {port}.")
            except Exception as e:
                findings[f'nc_banner_{port}'] = f"Error: {e}"
                raw_output[f'nc_banner_{port}'] = str(e)

    # --- ADVANCED LEVEL ---
    if level in ['advanced', 'stealth']:
        methodology.append("Protocol-specific enumeration using Nmap NSE scripts and additional tools.")
        # Example: SMB, SNMP, FTP, SSH, HTTP enumeration
        # SMB
        smb_cmd = ['nmap', '-p445', '--script', 'smb-enum-shares,smb-enum-users', target]
        try:
            smb_out = subprocess.check_output(smb_cmd, stderr=subprocess.STDOUT, text=True)
            findings['smb_enum'] = smb_out
            raw_output['smb_enum'] = smb_out
            commands.append(' '.join(smb_cmd))
            if 'Shares' in smb_out or 'Users' in smb_out:
                notable.append("SMB shares or users enumerated.")
        except Exception as e:
            findings['smb_enum'] = f"Error: {e}"
            raw_output['smb_enum'] = str(e)
        # SNMP
        snmp_cmd = ['nmap', '-sU', '-p161', '--script', 'snmp-info', target]
        try:
            snmp_out = subprocess.check_output(snmp_cmd, stderr=subprocess.STDOUT, text=True)
            findings['snmp_info'] = snmp_out
            raw_output['snmp_info'] = snmp_out
            commands.append(' '.join(snmp_cmd))
            if 'SNMP' in snmp_out:
                notable.append("SNMP information enumerated.")
        except Exception as e:
            findings['snmp_info'] = f"Error: {e}"
            raw_output['snmp_info'] = str(e)
        # FTP
        ftp_cmd = ['nmap', '-p21', '--script', 'ftp-anon,ftp-bounce,ftp-syst', target]
        try:
            ftp_out = subprocess.check_output(ftp_cmd, stderr=subprocess.STDOUT, text=True)
            findings['ftp_enum'] = ftp_out
            raw_output['ftp_enum'] = ftp_out
            commands.append(' '.join(ftp_cmd))
            if 'Anonymous FTP login allowed' in ftp_out:
                notable.append("Anonymous FTP login allowed.")
        except Exception as e:
            findings['ftp_enum'] = f"Error: {e}"
            raw_output['ftp_enum'] = str(e)
        # SSH
        ssh_cmd = ['nmap', '-p22', '--script', 'ssh2-enum-algos,ssh-hostkey', target]
        try:
            ssh_out = subprocess.check_output(ssh_cmd, stderr=subprocess.STDOUT, text=True)
            findings['ssh_enum'] = ssh_out
            raw_output['ssh_enum'] = ssh_out
            commands.append(' '.join(ssh_cmd))
            if 'ssh-hostkey' in ssh_out:
                notable.append("SSH hostkey and algorithms enumerated.")
        except Exception as e:
            findings['ssh_enum'] = f"Error: {e}"
            raw_output['ssh_enum'] = str(e)
        # HTTP
        http_cmd = ['nmap', '-p80,443', '--script', 'http-title,http-headers,http-methods', target]
        try:
            http_out = subprocess.check_output(http_cmd, stderr=subprocess.STDOUT, text=True)
            findings['http_enum'] = http_out
            raw_output['http_enum'] = http_out
            commands.append(' '.join(http_cmd))
            if 'http-title' in http_out:
                notable.append("HTTP service titles and headers enumerated.")
        except Exception as e:
            findings['http_enum'] = f"Error: {e}"
            raw_output['http_enum'] = str(e)

    # --- STEALTH LEVEL ---
    if level == 'stealth':
        methodology.append("Stealthy enumeration using slow timing, fragmented packets, and evasion techniques.")
        stealth_cmd = ['nmap', '-sV', '-T1', '-f', '--max-retries', '2', target]
        try:
            stealth_out = subprocess.check_output(stealth_cmd, stderr=subprocess.STDOUT, text=True)
            findings['nmap_stealth'] = stealth_out
            raw_output['nmap_stealth'] = stealth_out
            commands.append(' '.join(stealth_cmd))
            if 'open' in stealth_out:
                notable.append("Stealth scan detected open services.")
        except Exception as e:
            findings['nmap_stealth'] = f"Error: {e}"
            raw_output['nmap_stealth'] = str(e)

    # Recommendations
    recommendations.append("Review detected services and versions for vulnerabilities.")
    if level in ['intermediate', 'advanced', 'stealth']:
        recommendations.append("Investigate banners and protocol-specific findings for misconfigurations or weak/default credentials.")
    if level in ['advanced', 'stealth']:
        recommendations.append("Review protocol-specific enumeration results for further attack surface.")
    if level == 'stealth':
        recommendations.append("Consider using additional evasion techniques if target is highly monitored.")

    report_utils.append_section(
        report_path,
        section_title=f"Service Enumeration ({level.title()})",
        methodology='\n'.join(methodology),
        commands=commands,
        findings=findings,
        notable=notable,
        recommendations=recommendations,
        raw_output=raw_output
    )
    return {
        "status": "success",
        "target": target,
        "report": report_path,
        "findings": findings,
        "notable": notable,
        "recommendations": recommendations,
        "level": level
    } 