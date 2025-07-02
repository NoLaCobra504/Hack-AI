from . import portscan, service, vuln, web

def run_scan(scan_type, target, report_path=None, level='basic'):
    if scan_type == 'portscan':
        return portscan.run(target, report_path)
    if scan_type == 'service':
        return service.run(target, report_path, level=level)
    if scan_type == 'vuln':
        return vuln.run(target, report_path)
    if scan_type == 'web':
        return web.run(target, report_path)
    raise ValueError(f"Unknown scan type: {scan_type}")



