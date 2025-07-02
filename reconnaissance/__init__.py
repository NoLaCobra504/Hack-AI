from . import passive, active, dns, osint, whois, shodan, cert

def run_recon(recon_type, target):
    if recon_type == 'passive':
        return passive.run(target)
    if recon_type == 'active':
        return active.run(target)
    if recon_type == 'dns':
        return dns.run(target)
    if recon_type == 'osint':
        return osint.run(target)
    if recon_type == 'whois':
        return whois.run(target)
    if recon_type == 'shodan':
        return shodan.run(target)
    if recon_type == 'cert':
        return cert.run(target)
    raise ValueError(f"Unknown recon type: {recon_type}") 