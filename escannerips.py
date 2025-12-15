import nmap

def escanear_puertos_nmap(ip_objetivo, puertos='1-1024'):
    """Escanea puertos específicos en una IP usando nmap."""
    nm = nmap.PortScanner()
    # Escanea la IP en el rango de puertos especificado
    nm.scan(ip_objetivo, puertos) 
    
    print(f"Resultados para {ip_objetivo}:")
    for host in nm.all_hosts():
        print(f'Host : {host} ({nm[host].hostname()})')
        print(f'Estado: {nm[host].state()}')
        for proto in nm[host].all_protocols():
            print('----------')
            print(f'Protocolo: {proto}')
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                print(f'  Puerto : {port}\tEstado: {nm[host][proto][port]["state"]}')

# Ejemplo de uso:
if __name__ == '__main__':
    print("Iniciando escaneo de puertos...")
    # Reemplaza '192.168.1.1' con una IP de tu red
    escanear_puertos_nmap('192.168.110.1', '22-80') 
