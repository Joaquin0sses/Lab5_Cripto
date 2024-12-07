from scapy.all import rdpcap
import hashlib

# Cargar el archivo pcap
packets = rdpcap("C4-S1.pcapng")

for packet in packets:
    if packet.haslayer("Raw"):  # Extraer contenido bruto del paquete
        data = packet["Raw"].load
        if b"SSH-2.0" in data:  # Filtrar mensajes SSH
            print("Mensaje SSH detectado:", data)

# Suponiendo que tenemos los algoritmos extraídos:
algorithms = "diffie-hellman-group14-sha1;aes256-cbc;hmac-sha1;none"
hassh = hashlib.md5(algorithms.encode()).hexdigest()
print("HASSH:", hassh)