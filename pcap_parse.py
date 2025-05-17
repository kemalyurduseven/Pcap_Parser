import nest_asyncio
import pyshark
import pandas as pd
import numpy as np

# Event loop'u yeniden başlat
nest_asyncio.apply()

# PCAP dosyasını yükle
cap = pyshark.FileCapture('path to file pcap')

# DataFrame sütunları
columns = [
    'Flow ID', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port',
    'Protocol', 'Timestamp', 'Packet Length', 'SYN Flag', 'ACK Flag', 'FIN Flag'
]
df = pd.DataFrame(columns=columns)


def extract_protocol(packet):
    try:
        layers = [layer.layer_name.upper() for layer in packet.layers]

        if 'QUIC' in layers:
            return 'QUIC'
        elif 'TLS' in layers:
            if 'TLSV1.3' in str(packet):
                return 'TLSv1.3'
            elif 'TLSV1.2' in str(packet):
                return 'TLSv1.2'
            else:
                return 'TLS'
        elif 'DTLS' in layers:
            if 'DTLSV1.2' in str(packet):
                return 'DTLSv1.2'
            else:
                return 'DTLS'
        elif 'RTCP' in layers:
            return 'RTCP'
        elif 'STUN' in layers:
            return 'STUN'
        elif 'OCSP' in layers:
            return 'OCSP'
        elif 'HTTP' in layers:
            return 'HTTP'
        elif 'SSDP' in layers:
            return 'SSDP'
        elif 'NTP' in layers:
            return 'NTP'
        elif 'DNS' in layers:
            return 'DNS'
        elif 'MDNS' in layers:
            return 'MDNS'
        elif 'LLMNR' in layers:
            return 'LLMNR'
        elif 'DHCPV6' in layers or 'BOOTP' in layers:
            return 'DHCPv6'
        elif 'IGMP' in layers:
            if 'IGMPV3' in str(packet):
                return 'IGMPv3'
            elif 'IGMPV2' in str(packet):
                return 'IGMPv2'
            else:
                return 'IGMP'
        elif 'ICMPV6' in layers:
            return 'ICMPv6'
        elif 'ICMP' in layers:
            return 'ICMP'
        elif 'ARP' in layers:
            return 'ARP'
        elif 'TCP' in layers:
            return 'TCP'
        elif 'UDP' in layers:
            return 'UDP'
        else:
            return 'OTHER'
    except Exception:
        return 'UNKNOWN'

# Paketleri işleme
for i, packet in enumerate(cap):
    try:
        if not hasattr(packet, 'ip'):
            continue


        protocol = extract_protocol(packet)

        try:
            if packet.transport_layer in ['TCP', 'UDP']:
                src_port = getattr(packet[packet.transport_layer], 'srcport', np.nan)
                dst_port = getattr(packet[packet.transport_layer], 'dstport', np.nan)
            else:
                src_port = np.nan
                dst_port = np.nan
        except:
            src_port = np.nan
            dst_port = np.nan

        flow_id = f"{packet.ip.src}-{packet.ip.dst}-{src_port}-{dst_port}"

        row = {
            'Flow ID': flow_id,
            'Source IP': packet.ip.src,
            'Destination IP': packet.ip.dst,
            'Source Port': src_port,
            'Destination Port': dst_port,
            'Protocol': protocol,
            'Timestamp': packet.sniff_time,
            'Packet Length': packet.length,
            'SYN Flag': int(packet.tcp.flags_syn) if 'tcp' in packet else 0,
            'ACK Flag': int(packet.tcp.flags_ack) if 'tcp' in packet else 0,
            'FIN Flag': int(packet.tcp.flags_fin) if 'tcp' in packet else 0,
            'RST Flag': int(packet.tcp.flags_reset) if 'tcp' in packet else 0
        }

        df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)

    except AttributeError:
        continue

    if i % 100 == 0:
        print(f"{i} paket işlendi...")

# Veri temizliği ve dönüşümleri
df.replace("", np.nan, inplace=True)
df['Packet Length'] = pd.to_numeric(df['Packet Length'], errors='coerce')
df['Source Port'] = pd.to_numeric(df['Source Port'], errors='coerce')
df['Destination Port'] = pd.to_numeric(df['Destination Port'], errors='coerce')
df['Timestamp'] = pd.to_datetime(df['Timestamp'])

# Gruplama
grouped = df.groupby('Flow ID')
df['Flow Duration'] = grouped['Timestamp'].transform(lambda x: (x.max() - x.min()).total_seconds())
df['Total Fwd Packets'] = grouped['Source IP'].transform('size')
df['Total Bwd Packets'] = grouped['Destination IP'].transform('size')
df['Total Length of Fwd Packets'] = grouped['Packet Length'].transform('sum')
df['Total Length of Bwd Packets'] = grouped['Packet Length'].transform('sum')
df['Fwd Packet Length Max'] = grouped['Packet Length'].transform('max')
df['Fwd Packet Length Min'] = grouped['Packet Length'].transform('min')
df['Fwd Packet Length Mean'] = grouped['Packet Length'].transform('mean')
df['Fwd Packet Length Std'] = grouped['Packet Length'].transform('std')
df['Bwd Packet Length Max'] = grouped['Packet Length'].transform('max')
df['Bwd Packet Length Min'] = grouped['Packet Length'].transform('min')
df['Bwd Packet Length Mean'] = grouped['Packet Length'].transform('mean')
df['Bwd Packet Length Std'] = grouped['Packet Length'].transform('std')
df['Flow Bytes/s'] = df['Total Length of Fwd Packets'] / df['Flow Duration'].replace(0, 1)
df['Flow Packets/s'] = df['Total Fwd Packets'] / df['Flow Duration'].replace(0, 1)

# RST Flag sütunu (yoksa dummy 0 değerli olacak)
if 'RST Flag' not in df.columns:
    df['RST Flag'] = 0  # yoksa dummy

# Flow bazında bayrak sayımları
df['SYN Flag Count'] = df.groupby('Flow ID')['SYN Flag'].transform('sum')
df['ACK Flag Count'] = df.groupby('Flow ID')['ACK Flag'].transform('sum')
df['FIN Flag Count'] = df.groupby('Flow ID')['FIN Flag'].transform('sum')
df['RST Flag Count'] = df.groupby('Flow ID')['RST Flag'].transform('sum')


def label_ddos(df):
    attack_ip = '192.168.1.1'
    udp_ports = [21, 22, 53, 80, 443]
    syn_ports = [80, 443]
    http_ports = [80, 443]
    slowloris_ports = [80, 443]

    def classify(row):
        dest_ip = row['Destination IP']
        dst_port = row['Destination Port']
        proto = row['Protocol']
        syn = row.get('SYN Flag', 0)
        ack = row.get('ACK Flag', 0)
        fin = row.get('FIN Flag', 0)

        # Saldırgan IP dışındakiler benign
        if dest_ip != attack_ip:
            return 'BENIGN'

        # UDP Flood
        if proto == 'UDP' and dst_port in udp_ports:
            return 'DDOS'

        # ICMP Flood
        if proto == 'ICMP':
            return 'DDOS'

        # SYN Flood
        if proto == 'TCP' and syn == 1 and dst_port in syn_ports:
            return 'DDOS'

        # HTTP Flood
        if proto == 'HTTP' and dst_port in http_ports:
            return 'DDOS'

        # Slowloris
        if proto == 'TCP' and dst_port in slowloris_ports and syn == 1 and ack == 0 and fin == 0:
            return 'DDOS'

        return 'BENIGN'

    df['Label'] = df.apply(classify, axis=1)
    return df

df = label_ddos(df)

# Kayıt
print(df.head(10))
df.to_csv('path to file csv', index=False)
df.to_excel('path to file xlsx', index=False)
