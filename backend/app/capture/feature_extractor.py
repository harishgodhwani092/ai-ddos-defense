from dataclasses import dataclass, asdict
from statistics import mean, variance
from collections import Counter

FEATURES=['packets_per_second','bytes_per_second','packets_per_flow','bytes_per_flow','flow_duration','source_ip_frequency','destination_ip_frequency','unique_source_ips','unique_destination_ports','tcp_ratio','udp_ratio','icmp_ratio','syn_rate','ack_rate','syn_ack_ratio','average_packet_size','packet_size_variance','connection_rate','failed_short_connection_rate']
@dataclass
class TrafficWindow:
    packets_per_second: float; bytes_per_second: float; packets_per_flow: float; bytes_per_flow: float; flow_duration: float; source_ip_frequency: float; destination_ip_frequency: float; unique_source_ips: int; unique_destination_ports: int; tcp_ratio: float; udp_ratio: float; icmp_ratio: float; syn_rate: float; ack_rate: float; syn_ack_ratio: float; average_packet_size: float; packet_size_variance: float; connection_rate: float; failed_short_connection_rate: float
    def as_dict(self): return asdict(self)
class FeatureExtractor:
    def extract(self, records, duration=None):
        records=list(records); n=len(records); duration=max(float(duration or 1),0.001)
        sizes=[float(r.get('size',r.get('packet_size',0))) for r in records]
        src=Counter(r.get('source_ip','unknown') for r in records); dst=Counter(r.get('destination_ip','unknown') for r in records)
        prot=Counter(str(r.get('protocol','OTHER')).upper() for r in records); tcp=prot['TCP']
        syn=sum(1 for r in records if 'S' in str(r.get('flags',''))); ack=sum(1 for r in records if 'A' in str(r.get('flags','')))
        short=sum(1 for r in records if float(r.get('flow_duration',duration))<1)
        avg=mean(sizes) if sizes else 0; var=variance(sizes) if len(sizes)>1 else 0
        return TrafficWindow(n/duration,sum(sizes)/duration,n/max(len(src),1),sum(sizes)/max(len(src),1),duration,max(src.values(),default=0),max(dst.values(),default=0),len(src),len(set(r.get('destination_port') for r in records)),tcp/max(n,1),prot['UDP']/max(n,1),prot['ICMP']/max(n,1),syn/duration,ack/duration,syn/max(ack,1),avg,var,n/duration,short/max(n,1))
