#include <stdio.h>
#include <pcap.h>

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // Paket başlık bilgilerini yazdırıyoruz
    printf("Packet captured: Length = %d bytes\n", pkthdr->len);
    
    // Paket verilerini yazdırıyoruz (ilk 64 byte)
    for(int i = 0; i < 64 && i < pkthdr->len; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Ağ arayüzünü seçiyoruz (örneğin "eth0" veya "wlan0")
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("Error finding network device: %s\n", errbuf);
        return 1;
    }

    printf("Using device: %s\n", dev);

    // pcap açma işlemi
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error opening device %s: %s\n", dev, errbuf);
        return 1;
    }

    // Paket yakalamak için döngü başlatıyoruz
    printf("Starting packet capture...\n");
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        printf("Error capturing packets: %s\n", pcap_geterr(handle));
        return 1;
    }

    // pcap kapatma
    pcap_close(handle);
    return 0;
}
