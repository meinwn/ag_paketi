#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <time.h>

// Paket türlerini yazdırmak için fonksiyonlar
void print_ethertype(u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    printf("Ethernet Type: %x\n", ntohs(eth_header->ether_type));
}

void print_ip_header(const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    printf("IP Header:\n");
    printf("  Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("  Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
}

void print_tcp_header(const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    
    printf("TCP Header:\n");
    printf("  Source Port: %u\n", ntohs(tcp_header->th_sport));
    printf("  Destination Port: %u\n", ntohs(tcp_header->th_dport));
}

void print_udp_header(const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    
    printf("UDP Header:\n");
    printf("  Source Port: %u\n", ntohs(udp_header->uh_sport));
    printf("  Destination Port: %u\n", ntohs(udp_header->uh_dport));
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // Paket zaman bilgisini yazdırıyoruz
    time_t timestamp = pkthdr->ts.tv_sec;
    struct tm *time_info = localtime(&timestamp);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", time_info);
    printf("Timestamp: %s\n", time_str);

    // Paket türünü yazdırıyoruz (Ethernet)
    print_ethertype(packet);

    // IP başlığını yazdırıyoruz
    print_ip_header(packet);

    // Protokol bilgisine göre TCP veya UDP başlıklarını yazdırıyoruz
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    if (ip_header->ip_p == IPPROTO_TCP) {
        print_tcp_header(packet);
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        print_udp_header(packet);
    }

    // Paket verilerini yazdırıyoruz (ilk 64 bayt)
    printf("Packet data (first 64 bytes):\n");
    for (int i = 0; i < 64 && i < pkthdr->len; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Ağ arayüzünü seçiyoruz
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

    // Filtreleme eklemek için bir örnek (TCP paketleri)
    struct bpf_program fp;
    char filter_exp[] = "tcp";  // TCP paketlerini filtrele
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Paket yakalama işlemi
    printf("Starting packet capture...\n");
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        printf("Error capturing packets: %s\n", pcap_geterr(handle));
        return 1;
    }

    // pcap kapama
    pcap_close(handle);
    return 0;
}
