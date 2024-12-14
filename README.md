# ag_paketi
Ağ üzerindeki transferleri izleyebileceğiniz basit bir kod.

Özellikler
Ağ arayüzü üzerinden paketleri canlı olarak yakalama.
Her paket hakkında temel bilgi (paket uzunluğu ve ilk 64 bayt) gösterme.
Kolayca yapılandırılabilir ve derlenebilir.
Gereksinimler
libpcap kütüphanesi: Linux üzerinde ağ paketlerini yakalamak için kullanılan bir kütüphanedir.
GCC veya başka bir C derleyicisi.
Linux'ta libpcap Kurulumu
Programı derlemek ve çalıştırmak için libpcap kütüphanesini yüklemeniz gerekecek. Aşağıdaki komut ile kurulumu yapabilirsiniz:

bash
Kodu kopyala
sudo apt-get install libpcap-dev
Kurulum
Bu repoyu bilgisayarınıza klonlayın:

bash
Kodu kopyala
git clone https://github.com/<kullanıcı_adınız>/packet-sniffer.git
cd packet-sniffer
Programı derlemek için aşağıdaki komutu çalıştırın:

bash
Kodu kopyala
gcc -o packet_sniffer packet_sniffer.c -lpcap
Kullanım
Çalıştırma
Programı çalıştırmak için root yetkileri gerekebilir. Ağ arayüzünü dinlerken yönetici (root) izinlerine sahip olmalısınız. Aşağıdaki komutla çalıştırabilirsiniz:

bash
Kodu kopyala
sudo ./packet_sniffer
Program, cihazınızın ağ arayüzünü dinlemeye başlayacak ve her yakalanan paketin özetini yazdıracaktır.

Çıktı Örneği
Program her yakalanan paket için şu bilgileri yazdıracaktır:

python
Kodu kopyala
Packet captured: Length = 64 bytes
00 1f d2 23 5a f8 00 1f d2 23 5a f8 08 00 45 00
00 28 1c 46 40 00 40 06 b1 e6 c0 a8 00 68 c0 a8
00 01 50 01 50 00 06 00 00 00 00 00 00 00 00 00
...
İlk satır, paketin uzunluğunu gösterir.
Ardından, paket verisinin ilk 64 baytı hexadecimal formatta listelenir.
Kodu Anlama
packet_sniffer.c
Bu dosyada, libpcap kütüphanesini kullanarak ağ arayüzünden veri yakalanır. Her paket yakalandığında, packet_handler fonksiyonu çalışır ve paketin başlık bilgileri ile ilk 64 baytı ekrana yazdırılır.

packet_handler Fonksiyonu
packet_handler fonksiyonu, her paket alındığında çağrılır ve şu bilgileri yazdırır:

Paket uzunluğu
Paket verisinin ilk 64 baytı
pcap_open_live
Bu fonksiyon, belirtilen ağ arayüzünden canlı veri yakalamak için kullanılır.

pcap_loop
Bu fonksiyon, sürekli olarak paketleri dinler ve her paketi işlemek için packet_handler fonksiyonunu çağırır.

Katkı
Eğer projeye katkıda bulunmak isterseniz, aşağıdaki adımları izleyebilirsiniz:

Bu repoyu forklayın.
Yeni bir özellik ekleyin veya hatayı düzeltin.
Pull request gönderin.

# ENG

Features
Capture live packets from a network interface.
Display basic packet information (packet length and the first 64 bytes).
Easy to configure and compile.
Requirements
libpcap library: A library used for capturing network packets on Linux systems.
GCC or another C compiler.
Installing libpcap on Linux
To compile and run the program, you will need to install the libpcap library. You can do this with the following command:

bash
Kodu kopyala
sudo apt-get install libpcap-dev
Installation
Clone this repository to your local machine:

bash
Kodu kopyala
git clone https://github.com/<your_username>/packet-sniffer.git
cd packet-sniffer
Compile the program using the following command:

bash
Kodu kopyala
gcc -o packet_sniffer packet_sniffer.c -lpcap
Usage
Running the Program
To run the program, you may need root privileges to access the network interface. Use the following command:

bash
Kodu kopyala
sudo ./packet_sniffer
The program will start listening on your device's network interface and print the summary of each captured packet.

Example Output
For each captured packet, the program will print the following:

python
Kodu kopyala
Packet captured: Length = 64 bytes
00 1f d2 23 5a f8 00 1f d2 23 5a f8 08 00 45 00
00 28 1c 46 40 00 40 06 b1 e6 c0 a8 00 68 c0 a8
00 01 50 01 50 00 06 00 00 00 00 00 00 00 00 00
...
The first line shows the length of the packet.
The next lines show the first 64 bytes of the packet in hexadecimal format.
Understanding the Code
packet_sniffer.c
This file captures live data from the network interface using the libpcap library. For each captured packet, the packet_handler function is called, which prints the packet's header information and the first 64 bytes of the packet.

packet_handler Function
The packet_handler function is called whenever a packet is captured. It prints:

The packet's length.
The first 64 bytes of the packet data in hexadecimal format.
pcap_open_live
This function is used to open the network interface for live packet capture.

pcap_loop
This function starts an infinite loop, capturing packets continuously, and calls the packet_handler function to process each captured packet.

Contributing
If you want to contribute to this project, you can follow these steps:

Fork this repository.
Add a feature or fix a bug.
Submit a pull request.
