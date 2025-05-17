# PCAP to CSV & Excel Converter

Bu proje, `.pcap` dosyalarındaki ağ trafiği verilerini ayrıştırarak (parse ederek) yapılandırılmış **CSV** ve **Excel** formatına dönüştüren bir Python aracıdır.

## 🚀 Özellikler

- `.pcap` dosyasından ağ paketlerini okur.
- Belirli alanları çıkarıp kullanıcıya özel sütunlar oluşturur.
- Verileri `.csv` ve `.xlsx` dosyalarına kaydeder.

## 🧰 Gereksinimler

Python kütüphaneleri:
nest_asyncio
pyshark
pandas
numpy


Yüklemek için:

```bash
git clone https://github.com/kemalyurduseven/Pcap_Parser.git
cd Pcap_Parser

pip install -r requirements.txt

sudo apt-get install tshark

Kullanım:

cap = pyshark.FileCapture('path to file pcap') # "path to file pcap" bu alana pcap dosyasının yolu gelecek.

df.to_csv('path to file csv', index=False) # "path to file csv" bu alana oluşturmak istediğiniz csv dosyasının adı.
df.to_excel('path to file xlsx', index=False) # "path to file xlsx" bu alana oluşturmak istediğiniz excel dosyasının adı.

python pcap_parse.py
