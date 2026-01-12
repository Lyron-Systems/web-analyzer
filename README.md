# Lyron Web Scanner v2

Termux ve Linux için basit ama etkili web zafiyet tarama aracı  
2025 - Lyron Systems

# Özellikler
- Directory / dosya brute-force
- Basit subdomain enumeration
- Admin panel arama
- Crawler + temel form zafiyet testi (SQLi, XSS, LFI, Command Injection)

## Kurulum 

 # 1. Projeyi klonla
git clone https://github.com/KULLANICI_ADIN/lyron-web-scanner.git

cd lyron-web-scanner

# 2. Sanal ortam (opsiyonel ama önerilir)
python -m venv venv
source venv/bin/activate    # Linux / macOS
 veya Windows'ta: venv\Scripts\activate

 # 3. Bağımlılıkları kur
pip install -r requirements.txt

3 Kullanım:
python web_analyzerv2.py
