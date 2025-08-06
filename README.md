# 🛡️ SOC Telegram Bot

A comprehensive Security Operations Center (SOC) assistant bot for Telegram that provides threat intelligence analysis, MITRE ATT&CK framework lookup, and cybersecurity educational resources.

## 🚀 Features

### 🔍 **Threat Intelligence Analysis**
- **IP Address Analysis** - Check IP reputation via AbuseIPDB with risk scoring
- **Domain Analysis** - VirusTotal domain reputation checking
- **URL Scanning** - Real-time URL analysis through VirusTotal
- **File Hash Lookup** - MD5/SHA1/SHA256 hash analysis
- **WHOIS Lookup** - Domain and IP registration information

### 🎯 **MITRE ATT&CK Integration**
- Complete MITRE ATT&CK framework database
- 12 tactical categories with Russian translations
- 15+ techniques and subtechniques
- Searchable by ID, name, or description
- Instant response (no freezing or delays)

### 📚 **Cybersecurity Education**
- **Cyber Kill Chain** - 7-phase attack lifecycle explanation
- **OWASP Top 10** - Web application security risks
- **OSI Model** - 7-layer network model reference
- **TCP/IP Model** - 4-layer internet protocol stack

### 🔐 **Security Features**
- Private bot with owner-only access by default
- User authorization system for multi-user deployments
- Input sanitization and validation
- Rate limiting protection
- Secure API key management

## 📋 Prerequisites

- Python 3.7+
- Telegram Bot Token (from [@BotFather](https://t.me/BotFather))
- VirusTotal API Key ([Get here](https://www.virustotal.com/gui/my-apikey))
- AbuseIPDB API Key ([Get here](https://www.abuseipdb.com/api))
- Your Telegram User ID ([Get from @userinfobot](https://t.me/userinfobot))

## 🛠️ Installation

### Method 1: Environment Variables (Recommended for servers)

```bash
# Clone the repository
git clone https://github.com/yourusername/soc-telegram-bot.git
cd soc-telegram-bot

# Install dependencies
pip3 install python-telegram-bot aiohttp python-whois requests

# Set environment variables
export TELEGRAM_TOKEN="your_bot_token_from_botfather"
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
export OWNER_ID="your_telegram_user_id"

# Run the bot
python3 bot_interactive.py
```

### Method 2: Interactive Configuration

```bash
# Run the bot - it will prompt for configuration
python3 bot_interactive.py

# Follow the interactive setup to enter:
# - Telegram Bot Token
# - VirusTotal API Key  
# - AbuseIPDB API Key
# - Your Telegram User ID
```

### Method 3: Manual Configuration File

Create `.bot_config.json`:

```json
{
  "TELEGRAM_TOKEN": "your_bot_token",
  "VIRUSTOTAL_API_KEY": "your_virustotal_key",
  "ABUSEIPDB_API_KEY": "your_abuseipdb_key", 
  "OWNER_ID": your_telegram_user_id
}
```

## 🎮 Usage

### Basic Commands

- `/start` - Initialize bot and show main menu
- `/help` - Display all available commands

### Threat Analysis Commands

- `/ip 8.8.8.8` - Analyze IP address reputation
- `/domain example.com` - Check domain reputation
- `/url https://example.com` - Scan URL for threats
- `/hash abc123...` - Lookup file hash (MD5/SHA1/SHA256)
- `/whois example.com` - Get WHOIS information

### MITRE ATT&CK Commands

- `/mitre` - Show MITRE ATT&CK overview
- `/mitre T1566` - Lookup specific technique by ID
- `/mitre phishing` - Search techniques by keyword
- `/mitre TA0001` - Get tactic information

### Educational Commands

- `/killchain` - Cyber Kill Chain phases
- `/owasp` - OWASP Top 10 vulnerabilities
- `/osi` - OSI 7-layer model
- `/tcpip` - TCP/IP 4-layer model

### Administrative Commands (Owner only)

- `/admin` - Access user management panel
- Add/remove authorized users via inline buttons

## 🖼️ Interface

The bot provides both **command-line interface** and **interactive menu buttons**:

### Main Menu
- 🔍 **Анализ IOC** (IOC Analysis)
- 🎯 **MITRE ATT&CK** 
- 📚 **Обучение** (Education)
- ⚙️ **Админка** (Admin - owner only)

### IOC Analysis Submenu
- **IP** - IP address analysis
- **Domain** - Domain reputation
- **URL** - URL scanning
- **Hash** - File hash lookup
- **Whois** - Registration info

## 🔧 Configuration Details

### API Keys Setup

1. **Telegram Bot Token**:
   - Message [@BotFather](https://t.me/BotFather)
   - Create new bot with `/newbot`
   - Save the provided token

2. **VirusTotal API**:
   - Register at [VirusTotal](https://www.virustotal.com)
   - Go to [API Key page](https://www.virustotal.com/gui/my-apikey)
   - Copy your 64-character API key

3. **AbuseIPDB API**:
   - Register at [AbuseIPDB](https://www.abuseipdb.com)
   - Go to [API page](https://www.abuseipdb.com/api)
   - Generate 80-character API key

4. **Telegram User ID**:
   - Message [@userinfobot](https://t.me/userinfobot)
   - Note your numeric user ID

### Running as Service (Linux)

Create systemd service file:

```bash
sudo nano /etc/systemd/system/soc-bot.service
```

```ini
[Unit]
Description=SOC Telegram Bot
After=network.target

[Service]
Type=simple
User=your_user
WorkingDirectory=/path/to/bot
Environment=TELEGRAM_TOKEN=your_token
Environment=VIRUSTOTAL_API_KEY=your_key
Environment=ABUSEIPDB_API_KEY=your_key  
Environment=OWNER_ID=your_id
ExecStart=/usr/bin/python3 bot_interactive.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable soc-bot
sudo systemctl start soc-bot
```

## 📊 Example Outputs

### IP Analysis
```
📊 Результаты проверки IP: 8.8.8.8

🔹 Уровень риска: Низкий 🟢 (0%)
🔹 Страна: US  
🔹 Провайдер: Google LLC
🔹 Тип использования: hosting
🔹 Количество жалоб: 0
🔹 Последняя жалоба: Never

[VirusTotal] [AbuseIPDB] [Shodan]
```

### MITRE Lookup
```
🎯 ТАКТИКА MITRE ATT&CK

Название: Первоначальный доступ (Initial Access)
ID: TA0001

Описание:
Техники получения первоначального доступа к сети жертвы.

Связанные техники (5):
• T1566: Фишинг (Phishing)
• T1190: Эксплуатация публичных приложений
• T1078: Действительные учетные записи
```

## 🛡️ Security Considerations

- ✅ All user inputs are sanitized and validated
- ✅ API keys are never logged or exposed
- ✅ Private bot mode prevents unauthorized access  
- ✅ Rate limiting prevents API abuse
- ✅ Secure session management
- ✅ No sensitive data stored in logs

## 🐛 Troubleshooting

### Bot Not Starting
```bash
# Check Python version
python3 --version  # Should be 3.7+

# Install missing dependencies
pip3 install -r requirements.txt

# Check configuration
python3 -c "import json; print(json.load(open('.bot_config.json')))"
```

### API Errors
- **401 Unauthorized**: Check API keys are correct
- **429 Rate Limited**: Wait and try again, check quotas
- **403 Forbidden**: Verify API key has required permissions

### Bot Not Responding
- Verify bot token is active with [@BotFather](https://t.me/BotFather)
- Check your Telegram ID matches OWNER_ID
- Review logs for error messages

## 📝 Dependencies

```txt
python-telegram-bot==20.7
aiohttp==3.9.1
python-whois==0.8.0
requests==2.31.0
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⭐ Support

If this project helped you, please give it a ⭐ on GitHub!

For questions or issues, please open a GitHub issue.

---

**Made with ❤️ for SOC analysts and cybersecurity professionals**
