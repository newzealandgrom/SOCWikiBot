#!/usr/bin/env python3
"""
SOC Telegram Bot - Simple single script version
Run: python3 bot_interactive.py

Set environment variables:
export TELEGRAM_TOKEN="your_token"
export VIRUSTOTAL_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"
export OWNER_ID="your_telegram_id"
"""

import logging
import os
import json
import asyncio
import aiohttp
import whois
import ipaddress
import re
import pickle
import os.path
import getpass
from datetime import datetime
from threading import Lock
from typing import Optional, Dict, Any
from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    ReplyKeyboardMarkup,
    KeyboardButton,
)
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# Настройка логирования
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)

def setup_credentials():
    """Настройка учетных данных (интерактивная или через переменные окружения)"""
    config_file = ".bot_config.json"
    
    # Проверяем переменные окружения сначала
    env_config = {}
    if os.getenv('VIRUSTOTAL_API_KEY'):
        env_config['VIRUSTOTAL_API_KEY'] = os.getenv('VIRUSTOTAL_API_KEY')
    if os.getenv('ABUSEIPDB_API_KEY'):
        env_config['ABUSEIPDB_API_KEY'] = os.getenv('ABUSEIPDB_API_KEY')
    if os.getenv('TELEGRAM_TOKEN'):
        env_config['TELEGRAM_TOKEN'] = os.getenv('TELEGRAM_TOKEN')
    if os.getenv('OWNER_ID'):
        try:
            env_config['OWNER_ID'] = int(os.getenv('OWNER_ID'))
        except ValueError:
            pass
    
    # Если все переменные окружения установлены, используем их
    if len(env_config) == 4:
        print("✅ Используется конфигурация из переменных окружения")
        return env_config
    
    # Проверяем существующий конфиг
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                print("✅ Найден существующий конфигурационный файл.")
                
                # Проверяем, есть ли интерактивный режим (tty)
                try:
                    import sys
                    if not sys.stdin.isatty():
                        print("🤖 Запуск в неинтерактивном режиме, используется существующий конфиг")
                        return config
                except:
                    return config
                
                try:
                    use_existing = input("Использовать существующие настройки? (y/n): ").lower().strip()
                    if use_existing in ['y', 'yes', 'да', '']:
                        return config
                except (EOFError, KeyboardInterrupt):
                    return config
        except Exception as e:
            print(f"⚠️ Ошибка чтения конфига: {e}")
    
    # Проверяем интерактивный режим
    try:
        import sys
        if not sys.stdin.isatty():
            print("❌ Не найдена конфигурация и нет интерактивного терминала")
            print("Установите переменные окружения:")
            print("export TELEGRAM_TOKEN='your_bot_token'")
            print("export VIRUSTOTAL_API_KEY='your_vt_key'") 
            print("export ABUSEIPDB_API_KEY='your_abuse_key'")
            print("export OWNER_ID='your_telegram_id'")
            print("Или создайте файл .bot_config.json с конфигурацией")
            return None
    except:
        print("❌ Нет конфигурации. Установите переменные окружения или создайте .bot_config.json")
        return None
    
    print("🔧 Настройка SOC Telegram Bot")
    print("=" * 50)
    
    config = {}
    
    # VirusTotal API Key
    print("\n🔍 VirusTotal API Key:")
    print("Получить можно на: https://www.virustotal.com/gui/my-apikey")
    while True:
        try:
            vt_key = input("Введите VirusTotal API Key: ").strip()
            if len(vt_key) >= 64:  # VirusTotal keys are 64 chars
                config['VIRUSTOTAL_API_KEY'] = vt_key
                break
            else:
                print("❌ Некорректный API ключ. Должен быть длиной 64 символа.")
        except (EOFError, KeyboardInterrupt):
            print("\n❌ Настройка прервана")
            return None
    
    # AbuseIPDB API Key
    print("\n🛡️ AbuseIPDB API Key:")
    print("Получить можно на: https://www.abuseipdb.com/api")
    while True:
        try:
            abuse_key = input("Введите AbuseIPDB API Key: ").strip()
            if len(abuse_key) >= 80:  # AbuseIPDB keys are 80 chars
                config['ABUSEIPDB_API_KEY'] = abuse_key
                break
            else:
                print("❌ Некорректный API ключ. Должен быть длиной 80 символов.")
        except (EOFError, KeyboardInterrupt):
            print("\n❌ Настройка прервана")
            return None
    
    # Telegram Bot Token
    print("\n🤖 Telegram Bot Token:")
    print("Получить можно у @BotFather в Telegram")
    while True:
        try:
            tg_token = input("Введите Telegram Bot Token: ").strip()
            if ':' in tg_token and len(tg_token.split(':')[1]) >= 30:
                config['TELEGRAM_TOKEN'] = tg_token
                break
            else:
                print("❌ Некорректный токен. Формат: 123456789:ABC-DEF1234ghIkl-zyx57W2v1u123ew11")
        except (EOFError, KeyboardInterrupt):
            print("\n❌ Настройка прервана")
            return None
    
    # Owner ID
    print("\n👤 Owner ID (ваш Telegram ID):")
    print("Узнать можно у @userinfobot в Telegram")
    while True:
        try:
            owner_input = input("Введите ваш Telegram User ID: ").strip()
            owner_id = int(owner_input)
            if owner_id > 0:
                config['OWNER_ID'] = owner_id
                break
            else:
                print("❌ ID должен быть положительным числом.")
        except ValueError:
            print("❌ Введите корректное число.")
        except (EOFError, KeyboardInterrupt):
            print("\n❌ Настройка прервана")
            return None
    
    # Сохраняем конфиг
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"\n✅ Конфигурация сохранена в {config_file}")
        print("🔒 Этот файл содержит ваши API ключи. Не делитесь им!")
        
        # Создаем .gitignore если его нет
        if not os.path.exists('.gitignore'):
            with open('.gitignore', 'w') as f:
                f.write(".bot_config.json\n*.pkl\n__pycache__/\n*.log\n")
            print("✅ Создан .gitignore для защиты ваших ключей")
        
    except Exception as e:
        print(f"❌ Ошибка сохранения конфига: {e}")
        return None
    
    return config

# Global variables to be set after config loading
VIRUSTOTAL_API_KEY = None
ABUSEIPDB_API_KEY = None
TELEGRAM_TOKEN = None
OWNER_ID = None

# ======================
#   Управление доступом
# ======================
ALLOWED_USERS_FILE = "allowed_users.pkl"
ALLOWED_USERS = []

# Загрузка сохраненного списка авторизованных пользователей (если файл существует)
if os.path.exists(ALLOWED_USERS_FILE):
    try:
        with open(ALLOWED_USERS_FILE, "rb") as f:
            ALLOWED_USERS = pickle.load(f)
            logging.info(f"Загружены авторизованные пользователи: {ALLOWED_USERS}")
    except Exception as e:
        logging.error(f"Не удалось загрузить список пользователей: {e}")

# ======================
#   Кэш для MITRE ATT&CK
# ======================
MITRE_CACHE_FILE = "mitre_cache.pkl"
mitre_cache_lock = Lock()
MITRE_CACHE = {
    "tactics": [],
    "techniques": [],
    "subtechniques": [],
    "last_update": None,
}

# Очищаем старый кэш MITRE при запуске (на случай изменения структуры данных)
if os.path.exists(MITRE_CACHE_FILE):
    try:
        os.remove(MITRE_CACHE_FILE)
        logging.info("Удален старый кэш MITRE для избежания ошибок структуры данных")
    except Exception as e:
        logging.error(f"Не удалось удалить старый кэш MITRE: {e}")

# ======================
#  Вспомогательные функции
# ======================

def sanitize_input(text: str, max_length: int = 200) -> str:
    """Санитаризация пользовательского ввода"""
    if not isinstance(text, str):
        return ""
    # Удаляем опасные символы и ограничиваем длину
    sanitized = re.sub(r'[<>"\'\/\\]', '', text.strip())
    return sanitized[:max_length]

def validate_ip(ip_str: str) -> bool:
    """Проверка корректности IP-адреса"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_domain(domain: str) -> bool:
    """Проверка корректности доменного имени"""
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'  # домен
        r'[a-zA-Z]{2,}$'  # TLD
    )
    return bool(domain_pattern.match(domain)) and len(domain) <= 253

def validate_url(url: str) -> bool:
    """Проверка корректности URL"""
    url_pattern = re.compile(
        r'^https?://'  # http:// или https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  # домен
        r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # TLD
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # порт
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return bool(url_pattern.match(url)) and len(url) <= 2000

def validate_hash(hash_str: str) -> bool:
    """Проверка корректности хеша (MD5, SHA1, SHA256)"""
    hash_patterns = {
        32: r'^[a-fA-F0-9]{32}$',  # MD5
        40: r'^[a-fA-F0-9]{40}$',  # SHA1
        64: r'^[a-fA-F0-9]{64}$'   # SHA256
    }
    hash_len = len(hash_str)
    if hash_len in hash_patterns:
        return bool(re.match(hash_patterns[hash_len], hash_str))
    return False

async def rate_limit_check(user_id: int, action: str) -> bool:
    """Простая проверка rate limiting (можно расширить)"""
    # В данной реализации - заглушка, можно добавить Redis или SQLite для хранения
    return True

async def check_access(update: Update) -> bool:
    """Проверяет, имеет ли пользователь доступ к боту."""
    user_id = update.effective_user.id
    logging.info(f"User {user_id} trying to access bot. Owner ID: {OWNER_ID}")
    
    if user_id != OWNER_ID and user_id not in ALLOWED_USERS:
        # Если пользователь не в списке, отказываем в доступе
        await update.message.reply_text(
            f"⛔️ Этот бот является приватным. Ваш ID: {user_id}. Обратитесь к владельцу для получения доступа."
        )
        logging.warning(f"Попытка доступа от неавторизованного пользователя: {user_id}")
        return False
    return True

def save_allowed_users():
    """Сохраняет список ALLOWED_USERS в файл."""
    try:
        with open(ALLOWED_USERS_FILE, "wb") as f:
            pickle.dump(ALLOWED_USERS, f)
            logging.info(f"Список пользователей сохранен ({len(ALLOWED_USERS)} записей).")
    except Exception as e:
        logging.error(f"Ошибка при сохранении списка пользователей: {e}")

def save_mitre_cache():
    """Сохраняет кэш MITRE в файл."""
    try:
        with mitre_cache_lock:
            with open(MITRE_CACHE_FILE, "wb") as f:
                pickle.dump(MITRE_CACHE, f)
                logging.info(
                    f"MITRE cache saved, tactics: {len(MITRE_CACHE['tactics'])}, techniques: {len(MITRE_CACHE['techniques'])}"
                )
    except Exception as e:
        logging.error(f"Error saving MITRE cache: {e}")

def get_tactics_for_technique(technique_obj):
    """Возвращает список тактик (названий фаз ATT&CK), к которым относится техника."""
    tactics = []
    for phase in technique_obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            tactics.append(phase.get("phase_name", ""))
    return tactics

def get_russian_name(name_en: str) -> str:
    """Возвращает русскоязычное название для заданного английского (если определено)."""
    # В данной версии реализация упрощена, можно расширить сопоставления при необходимости
    # Санитаризация ввода
    if not isinstance(name_en, str):
        return ""
    return name_en.strip()[:200]  # Ограничиваем длину

async def fetch_mitre_data():
    """Получает данные MITRE ATT&CK через веб-скрапинг."""
    now = datetime.now()
    
    # Проверяем кэш (обновляем каждые 7 дней)
    with mitre_cache_lock:
        if (MITRE_CACHE["last_update"] and 
            (now - MITRE_CACHE["last_update"]).days < 7 and 
            MITRE_CACHE["tactics"]):
            return MITRE_CACHE
    
    # Загружаем компактные данные
    with mitre_cache_lock:
        MITRE_CACHE.update(get_comprehensive_mitre_data())
        MITRE_CACHE["last_update"] = now
    
    return MITRE_CACHE

def get_comprehensive_mitre_data():
    """Возвращает полную базу данных MITRE ATT&CK."""
    return {
        "tactics": [
            {"id": "TA0001", "name": "Initial Access", "name_ru": "Первоначальный доступ", 
             "description": "Техники получения первоначального доступа к сети жертвы."},
            {"id": "TA0002", "name": "Execution", "name_ru": "Выполнение", 
             "description": "Техники запуска вредоносного кода в системе жертвы."},
            {"id": "TA0003", "name": "Persistence", "name_ru": "Закрепление", 
             "description": "Техники сохранения присутствия в системе."},
            {"id": "TA0004", "name": "Privilege Escalation", "name_ru": "Повышение привилегий", 
             "description": "Техники получения более высоких прав доступа."},
            {"id": "TA0005", "name": "Defense Evasion", "name_ru": "Обход защиты", 
             "description": "Техники избежания обнаружения защитными системами."},
            {"id": "TA0006", "name": "Credential Access", "name_ru": "Доступ к учетным данным", 
             "description": "Техники кражи учетных данных."},
            {"id": "TA0007", "name": "Discovery", "name_ru": "Разведка", 
             "description": "Техники получения информации о системе и сети."},
            {"id": "TA0008", "name": "Lateral Movement", "name_ru": "Горизонтальное движение", 
             "description": "Техники перемещения по сети жертвы."},
            {"id": "TA0009", "name": "Collection", "name_ru": "Сбор данных", 
             "description": "Техники сбора данных интересующих злоумышленника."},
            {"id": "TA0010", "name": "Command and Control", "name_ru": "Управление", 
             "description": "Техники связи с скомпрометированными системами."},
            {"id": "TA0011", "name": "Exfiltration", "name_ru": "Извлечение", 
             "description": "Техники кражи данных из сети жертвы."},
            {"id": "TA0040", "name": "Impact", "name_ru": "Воздействие", 
             "description": "Техники нарушения работы систем, данных или сети."},
        ],
        "techniques": [
            {"id": "T1566", "name": "Phishing", "name_ru": "Фишинг", "tactics": ["initial-access"],
             "description": "Отправка фишинговых сообщений для получения доступа к системам."},
            {"id": "T1059", "name": "Command and Scripting Interpreter", "name_ru": "Интерпретаторы команд", "tactics": ["execution"],
             "description": "Выполнение команд через интерпретаторы командной строки."},
            {"id": "T1053", "name": "Scheduled Task/Job", "name_ru": "Запланированные задачи", "tactics": ["execution", "persistence"],
             "description": "Создание запланированных задач для выполнения кода."},
            {"id": "T1055", "name": "Process Injection", "name_ru": "Внедрение в процесс", "tactics": ["defense-evasion", "privilege-escalation"],
             "description": "Внедрение кода в запущенные процессы."},
            {"id": "T1027", "name": "Obfuscated Files or Information", "name_ru": "Обфускация", "tactics": ["defense-evasion"],
             "description": "Сокрытие файлов и информации от анализа."},
            {"id": "T1003", "name": "OS Credential Dumping", "name_ru": "Извлечение учетных данных ОС", "tactics": ["credential-access"],
             "description": "Получение учетных данных из операционной системы."},
            {"id": "T1082", "name": "System Information Discovery", "name_ru": "Получение информации о системе", "tactics": ["discovery"],
             "description": "Сбор информации о системе и конфигурации."},
            {"id": "T1021", "name": "Remote Services", "name_ru": "Удаленные сервисы", "tactics": ["lateral-movement"],
             "description": "Использование удаленных сервисов для движения по сети."},
            {"id": "T1005", "name": "Data from Local System", "name_ru": "Данные с локальной системы", "tactics": ["collection"],
             "description": "Сбор данных с локальной системы жертвы."},
            {"id": "T1071", "name": "Application Layer Protocol", "name_ru": "Протоколы прикладного уровня", "tactics": ["command-and-control"],
             "description": "Использование стандартных протоколов для скрытой связи."},
            {"id": "T1041", "name": "Exfiltration Over C2 Channel", "name_ru": "Извлечение через канал управления", "tactics": ["exfiltration"],
             "description": "Кража данных через существующий канал управления."},
            {"id": "T1486", "name": "Data Encrypted for Impact", "name_ru": "Шифрование данных для воздействия", "tactics": ["impact"],
             "description": "Шифрование данных для нарушения их доступности."},
            {"id": "T1190", "name": "Exploit Public-Facing Application", "name_ru": "Эксплуатация публичных приложений", "tactics": ["initial-access"],
             "description": "Использование уязвимостей в публично доступных приложениях."},
            {"id": "T1078", "name": "Valid Accounts", "name_ru": "Действительные учетные записи", "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
             "description": "Использование легитимных учетных записей для доступа."},
            {"id": "T1574", "name": "Hijack Execution Flow", "name_ru": "Перехват потока выполнения", "tactics": ["persistence", "privilege-escalation", "defense-evasion"],
             "description": "Изменение способа выполнения программ в системе."},
        ],
        "subtechniques": [
            {"id": "T1566.001", "name": "Spearphishing Attachment", "parent": "T1566", "tactics": ["initial-access"],
             "description": "Фишинг с вредоносным вложением."},
            {"id": "T1566.002", "name": "Spearphishing Link", "parent": "T1566", "tactics": ["initial-access"],
             "description": "Фишинг со ссылкой на вредоносный ресурс."},
            {"id": "T1059.001", "name": "PowerShell", "parent": "T1059", "tactics": ["execution"],
             "description": "Выполнение команд через PowerShell."},
            {"id": "T1059.003", "name": "Windows Command Shell", "parent": "T1059", "tactics": ["execution"],
             "description": "Выполнение команд через командную строку Windows."},
            {"id": "T1055.001", "name": "Dynamic-link Library Injection", "parent": "T1055", "tactics": ["defense-evasion", "privilege-escalation"],
             "description": "Внедрение DLL в процессы."},
        ],
        "last_update": datetime.now(),
    }

def get_fallback_mitre_data():
    """Возвращает резервные данные MITRE."""
    return get_comprehensive_mitre_data()

# ======================
#     Основные команды
# ======================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обрабатывает команду /start: приветствие и вывод главного меню."""
    if not await check_access(update):
        return
    user = update.effective_user
    # Формируем кнопки главного меню
    main_menu_buttons = [
        [KeyboardButton("Анализ IOC"), KeyboardButton("MITRE ATT&CK")],
        [KeyboardButton("Обучение")],
    ]
    # Добавляем кнопку "Админка" только для владельца
    if user.id == OWNER_ID:
        main_menu_buttons[1].append(KeyboardButton("Админка"))
    reply_markup = ReplyKeyboardMarkup(main_menu_buttons, resize_keyboard=True)
    await update.message.reply_html(
        f"Привет, {user.mention_html()}! 👋\n\n"
        f"Я бот-помощник для аналитика SOC. Вот что я умею:\n\n"
        f"🔍 <b>Команды для проверки:</b>\n"
        f"/ip [IP] – проверить IP-адрес\n"
        f"/domain [домен] – проверить домен\n"
        f"/url [URL] – проверить URL\n"
        f"/hash [hash] – проверить хэш файла\n"
        f"/whois [домен/IP] – получить WHOIS информацию\n\n"
        f"📚 <b>Справочники:</b>\n"
        f"/mitre [запрос] – поиск в MITRE ATT&CK\n"
        f"/killchain – фазы Cyber Kill Chain\n"
        f"/owasp – OWASP Top 10\n"
        f"/osi – модель OSI\n"
        f"/tcpip – модель TCP/IP\n\n"
        f"📰 <b>Дополнительные команды:</b>\n"
        f"/help – справка по командам",
        reply_markup=reply_markup,
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обрабатывает команду /help: выводит справку по командам."""
    if not await check_access(update):
        return
    help_text = (
        "📖 <b>Справка по командам</b>\n\n"
        "<b>Основные:</b>\n"
        "/start – начать работу с ботом (приветствие и меню)\n"
        "/help – показать эту справку\n\n"
        "<b>Анализ IOC:</b>\n"
        "/ip [IP] – проверить репутацию IP-адреса\n"
        "/domain [домен] – проверить репутацию домена\n"
        "/url [URL] – проверить репутацию URL\n"
        "/hash [hash] – проверить хэш файла\n"
        "/whois [домен/IP] – получить WHOIS информацию\n\n"
        "<b>Справочники:</b>\n"
        "/mitre [тактика/техника/ID] – поиск в MITRE ATT&CK\n"
        "/killchain – фазы Cyber Kill Chain\n"
        "/owasp – OWASP Top 10 уязвимостей\n"
        "/osi – модель OSI\n"
        "/tcpip – модель TCP/IP\n"
    )
    await update.message.reply_html(help_text)

# ======= Функции анализа IOC (VirusTotal, AbuseIPDB, WHOIS) =======

async def check_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /ip – проверка IP-адреса через AbuseIPDB и ссылки на VirusTotal/Shodan."""
    if not await check_access(update):
        return
    if not context.args:
        await update.message.reply_text(
            "Пожалуйста, укажите IP-адрес. Пример: /ip 8.8.8.8"
        )
        return
    
    ip = sanitize_input(context.args[0])
    if not validate_ip(ip):
        await update.message.reply_text(
            "⚠️ Некорректный IP-адрес. Пожалуйста, проверьте формат."
        )
        return
    
    if not await rate_limit_check(update.effective_user.id, "ip_check"):
        await update.message.reply_text(
            "⚠️ Слишком много запросов. Подождите немного."
        )
        return
        
    await update.message.reply_text(f"🔍 Проверяю IP-адрес: {ip}...")
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data_json = await response.json()
                    data = data_json.get("data", {})
                    abuse_score = data.get("abuseConfidenceScore", 0)
                    country = data.get("countryCode", "Unknown")
                    isp = data.get("isp", "Unknown")
                    usage_type = data.get("usageType", "Unknown")
                    total_reports = data.get("totalReports", 0)
                    last_reported = data.get("lastReportedAt", "Never")
                    # Определяем уровень риска по abuse score
                    risk_level = "Низкий 🟢"
                    if abuse_score > 80:
                        risk_level = "Высокий 🔴"
                    elif abuse_score > 30:
                        risk_level = "Средний 🟠"
                    message = (
                        f"📊 <b>Результаты проверки IP: {ip}</b>\n\n"
                        f"🔹 <b>Уровень риска:</b> {risk_level} ({abuse_score}%)\n"
                        f"🔹 <b>Страна:</b> {country}\n"
                        f"🔹 <b>Провайдер:</b> {isp}\n"
                        f"🔹 <b>Тип использования:</b> {usage_type}\n"
                        f"🔹 <b>Количество жалоб:</b> {total_reports}\n"
                        f"🔹 <b>Последняя жалоба:</b> {last_reported}\n\n"
                    )
                    # Кнопки: переход на VirusTotal, AbuseIPDB, Shodan
                    keyboard = [
                        [
                            InlineKeyboardButton(
                                "VirusTotal",
                                url=f"https://www.virustotal.com/gui/ip-address/{ip}",
                            ),
                            InlineKeyboardButton(
                                "AbuseIPDB", url=f"https://www.abuseipdb.com/check/{ip}"
                            ),
                        ],
                        [
                            InlineKeyboardButton(
                                "Shodan", url=f"https://www.shodan.io/host/{ip}"
                            )
                        ],
                    ]
                    reply_markup = InlineKeyboardMarkup(keyboard)
                    await update.message.reply_html(message, reply_markup=reply_markup)
                else:
                    logging.error(f"AbuseIPDB API error: {response.status}")
                    await update.message.reply_text(
                        f"⚠️ Ошибка при проверке IP: {response.status}"
                    )
    except asyncio.TimeoutError:
        logging.error(f"Timeout during IP check for user {update.effective_user.id}")
        await update.message.reply_text("⚠️ Тайм-аут запроса. Попробуйте позже.")
    except Exception as e:
        logging.error(f"Error in IP check: {str(e)}")
        await update.message.reply_text("⚠️ Произошла ошибка при проверке. Попробуйте позже.")

async def check_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /domain – проверка домена через VirusTotal."""
    if not await check_access(update):
        return
    if not context.args:
        await update.message.reply_text(
            "Пожалуйста, укажите домен. Пример: /domain example.com"
        )
        return
    
    domain = sanitize_input(context.args[0]).lower()
    if not validate_domain(domain):
        await update.message.reply_text(
            "⚠️ Некорректный домен. Пожалуйста, проверьте формат."
        )
        return
    
    if not await rate_limit_check(update.effective_user.id, "domain_check"):
        await update.message.reply_text(
            "⚠️ Слишком много запросов. Подождите немного."
        )
        return
        
    await update.message.reply_text(f"🔍 Проверяю домен: {domain}...")
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data_json = await response.json()
                    data = data_json.get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected
                    risk_score = (malicious + suspicious) / total * 100 if total > 0 else 0
                    risk_level = "Низкий 🟢"
                    if risk_score > 50:
                        risk_level = "Высокий 🔴"
                    elif risk_score > 20:
                        risk_level = "Средний 🟠"
                    creation_date = data.get("creation_date", "Неизвестно")
                    if isinstance(creation_date, int):
                        creation_date = datetime.fromtimestamp(creation_date).strftime(
                            "%Y-%m-%d"
                        )
                    message = (
                        f"📊 <b>Результаты проверки домена: {domain}</b>\n\n"
                        f"🔹 <b>Уровень риска:</b> {risk_level} ({risk_score:.1f}%)\n"
                        f"🔹 <b>Вредоносных:</b> {malicious}\n"
                        f"🔹 <b>Подозрительных:</b> {suspicious}\n"
                        f"🔹 <b>Безопасных:</b> {harmless}\n"
                        f"🔹 <b>Не определено:</b> {undetected}\n"
                        f"🔹 <b>Всего анализов:</b> {total}\n"
                        f"🔹 <b>Дата регистрации домена:</b> {creation_date}\n\n"
                    )
                    keyboard = [
                        [
                            InlineKeyboardButton(
                                "VirusTotal",
                                url=f"https://www.virustotal.com/gui/domain/{domain}",
                            ),
                            InlineKeyboardButton(
                                "URLScan", url=f"https://urlscan.io/domain/{domain}"
                            ),
                        ]
                    ]
                    reply_markup = InlineKeyboardMarkup(keyboard)
                    await update.message.reply_html(message, reply_markup=reply_markup)
                else:
                    logging.error(f"VirusTotal API error: {response.status}")
                    await update.message.reply_text(
                        f"⚠️ Ошибка при проверке домена: {response.status}"
                    )
    except asyncio.TimeoutError:
        logging.error(f"Timeout during domain check for user {update.effective_user.id}")
        await update.message.reply_text("⚠️ Тайм-аут запроса. Попробуйте позже.")
    except Exception as e:
        logging.error(f"Error in domain check: {str(e)}")
        await update.message.reply_text("⚠️ Произошла ошибка при проверке. Попробуйте позже.")

async def check_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /url – сканирование URL через VirusTotal (с кратким ожиданием)."""
    if not await check_access(update):
        return
    if not context.args:
        await update.message.reply_text(
            "Пожалуйста, укажите URL. Пример: /url https://example.com/page"
        )
        return
    
    url_to_check = context.args[0]  # Не санитаризуем URL полностью, чтобы не сломать
    if not validate_url(url_to_check):
        await update.message.reply_text(
            "⚠️ Некорректный URL. Пожалуйста, проверьте формат (должен начинаться с http:// или https://)."
        )
        return
    
    if not await rate_limit_check(update.effective_user.id, "url_check"):
        await update.message.reply_text(
            "⚠️ Слишком много запросов. Подождите немного."
        )
        return
        
    await update.message.reply_text(f"🔍 Проверяю URL: {url_to_check}...")
    try:
        api_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        data = {"url": url_to_check}
        
        timeout = aiohttp.ClientTimeout(total=60)  # Увеличиваем timeout для URL-сканирования
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(api_url, headers=headers, data=data) as response:
                if response.status == 200:
                    response_json = await response.json()
                    analysis_id = response_json.get("data", {}).get("id", "")
                    # Ожидание результатов анализа (несколько секунд)
                    await update.message.reply_text(
                        "⏳ URL отправлен на анализ. Ожидаю результаты..."
                    )
                    await asyncio.sleep(5)  # Асинхронное ожидание
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    async with session.get(analysis_url, headers=headers) as analysis_response:
                        if analysis_response.status == 200:
                            analysis_json = await analysis_response.json()
                            data = analysis_json.get("data", {}).get("attributes", {})
                            stats = data.get("stats", {})
                            malicious = stats.get("malicious", 0)
                            suspicious = stats.get("suspicious", 0)
                            harmless = stats.get("harmless", 0)
                            undetected = stats.get("undetected", 0)
                            total = malicious + suspicious + harmless + undetected
                            risk_score = (malicious + suspicious) / total * 100 if total > 0 else 0
                            risk_level = "Низкий 🟢"
                            if risk_score > 50:
                                risk_level = "Высокий 🔴"
                            elif risk_score > 20:
                                risk_level = "Средний 🟠"
                            message = (
                                f"📊 <b>Результаты проверки URL:</b>\n\n"
                                f"🔹 <b>Уровень риска:</b> {risk_level} ({risk_score:.1f}%)\n"
                                f"🔹 <b>Вредоносных:</b> {malicious}\n"
                                f"🔹 <b>Подозрительных:</b> {suspicious}\n"
                                f"🔹 <b>Безопасных:</b> {harmless}\n"
                                f"🔹 <b>Не определено:</b> {undetected}\n"
                                f"🔹 <b>Всего двигателей:</b> {total}\n\n"
                            )
                            keyboard = [
                                [
                                    InlineKeyboardButton(
                                        "VirusTotal",
                                        url=f"https://www.virustotal.com/gui/url/{analysis_id}/detection",
                                    ),
                                    InlineKeyboardButton("URLScan", url="https://urlscan.io/"),
                                ]
                            ]
                            reply_markup = InlineKeyboardMarkup(keyboard)
                            await update.message.reply_html(message, reply_markup=reply_markup)
                        else:
                            logging.error(f"VirusTotal analysis error: {analysis_response.status}")
                            await update.message.reply_text(
                                f"⚠️ Ошибка при получении результатов анализа: {analysis_response.status}"
                            )
                else:
                    logging.error(f"VirusTotal URL submit error: {response.status}")
                    await update.message.reply_text(
                        f"⚠️ Ошибка при отправке URL на анализ: {response.status}"
                    )
    except asyncio.TimeoutError:
        logging.error(f"Timeout during URL check for user {update.effective_user.id}")
        await update.message.reply_text("⚠️ Тайм-аут запроса. Попробуйте позже.")
    except Exception as e:
        logging.error(f"Error in URL check: {str(e)}")
        await update.message.reply_text("⚠️ Произошла ошибка при проверке. Попробуйте позже.")

async def check_hash(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /hash – проверка хэша файла через VirusTotal."""
    if not await check_access(update):
        return
    if not context.args:
        await update.message.reply_text(
            "Пожалуйста, укажите хэш файла (MD5, SHA1 или SHA256). Пример: /hash 44d88612fea8a8f36de82e1278abb02f"
        )
        return
    
    file_hash = sanitize_input(context.args[0]).lower()
    if not validate_hash(file_hash):
        await update.message.reply_text(
            "⚠️ Некорректный хэш. Поддерживаются MD5 (32 символа), SHA1 (40 символов) и SHA256 (64 символа)."
        )
        return
    
    if not await rate_limit_check(update.effective_user.id, "hash_check"):
        await update.message.reply_text(
            "⚠️ Слишком много запросов. Подождите немного."
        )
        return
        
    await update.message.reply_text(f"🔍 Проверяю хэш: {file_hash}...")
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data_json = await response.json()
                    data = data_json.get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected
                    risk_score = (malicious + suspicious) / total * 100 if total > 0 else 0
                    risk_level = "Низкий 🟢"
                    if risk_score > 50:
                        risk_level = "Высокий 🔴"
                    elif risk_score > 20:
                        risk_level = "Средний 🟠"
                    message = (
                        f"📊 <b>Результаты проверки хэша:</b>\n\n"
                        f"🔹 <b>Уровень риска:</b> {risk_level} ({risk_score:.1f}%)\n"
                        f"🔹 <b>Вредоносных:</b> {malicious}\n"
                        f"🔹 <b>Подозрительных:</b> {suspicious}\n"
                        f"🔹 <b>Безопасных:</b> {harmless}\n"
                        f"🔹 <b>Неизвестных:</b> {undetected}\n"
                        f"🔹 <b>Всего анализов:</b> {total}\n\n"
                    )
                    keyboard = [
                        [
                            InlineKeyboardButton(
                                "VirusTotal",
                                url=f"https://www.virustotal.com/gui/file/{file_hash}/detection",
                            ),
                            InlineKeyboardButton(
                                "Hybrid Analysis",
                                url=f"https://www.hybrid-analysis.com/search?query={file_hash}",
                            ),
                        ]
                    ]
                    reply_markup = InlineKeyboardMarkup(keyboard)
                    await update.message.reply_html(message, reply_markup=reply_markup)
                else:
                    logging.error(f"VirusTotal hash check error: {response.status}")
                    await update.message.reply_text(
                        f"⚠️ Ошибка при проверке хэша: {response.status}"
                    )
    except asyncio.TimeoutError:
        logging.error(f"Timeout during hash check for user {update.effective_user.id}")
        await update.message.reply_text("⚠️ Тайм-аут запроса. Попробуйте позже.")
    except Exception as e:
        logging.error(f"Error in hash check: {str(e)}")
        await update.message.reply_text("⚠️ Произошла ошибка при проверке. Попробуйте позже.")

async def whois_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /whois – получение WHOIS информации о домене или IP."""
    if not await check_access(update):
        return
    if not context.args:
        await update.message.reply_text(
            "Пожалуйста, укажите домен или IP-адрес. Пример: /whois example.com"
        )
        return
    target = sanitize_input(context.args[0])
    await update.message.reply_text(f"🔍 Ищу WHOIS информацию для: {target}...")
    try:
        # Выполняем whois в отдельном потоке чтобы не блокировать бот
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, whois.whois, target)
        
        # Приводим результат к строке (словарь или объект -> строка)
        info_text = ""
        if isinstance(result, dict):
            for key, value in result.items():
                info_text += f"{key}: {value}\n"
        else:
            info_text = str(result)
        # Ограничиваем длину, чтобы сообщение не превышало лимит Telegram
        if len(info_text) > 4000:
            info_text = info_text[:4000] + "..."
        await update.message.reply_text(f"```{info_text}```", parse_mode="Markdown")
    except Exception as e:
        logging.error(f"WHOIS lookup error: {str(e)}")
        await update.message.reply_text(
            "⚠️ Произошла ошибка при запросе WHOIS: не удалось получить информацию"
        )

# ======= Функция поиска по MITRE ATT&CK =======

async def mitre_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /mitre – поиск информации в базе MITRE ATT&CK по ID или ключевому слову."""
    if not await check_access(update):
        return
    mitre_data = await fetch_mitre_data()
    if not context.args:
        # Без аргументов – выводим справочную информацию о тактиках и количестве техник
        message = "🛡️ <b>MITRE ATT&CK Matrix – Обзор</b>\n\n"
        message += "MITRE ATT&CK – база знаний о тактиках и техниках, используемых злоумышленниками.\n\n"
        message += "<b>Доступные тактики:</b>\n"
        for tactic in mitre_data["tactics"]:
            tid = tactic.get("id", "")
            name_en = tactic.get("name", "")
            name_ru = tactic.get("name_ru", "")
            if name_ru and name_ru != name_en:
                message += f"• <code>{tid}</code>: {name_ru} ({name_en})\n"
            else:
                message += f"• <code>{tid}</code>: {name_en}\n"
        message += f"\n<b>Всего техник:</b> {len(mitre_data['techniques'])}\n"
        message += f"<b>Всего подтехник:</b> {len(mitre_data['subtechniques'])}\n\n"
        message += "Для поиска информации используйте команду:\n"
        message += "/mitre [ID или ключевое слово]\n\n"
        message += "Примеры запросов:\n"
        message += "/mitre T1566 (поиск техники по ID)\n"
        message += "/mitre TA0001 (поиск тактики по ID)\n"
        message += "/mitre фишинг (поиск по названию)\n"
        message += "/mitre lateral (поиск по части названия)"
        await update.message.reply_html(message)
        return
    # Пользователь указал запрос
    query = sanitize_input(" ".join(context.args)).lower()
    found_tactics = []
    found_techniques = []
    found_subtechniques = []
    # Ищем совпадения в списках тактик, техник и подтехник
    for tactic in mitre_data["tactics"]:
        if (
            query in tactic.get("id", "").lower()
            or query in tactic.get("name", "").lower()
            or query in tactic.get("name_ru", "").lower()
            or query in tactic.get("description", "").lower()
        ):
            found_tactics.append(tactic)
    for tech in mitre_data["techniques"]:
        if (
            query in tech.get("id", "").lower()
            or query in tech.get("name", "").lower()
            or query in tech.get("name_ru", "").lower()
            or query in tech.get("description", "").lower()
        ):
            found_techniques.append(tech)
    for sub in mitre_data["subtechniques"]:
        if (
            query in sub.get("id", "").lower()
            or query in sub.get("name", "").lower()
            or query in sub.get("name_ru", "").lower()
            or query in sub.get("description", "").lower()
        ):
            found_subtechniques.append(sub)
    if not found_tactics and not found_techniques and not found_subtechniques:
        await update.message.reply_html(
            f"⚠️ По запросу '<b>{query}</b>' ничего не найдено."
        )
        return
    # Проверяем, искал ли пользователь точный ID (полное совпадение)
    exact_type = None
    exact_item = None
    for tactic in found_tactics:
        if tactic.get("id", "").lower() == query:
            exact_type, exact_item = "tactic", tactic
            break
    if not exact_item:
        for tech in found_techniques:
            if tech.get("id", "").lower() == query:
                exact_type, exact_item = "technique", tech
                break
    if not exact_item:
        for sub in found_subtechniques:
            if sub.get("id", "").lower() == query:
                exact_type, exact_item = "subtechnique", sub
                break
    if exact_item:
        # Есть точное совпадение по ID – выводим подробности только этого элемента
        if exact_type == "tactic":
            message = format_tactic_message(exact_item, mitre_data)
        else:
            message = format_technique_message(
                exact_item, mitre_data, is_subtechnique=(exact_type == "subtechnique")
            )
        # Сообщение может превышать лимиты, разобьём при необходимости
        if len(message) > 4000:
            parts = [message[i : i + 4000] for i in range(0, len(message), 4000)]
            for part in parts:
                await update.message.reply_html(part)
        else:
            await update.message.reply_html(message)
        return
    # Если точного совпадения нет, формируем краткий список всех найденных результатов
    result_msg = f"🔍 <b>Результаты поиска:</b> {query}\n\n"
    if found_tactics:
        result_msg += f"<b>🎯 Найдено тактик: {len(found_tactics)}</b>\n"
        for t in found_tactics[:3]:
            tid = t.get("id", "")
            name_en = t.get("name", "")
            name_ru = t.get("name_ru", "")
            if name_ru and name_ru != name_en:
                result_msg += f"• <code>{tid}</code>: {name_ru} ({name_en})\n"
            else:
                result_msg += f"• <code>{tid}</code>: {name_en}\n"
        if len(found_tactics) > 3:
            result_msg += f"... и еще {len(found_tactics)-3} тактик\n"
        result_msg += "Чтобы узнать подробнее о тактике, введите ее ID, например:\n"
        result_msg += f"/mitre {found_tactics[0].get('id', '')}\n\n"
    if found_techniques:
        result_msg += f"<b>⚙️ Найдено техник: {len(found_techniques)}</b>\n"
        for tech in found_techniques[:5]:
            tid = tech.get("id", "")
            name_en = tech.get("name", "")
            name_ru = tech.get("name_ru", "")
            if name_ru and name_ru != name_en:
                result_msg += f"• <code>{tid}</code>: {name_ru} ({name_en})\n"
            else:
                result_msg += f"• <code>{tid}</code>: {name_en}\n"
        if len(found_techniques) > 5:
            result_msg += f"... и еще {len(found_techniques)-5} техник\n"
        result_msg += "Чтобы узнать подробнее о технике, введите ее ID, например:\n"
        result_msg += f"/mitre {found_techniques[0].get('id', '')}\n\n"
    if found_subtechniques:
        result_msg += f"<b>🔧 Найдено подтехник: {len(found_subtechniques)}</b>\n"
        for sub in found_subtechniques[:5]:
            sid = sub.get("id", "")
            name_en = sub.get("name", "")
            name_ru = sub.get("name_ru", "")
            if name_ru and name_ru != name_en:
                result_msg += f"• <code>{sid}</code>: {name_ru} ({name_en})\n"
            else:
                result_msg += f"• <code>{sid}</code>: {name_en}\n"
        if len(found_subtechniques) > 5:
            result_msg += f"... и еще {len(found_subtechniques)-5} подтехник\n"
        result_msg += "Чтобы узнать подробнее о подтехнике, введите ее ID, например:\n"
        result_msg += f"/mitre {found_subtechniques[0].get('id', '')}\n"
    await update.message.reply_html(result_msg)

def format_tactic_message(tactic: dict, mitre_data: dict) -> str:
    """Формирует подробное описание тактики MITRE ATT&CK."""
    tid = tactic.get("id", "")
    name_en = tactic.get("name", "")
    name_ru = tactic.get("name_ru", "")
    desc = tactic.get("description", "") or "Описание не предоставлено."
    msg = "<b>🎯 ТАКТИКА MITRE ATT&CK</b>\n\n"
    if name_ru and name_ru != name_en:
        msg += f"<b>Название:</b> {name_ru} ({name_en})\n"
    else:
        msg += f"<b>Название:</b> {name_en}\n"
    msg += f"<b>ID:</b> <code>{tid}</code>\n\n"
    msg += f"<b>Описание:</b>\n{desc}\n\n"
    # Находим связанные техники (те, у которых в списке тактик есть текущая)
    related_techniques = [
        tech
        for tech in mitre_data["techniques"]
        if tid.lower() in [t.lower() for t in tech.get("tactics", [])]
    ]
    msg += f"<b>Связанные техники ({len(related_techniques)}):</b>\n"
    for tech in sorted(related_techniques, key=lambda x: x.get("id", ""))[:15]:
        t_id = tech.get("id", "")
        t_name = tech.get("name", "")
        t_name_ru = tech.get("name_ru", "")
        if t_name_ru and t_name_ru != t_name:
            msg += f"• <code>{t_id}</code>: {t_name_ru} ({t_name})\n"
        else:
            msg += f"• <code>{t_id}</code>: {t_name}\n"
    return msg

def format_technique_message(
    technique: dict, mitre_data: dict, is_subtechnique: bool = False
) -> str:
    """Формирует подробное описание техники или подтехники MITRE ATT&CK."""
    tid = technique.get("id", "")
    name_en = technique.get("name", "")
    name_ru = technique.get("name_ru", "")
    desc = technique.get("description", "") or "Описание не предоставлено."
    parent_id = technique.get("parent", "") if is_subtechnique else None
    msg = (
        "<b>⚙️ ТЕХНИКА MITRE ATT&CK</b>\n\n"
        if not is_subtechnique
        else "<b>🔧 ПОДТЕХНИКА MITRE ATT&CK</b>\n\n"
    )
    if name_ru and name_ru != name_en:
        msg += f"<b>Название:</b> {name_ru} ({name_en})\n"
    else:
        msg += f"<b>Название:</b> {name_en}\n"
    msg += f"<b>ID:</b> <code>{tid}</code>\n"
    if parent_id:
        msg += f"<b>Родительская техника:</b> {parent_id}\n"
    msg += f"\n<b>Описание:</b>\n{desc}\n\n"
    # Указываем тактики, к которым принадлежит техника
    tactics = technique.get("tactics", [])
    if tactics:
        msg += "<b>Тактики:</b> " + ", ".join(tactics) + "\n\n"
    # Если техника не является подтехникой, перечисляем некоторые подтехники (если есть)
    if not is_subtechnique:
        subtechs = [st for st in mitre_data["subtechniques"] if st.get("parent") == tid]
        if subtechs:
            msg += f"<b>Подтехники ({len(subtechs)}):</b>\n"
            for st in sorted(subtechs, key=lambda x: x.get("id", ""))[:10]:
                st_id = st.get("id", "")
                st_name = st.get("name", "")
                st_name_ru = st.get("name_ru", "")
                if st_name_ru and st_name_ru != st_name:
                    msg += f"• <code>{st_id}</code>: {st_name_ru} ({st_name})\n"
                else:
                    msg += f"• <code>{st_id}</code>: {st_name}\n"
            if len(subtechs) > 10:
                msg += "... и другие\n"
    return msg

# ======= Функции обучающего раздела (справочные материалы) =======

async def killchain_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Выводит информацию о моделe Cyber Kill Chain."""
    if not await check_access(update):
        return
    message = (
        "🎯 <b>Модель Cyber Kill Chain</b>\n\n"
        "1️⃣ <b>Разведка (Reconnaissance)</b>\n"
        "Атакующий собирает информацию о цели – например, сканирование сетей, поиск уязвимостей, сбор данных о сотрудниках.\n\n"
        "2️⃣ <b>Вооружение (Weaponization)</b>\n"
        "Подготовка эксплойта или вредоносного ПО для атаки, часто объединяя эксплойт с бэкдором.\n\n"
        "3️⃣ <b>Доставка (Delivery)</b>\n"
        "Доставка вредоносной нагрузки жертве (через email, USB или веб-сайт).\n\n"
        "4️⃣ <b>Эксплуатация (Exploitation)</b>\n"
        "Использование уязвимости для выполнения вредоносного кода на системе жертвы.\n\n"
        "5️⃣ <b>Установка (Installation)</b>\n"
        "Установка вредоносного ПО (например, бэкдора) на целевой системе.\n\n"
        "6️⃣ <b>Командование и управление (Command & Control)</b>\n"
        "Установление связи с скомпрометированной системой для удаленного управления.\n\n"
        "7️⃣ <b>Действия на цели (Actions on Objectives)</b>\n"
        "Завершение целей атаки – кража данных, нарушение работы системы и т.д.\n\n"
        "<b>Применение в SOC:</b> помогает понять этап, на котором находится атака, и выбрать правильные меры реагирования."
    )
    keyboard = [
        [
            InlineKeyboardButton(
                "Подробнее о Kill Chain",
                url="https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html",
            )
        ]
    ]
    await update.message.reply_html(
        message, reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def owasp_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Выводит информацию об OWASP Top 10."""
    if not await check_access(update):
        return
    message = (
        "🔐 <b>OWASP Top 10 (2021)</b>\n\n"
        "Наиболее критичные уязвимости веб-приложений:\n\n"
        "1️⃣ <b>A01:2021 – Broken Access Control (Нарушение контроля доступа)</b>\n"
        "Некорректная реализация ограничений доступа, позволяющая атакующим обходить правила доступа.\n\n"
        "2️⃣ <b>A02:2021 – Cryptographic Failures (Криптографические ошибки)</b>\n"
        "Недостатки в реализации криптографии, приводящие к компрометации данных.\n\n"
        "3️⃣ <b>A03:2021 – Injection (Инъекции)</b>\n"
        "Внедрение вредоносных данных (SQL, NoSQL, OS Command и т.д.) в интерпретатор.\n\n"
        "4️⃣ <b>A04:2021 – Insecure Design (Небезопасный дизайн)</b>\n"
        "Пробелы в проектировании и архитектуре безопасности приложений.\n\n"
        "5️⃣ <b>A05:2021 – Security Misconfiguration (Ошибки конфигурации безопасности)</b>\n"
        "Использование небезопасных настроек или параметров по умолчанию.\n\n"
        "6️⃣ <b>A06:2021 – Vulnerable and Outdated Components (Уязвимые компоненты)</b>\n"
        "Использование устаревших библиотек/пакетов с известными уязвимостями.\n\n"
        "7️⃣ <b>A07:2021 – Identification and Authentication Failures (Ошибки аутентификации)</b>\n"
        "Недостатки, позволяющие обходить механизмы аутентификации (например, неправильная обработка сессий).\n\n"
        "8️⃣ <b>A08:2021 – Software and Data Integrity Failures (Нарушение целостности ПО и данных)</b>\n"
        "Отсутствие проверок целостности программ и данных (например, неподписанные обновления, уязвимости цепочки поставок).\n\n"
        "9️⃣ <b>A09:2021 – Security Logging and Monitoring Failures (Недостатки логирования и мониторинга)</b>\n"
        "Нехватка или неэффективность журналирования и мониторинга, что мешает обнаружению атак.\n\n"
        "🔟 <b>A10:2021 – Server-Side Request Forgery (SSRF)</b>\n"
        "Уязвимость, позволяющая злоумышленнику заставить сервер делать запросы к произвольным ресурсам (включая внутренние)."
    )
    keyboard = [
        [InlineKeyboardButton("Подробнее на OWASP.org", url="https://owasp.org/Top10/")]
    ]
    await update.message.reply_html(
        message, reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def osi_model(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Выводит информацию о семиуровневой модели OSI."""
    if not await check_access(update):
        return
    message = (
        "📘 <b>Модель OSI (Open Systems Interconnection)</b>\n\n"
        "Эталонная модель взаимодействия сетевых систем, разделенная на 7 уровней:\n\n"
        "7️⃣ <b>Прикладной (Application)</b> – протоколы прикладного уровня (HTTP, FTP, SMTP и др.)\n"
        "6️⃣ <b>Уровень представления (Presentation)</b> – кодирование, шифрование, сжатие данных\n"
        "5️⃣ <b>Сеансовый (Session)</b> – управление сеансами (установка, поддержание и завершение сеанса)\n"
        "4️⃣ <b>Транспортный (Transport)</b> – доставка данных (TCP, UDP)\n"
        "3️⃣ <b>Сетевой (Network)</b> – маршрутизация пакетов (IP)\n"
        "2️⃣ <b>Канальный (Data Link)</b> – передача кадров внутри одной сети (Ethernet и др.)\n"
        "1️⃣ <b>Физический (Physical)</b> – физические среды передачи (кабели, радиоволны)\n\n"
        "<b>Примечание:</b> Модель OSI часто используется для обучения, тогда как в практике применяют более простую модель TCP/IP."
    )
    # Кнопка для переключения на модель TCP/IP
    keyboard = [
        [InlineKeyboardButton("Сетевая модель TCP/IP", callback_data="show_tcpip")]
    ]
    await update.message.reply_html(
        message, reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def tcpip_model(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Выводит информацию о модели TCP/IP."""
    if not await check_access(update):
        return
    message = (
        "🌐 <b>Сетевая модель TCP/IP</b>\n\n"
        "Практическая четырехуровневая модель, легшая в основу интернета:\n\n"
        "4️⃣ <b>Прикладной (Application)</b> – включает уровни 5-7 модели OSI (протоколы: HTTP, SMTP, FTP и др.)\n"
        "3️⃣ <b>Транспортный (Transport)</b> – аналог транспортного уровня OSI (TCP, UDP)\n"
        "2️⃣ <b>Сетевой (Internet)</b> – аналог сетевого уровня OSI (IP, ICMP)\n"
        "1️⃣ <b>Канальный + Физический (Link)</b> – объединяет уровни 1-2 OSI (Ethernet, Wi-Fi и пр.)\n\n"
        "<b>Отличия от OSI:</b> модель TCP/IP более прикладная и используется на практике повсеместно, тогда как OSI – теоретическая основа для понимания сетевых принципов."
    )
    # Кнопка для переключения на модель OSI
    keyboard = [[InlineKeyboardButton("Модель OSI", callback_data="show_osi")]]
    await update.message.reply_html(
        message, reply_markup=InlineKeyboardMarkup(keyboard)
    )

# ======= Административные функции (приватность бота) =======

async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /admin или кнопка 'Админка' – открывает админ-панель для владельца бота."""
    if not await check_access(update):
        return
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("⛔️ Команда доступна только владельцу бота.")
        return
    # Формируем текст панели с текущими авторизованными пользователями
    text = "👮 <b>Админ-панель</b>\n\n"
    text += "Авторизованные пользователи:\n"
    if ALLOWED_USERS:
        for uid in ALLOWED_USERS:
            text += f"• {uid}\n"
    else:
        text += "• (нет дополнительных пользователей)\n"
    text += "\nВы можете добавить или удалить пользователей с помощью кнопок ниже."
    # Клавиатура: добавить пользователя + удалить для каждого
    keyboard = [
        [
            InlineKeyboardButton(
                "➕ Добавить пользователя", callback_data="admin_add_user"
            )
        ]
    ]
    for uid in ALLOWED_USERS:
        keyboard.append(
            [
                InlineKeyboardButton(
                    f"Удалить {uid}", callback_data=f"admin_remove_user_{uid}"
                )
            ]
        )
    msg = await update.message.reply_html(
        text, reply_markup=InlineKeyboardMarkup(keyboard)
    )
    # Сохраняем ID сообщения и чата, чтобы обновлять панель
    context.user_data["admin_msg_id"] = msg.message_id
    context.user_data["admin_chat_id"] = msg.chat_id

# ======= Обработка CallbackQuery от inline-кнопок =======

async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обрабатывает нажатия на inline-кнопки (например, админ-панель, переключатели моделей и т.д.)."""
    query = update.callback_query
    user_id = query.from_user.id
    # Проверяем доступ (для колбэков тоже нужно ограничение)
    if user_id != OWNER_ID and user_id not in ALLOWED_USERS:
        await query.answer("⛔️ Приватный бот: доступ запрещен.", show_alert=True)
        return
    await query.answer()  # Закрываем всплывающее уведомление, если было
    data = query.data
    if data == "admin_add_user":
        # Нажата кнопка "Добавить пользователя"
        if context.user_data.get("expecting_add", False):
            # Если бот уже ждет ввод ID, предупреждаем
            await query.answer(
                "⚠️ Сейчас ожидается ввод ID пользователя.", show_alert=True
            )
        else:
            # Устанавливаем флаг ожидания и просим ввести ID
            context.user_data["expecting_add"] = True
            await query.message.reply_text(
                "⌨️ Введите ID пользователя, которого нужно добавить:"
            )
    elif data.startswith("admin_remove_user_"):
        # Нажата кнопка удаления пользователя
        try:
            remove_id = int(data.split("admin_remove_user_")[1])
        except ValueError:
            await query.answer("Некорректный ID.", show_alert=True)
            return
        if remove_id in ALLOWED_USERS:
            ALLOWED_USERS.remove(remove_id)
            save_allowed_users()
            await query.answer("✅ Пользователь удален.", show_alert=False)
        else:
            await query.answer("Пользователь не найден.", show_alert=True)
        # Обновляем сообщение админ-панели
        text = "👮 <b>Админ-панель</b>\n\n"
        text += "Авторизованные пользователи:\n"
        if ALLOWED_USERS:
            for uid in ALLOWED_USERS:
                text += f"• {uid}\n"
        else:
            text += "• (нет дополнительных пользователей)\n"
        text += "\nВы можете добавить или удалить пользователей с помощью кнопок ниже."
        keyboard = [
            [
                InlineKeyboardButton(
                    "➕ Добавить пользователя", callback_data="admin_add_user"
                )
            ]
        ]
        for uid in ALLOWED_USERS:
            keyboard.append(
                [
                    InlineKeyboardButton(
                        f"Удалить {uid}", callback_data=f"admin_remove_user_{uid}"
                    )
                ]
            )
        try:
            await query.edit_message_text(
                text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="HTML"
            )
        except Exception as e:
            logging.error(f"Не удалось обновить сообщение админ-панели: {e}")
    elif data.startswith("check_vt_"):
        # Inline-кнопка из результатов AbuseIPDB: проверить через VirusTotal
        target = data.split("_", 2)[2]  # Получаем IP или домен
        # Определяем, IP это или домен, и вызываем соответствующую функцию
        try:
            ipaddress.ip_address(target)
            context.args = [target]
            await check_ip(update, context)
        except ValueError:
            context.args = [target]
            await check_domain(update, context)
    elif data == "show_osi":
        # Переключение на модель OSI
        await osi_model(update, context)
    elif data == "show_tcpip":
        # Переключение на модель TCP/IP
        await tcpip_model(update, context)

# ======= Обработка текстовых сообщений (Reply-кнопок) =======

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обрабатывает обычные текстовые сообщения (в том числе нажатия кнопок главного меню и подменю)."""
    if not await check_access(update):
        return
    text = update.message.text.strip().lower()
    # Глобальная кнопка "Назад" – возвращает пользователя в главное меню
    if text == "назад":
        # Сбрасываем все флаги ожидания ввода
        context.user_data.pop("expecting_add", None)
        context.user_data.pop("expecting_ip", None)
        context.user_data.pop("expecting_domain", None)
        context.user_data.pop("expecting_url", None)
        context.user_data.pop("expecting_hash", None)
        context.user_data.pop("expecting_whois", None)
        # Отправляем главное меню заново
        await start(update, context)
        return
    # Если ожидается ввод ID (для добавления пользователя в админке)
    if context.user_data.get("expecting_add"):
        # Ввод ID разрешен только владельцу
        if update.effective_user.id != OWNER_ID:
            context.user_data["expecting_add"] = False
            return
        if not text.isdigit():
            await update.message.reply_text(
                "⚠️ Пожалуйста, отправьте числовой ID пользователя."
            )
            return
        new_id = int(text)
        if new_id == OWNER_ID:
            await update.message.reply_text(
                "Этот ID принадлежит владельцу бота по умолчанию."
            )
        elif new_id in ALLOWED_USERS:
            await update.message.reply_text("Этот пользователь уже авторизован.")
        else:
            ALLOWED_USERS.append(new_id)
            save_allowed_users()
            await update.message.reply_text(
                f"✅ Пользователь {new_id} добавлен в список авторизованных."
            )
            logging.info(f"Authorized new user {new_id}")
        context.user_data["expecting_add"] = False
        return
    
    # Если ожидается ввод параметра для проверки IOC
    if context.user_data.get("expecting_ip"):
        context.user_data["expecting_ip"] = False
        ip_input = sanitize_input(text)
        if not validate_ip(ip_input):
            await update.message.reply_text(
                "⚠️ Некорректный IP-адрес. Попробуйте снова или нажмите 'Назад' для отмены."
            )
            context.user_data["expecting_ip"] = True
            return
        context.args = [ip_input]
        await check_ip(update, context)
        return
    if context.user_data.get("expecting_domain"):
        context.user_data["expecting_domain"] = False
        domain_input = sanitize_input(text).lower()
        if not validate_domain(domain_input):
            await update.message.reply_text(
                "⚠️ Некорректный домен. Попробуйте снова или нажмите 'Назад' для отмены."
            )
            context.user_data["expecting_domain"] = True
            return
        context.args = [domain_input]
        await check_domain(update, context)
        return
    if context.user_data.get("expecting_url"):
        context.user_data["expecting_url"] = False
        url_input = text.strip()
        if not validate_url(url_input):
            await update.message.reply_text(
                "⚠️ Некорректный URL. Попробуйте снова или нажмите 'Назад' для отмены."
            )
            context.user_data["expecting_url"] = True
            return
        context.args = [url_input]
        await check_url(update, context)
        return
    if context.user_data.get("expecting_hash"):
        context.user_data["expecting_hash"] = False
        hash_input = sanitize_input(text).lower()
        if not validate_hash(hash_input):
            await update.message.reply_text(
                "⚠️ Некорректный хэш. Поддерживаются MD5, SHA1, SHA256. Попробуйте снова или нажмите 'Назад' для отмены."
            )
            context.user_data["expecting_hash"] = True
            return
        context.args = [hash_input]
        await check_hash(update, context)
        return
    if context.user_data.get("expecting_whois"):
        context.user_data["expecting_whois"] = False
        whois_input = sanitize_input(text)
        context.args = [whois_input]
        await whois_lookup(update, context)
        return
    
    # Обработка нажатий кнопок главного меню
    if text == "анализ ioc":
        # Пользователь выбрал раздел "Анализ IOC" – выводим подменю
        ioc_menu_buttons = [
            [KeyboardButton("IP"), KeyboardButton("Domain")],
            [KeyboardButton("URL"), KeyboardButton("Hash")],
            [KeyboardButton("Whois"), KeyboardButton("Назад")],
        ]
        await update.message.reply_text(
            "Выберите тип индикатора для проверки:",
            reply_markup=ReplyKeyboardMarkup(ioc_menu_buttons, resize_keyboard=True),
        )
        return
    elif text == "mitre att&ck":
        # Пользователь выбрал раздел "MITRE ATT&CK" – запускаем поиск без параметров (обзор тактик)
        context.args = []
        await mitre_lookup(update, context)
        return
    elif text == "обучение":
        # Пользователь выбрал раздел "Обучение" – выводим меню справочных материалов
        edu_menu_buttons = [
            [KeyboardButton("Kill Chain"), KeyboardButton("OWASP Top 10")],
            [KeyboardButton("Модель OSI"), KeyboardButton("Модель TCP/IP")],
            [KeyboardButton("Назад")],
        ]
        await update.message.reply_text(
            "Выберите тему для получения справки:",
            reply_markup=ReplyKeyboardMarkup(edu_menu_buttons, resize_keyboard=True),
        )
        return
    elif text == "админка":
        # Пользователь выбрал "Админка" – открываем админ-панель (если это владелец)
        if update.effective_user.id == OWNER_ID:
            await admin_panel(update, context)
        else:
            await update.message.reply_text(
                "⛔️ Команда доступна только владельцу бота."
            )
        return
    
    # Обработка нажатий кнопок IOC подменю
    if text == "ip":
        context.user_data["expecting_ip"] = True
        await update.message.reply_text(
            "🔍 Введите IP-адрес для проверки (например: 8.8.8.8):"
        )
        return
    elif text == "domain":
        context.user_data["expecting_domain"] = True
        await update.message.reply_text(
            "🔍 Введите домен для проверки (например: example.com):"
        )
        return
    elif text == "url":
        context.user_data["expecting_url"] = True
        await update.message.reply_text(
            "🔍 Введите URL для проверки (например: https://example.com):"
        )
        return
    elif text == "hash":
        context.user_data["expecting_hash"] = True
        await update.message.reply_text(
            "🔍 Введите хэш файла для проверки (MD5/SHA1/SHA256):"
        )
        return
    elif text == "whois":
        context.user_data["expecting_whois"] = True
        await update.message.reply_text(
            "🔍 Введите домен или IP для WHOIS запроса:"
        )
        return
    
    # Обработка нажатий кнопок справочного подменю ("Обучение")
    elif text == "kill chain":
        await killchain_info(update, context)
    elif text == "owasp top 10":
        await owasp_info(update, context)
    elif text == "модель osi":
        await osi_model(update, context)
    elif text == "модель tcp/ip":
        await tcpip_model(update, context)
    else:
        # Неизвестный ввод – предлагаем команду /help
        await update.message.reply_text(
            "❓ Не понял запрос. Введите /help для списка команд."
        )

# ======= Запуск бота =======

def main():
    global VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, TELEGRAM_TOKEN, OWNER_ID
    
    try:
        print("🚀 Запуск SOC Telegram Bot...")
        config = setup_credentials()

        if not config:
            print("❌ Не удалось настроить конфигурацию. Выход.")
            exit(1)

        required_keys = ['VIRUSTOTAL_API_KEY', 'ABUSEIPDB_API_KEY', 'TELEGRAM_TOKEN', 'OWNER_ID']
        missing_keys = [key for key in required_keys if key not in config]
        
        if missing_keys:
            print(f"❌ Отсутствуют обязательные ключи конфигурации: {', '.join(missing_keys)}")
            exit(1)

        VIRUSTOTAL_API_KEY = config['VIRUSTOTAL_API_KEY']
        ABUSEIPDB_API_KEY = config['ABUSEIPDB_API_KEY']
        TELEGRAM_TOKEN = config['TELEGRAM_TOKEN']
        OWNER_ID = config['OWNER_ID']

        print("✅ Конфигурация загружена успешно!")
        
        try:
            application = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
        except Exception as e:
            print(f"❌ Ошибка инициализации Telegram бота: {e}")
            exit(1)
        
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(CommandHandler("ip", check_ip))
        application.add_handler(CommandHandler("domain", check_domain))
        application.add_handler(CommandHandler("url", check_url))
        application.add_handler(CommandHandler("hash", check_hash))
        application.add_handler(CommandHandler("whois", whois_lookup))
        application.add_handler(CommandHandler("mitre", mitre_lookup))
        application.add_handler(CommandHandler("killchain", killchain_info))
        application.add_handler(CommandHandler("owasp", owasp_info))
        application.add_handler(CommandHandler("osi", osi_model))
        application.add_handler(CommandHandler("tcpip", tcpip_model))
        application.add_handler(CommandHandler("admin", admin_panel))
        application.add_handler(CallbackQueryHandler(handle_callback))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        
        print("🚀 SOC Telegram Bot started successfully!")
        print("📋 Configuration loaded and bot is running securely!")
        print("Bot is running... Press Ctrl+C to stop")
        
        application.run_polling()
        
    except KeyboardInterrupt:
        print("\n⏹️ Бот остановлен пользователем (Ctrl+C)")
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")
        logging.error(f"Critical error in main: {e}")
        exit(1)

if __name__ == "__main__":
    main()
