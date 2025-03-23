import logging
import os
import json
import requests
import time
import socket
import whois
import ipaddress
import re
import pickle
import os.path
from datetime import datetime
from threading import Lock
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

# ======================
#    API ключи и токены
# ======================
VIRUSTOTAL_API_KEY = "ВАШ VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY = (
    "ВАШ ABUSEIPDB_API_KEY"
)
TELEGRAM_TOKEN = "ВАШ TELEGRAM_TOKEN"

# ID владельца бота (основной администратор)
OWNER_ID = ВАШ OWNER_ID  # Telegram ID владельца бота

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
            print(f"Загружены авторизованные пользователи: {ALLOWED_USERS}")
    except Exception as e:
        print(f"Не удалось загрузить список пользователей: {e}")

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
        print("Удален старый кэш MITRE для избежания ошибок структуры данных")
    except Exception as e:
        print(f"Не удалось удалить старый кэш MITRE: {e}")

# ======================
#  Вспомогательные функции
# ======================


async def check_access(update: Update) -> bool:
    """Проверяет, имеет ли пользователь доступ к боту."""
    user_id = update.effective_user.id
    if user_id != OWNER_ID and user_id not in ALLOWED_USERS:
        # Если пользователь не в списке, отказываем в доступе
        await update.message.reply_text(
            "⛔️ Этот бот является приватным и доступен только авторизованным пользователям. Доступ запрещен."
        )
        logging.warning(f"Попытка доступа от неавторизованного пользователя: {user_id}")
        return False
    return True


def save_allowed_users():
    """Сохраняет список ALLOWED_USERS в файл."""
    try:
        with open(ALLOWED_USERS_FILE, "wb") as f:
            pickle.dump(ALLOWED_USERS, f)
            print(f"Список пользователей сохранен ({len(ALLOWED_USERS)} записей).")
    except Exception as e:
        print(f"Ошибка при сохранении списка пользователей: {e}")


def save_mitre_cache():
    """Сохраняет кэш MITRE в файл."""
    try:
        with open(MITRE_CACHE_FILE, "wb") as f:
            pickle.dump(MITRE_CACHE, f)
            print(
                f"MITRE cache saved, tactics: {len(MITRE_CACHE['tactics'])}, techniques: {len(MITRE_CACHE['techniques'])}"
            )
    except Exception as e:
        print(f"Error saving MITRE cache: {e}")


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
    return name_en


def fetch_mitre_data():
    """Получает данные MITRE ATT&CK (тактики, техники, подтехники) с кэшем."""
    now = datetime.now()
    # Если данные свежие (менее часа), возвращаем из кэша
    if MITRE_CACHE["last_update"] and (now - MITRE_CACHE["last_update"]).seconds < 3600:
        return MITRE_CACHE
    try:
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            content = json.loads(response.text)
            objects = content.get("objects", [])
            # Очищаем предыдущие данные
            MITRE_CACHE["tactics"].clear()
            MITRE_CACHE["techniques"].clear()
            MITRE_CACHE["subtechniques"].clear()
            # Наполняем кэш новыми данными
            for obj in objects:
                obj_type = obj.get("type", "")
                if obj_type == "x-mitre-tactic":
                    tactic_id = obj.get("external_references", [{}])[0].get(
                        "external_id", ""
                    )
                    tactic = {
                        "id": tactic_id,
                        "name": obj.get("name", ""),
                        "name_ru": get_russian_name(obj.get("name", "")),
                        "description": obj.get("description", ""),
                    }
                    MITRE_CACHE["tactics"].append(tactic)
                elif obj_type == "attack-pattern":
                    technique_id = obj.get("external_references", [{}])[0].get(
                        "external_id", ""
                    )
                    if "." in technique_id:  # Это подтехника
                        subtech = {
                            "id": technique_id,
                            "name": obj.get("name", ""),
                            "name_ru": get_russian_name(obj.get("name", "")),
                            "description": obj.get("description", ""),
                            "parent": technique_id.split(".")[0],
                            "tactics": get_tactics_for_technique(obj),
                        }
                        MITRE_CACHE["subtechniques"].append(subtech)
                    else:  # Это основная техника
                        tech = {
                            "id": technique_id,
                            "name": obj.get("name", ""),
                            "name_ru": get_russian_name(obj.get("name", "")),
                            "description": obj.get("description", ""),
                            "tactics": get_tactics_for_technique(obj),
                        }
                        MITRE_CACHE["techniques"].append(tech)
            # Сортируем списки по ID для удобства
            MITRE_CACHE["tactics"].sort(key=lambda x: x.get("id", ""))
            MITRE_CACHE["techniques"].sort(key=lambda x: x.get("id", ""))
            MITRE_CACHE["subtechniques"].sort(key=lambda x: x.get("id", ""))
            MITRE_CACHE["last_update"] = now
            save_mitre_cache()
            print(
                f"MITRE data fetched successfully. Tactics: {len(MITRE_CACHE['tactics'])}, Techniques: {len(MITRE_CACHE['techniques'])}, Subtechniques: {len(MITRE_CACHE['subtechniques'])}"
            )
        else:
            print(f"Error fetching MITRE data: {response.status_code}")
            MITRE_CACHE.update(get_fallback_mitre_data())
    except Exception as e:
        print(f"Error fetching MITRE data: {e}")
        MITRE_CACHE.update(get_fallback_mitre_data())
    return MITRE_CACHE


def get_fallback_mitre_data():
    """Возвращает резервные данные MITRE (частичный список тактик) на случай ошибки сети."""
    return {
        "tactics": [
            {
                "id": "TA0001",
                "name": "Initial Access",
                "name_ru": "Первоначальный доступ",
                "description": "Техники, используемые злоумышленниками для получения доступа к сети.",
            },
            {
                "id": "TA0002",
                "name": "Execution",
                "name_ru": "Выполнение",
                "description": "Техники, используемые для запуска управляемого злоумышленником кода.",
            },
            {
                "id": "TA0003",
                "name": "Persistence",
                "name_ru": "Закрепление",
                "description": "Техники для сохранения доступа при перезагрузке или изменении учетных данных.",
            },
            # ... при необходимости можно добавить другие тактики
        ],
        "techniques": [],
        "subtechniques": [],
        "last_update": datetime.now(),
    }


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
    ip = context.args[0]
    await update.message.reply_text(f"🔍 Проверяю IP-адрес: {ip}...")
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": True}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json().get("data", {})
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
            await update.message.reply_text(
                f"⚠️ Ошибка при проверке IP: {response.status_code}"
            )
    except Exception as e:
        await update.message.reply_text(f"⚠️ Произошла ошибка: {str(e)}")


async def check_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /domain – проверка домена через VirusTotal."""
    if not await check_access(update):
        return
    if not context.args:
        await update.message.reply_text(
            "Пожалуйста, укажите домен. Пример: /domain example.com"
        )
        return
    domain = context.args[0]
    await update.message.reply_text(f"🔍 Проверяю домен: {domain}...")
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
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
            await update.message.reply_text(
                f"⚠️ Ошибка при проверке домена: {response.status_code}"
            )
    except Exception as e:
        await update.message.reply_text(f"⚠️ Произошла ошибка: {str(e)}")


async def check_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /url – сканирование URL через VirusTotal (с кратким ожиданием)."""
    if not await check_access(update):
        return
    if not context.args:
        await update.message.reply_text(
            "Пожалуйста, укажите URL. Пример: /url https://example.com/page"
        )
        return
    url_to_check = context.args[0]
    await update.message.reply_text(f"🔍 Проверяю URL: {url_to_check}...")
    try:
        api_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        data = {"url": url_to_check}
        response = requests.post(api_url, headers=headers, data=data)
        if response.status_code == 200:
            analysis_id = response.json().get("data", {}).get("id", "")
            # Ожидание результатов анализа (несколько секунд)
            await update.message.reply_text(
                "⏳ URL отправлен на анализ. Ожидаю результаты..."
            )
            time.sleep(5)  # *Примечание:* лучше заменить на асинхронное ожидание
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code == 200:
                data = analysis_response.json().get("data", {}).get("attributes", {})
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
                await update.message.reply_text(
                    f"⚠️ Ошибка при получении результатов анализа: {analysis_response.status_code}"
                )
        else:
            await update.message.reply_text(
                f"⚠️ Ошибка при отправке URL на анализ: {response.status_code}"
            )
    except Exception as e:
        await update.message.reply_text(f"⚠️ Произошла ошибка: {str(e)}")


async def check_hash(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /hash – проверка хэша файла через VirusTotal."""
    if not await check_access(update):
        return
    if not context.args:
        await update.message.reply_text(
            "Пожалуйста, укажите хэш файла (MD5, SHA1 или SHA256). Пример: /hash 44d88612fea8a8f36de82e1278abb02f"
        )
        return
    file_hash = context.args[0]
    await update.message.reply_text(f"🔍 Проверяю хэш: {file_hash}...")
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
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
            await update.message.reply_text(
                f"⚠️ Ошибка при проверке хэша: {response.status_code}"
            )
    except Exception as e:
        await update.message.reply_text(f"⚠️ Произошла ошибка: {str(e)}")


async def whois_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /whois – получение WHOIS информации о домене или IP."""
    if not await check_access(update):
        return
    if not context.args:
        await update.message.reply_text(
            "Пожалуйста, укажите домен или IP-адрес. Пример: /whois example.com"
        )
        return
    target = context.args[0]
    await update.message.reply_text(f"🔍 Ищу WHOIS информацию для: {target}...")
    try:
        result = whois.whois(target)
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
        await update.message.reply_text(
            f"⚠️ Произошла ошибка при запросе WHOIS: {str(e)}"
        )


# ======= Функция поиска по MITRE ATT&CK =======


async def mitre_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Команда /mitre – поиск информации в базе MITRE ATT&CK по ID или ключевому слову."""
    if not await check_access(update):
        return
    mitre_data = fetch_mitre_data()
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
    query = " ".join(context.args).lower()
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


async def attack_vectors_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Выводит информацию об основных векторах атак."""
    if not await check_access(update):
        return
    message = (
        "🎯 <b>Основные векторы атак</b>\n\n"
        "• Фишинг – рассылка писем с вредоносными вложениями или ссылками.\n"
        "• Вредоносные сайты (drive-by) – сайты, автоматически эксплуатирующие уязвимости в браузере.\n"
        "• Съемные носители – использование зараженных USB-накопителей.\n"
        "• Социальная инженерия – методы обмана людей для получения доступа.\n"
        "• Brute-force – перебор паролей к учетным записям.\n"
        "• Эксплуатация уязвимостей публичных сервисов – атаки на веб-сайты, серверы и пр."
    )
    await update.message.reply_html(message)


async def attacker_tools_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Выводит информацию об инструментах, используемых атакующими."""
    if not await check_access(update):
        return
    message = (
        "🛠️ <b>Инструменты атакующих</b>\n\n"
        "• Эксплойт-киты (например, Metasploit) – наборы эксплойтов для различных уязвимостей.\n"
        "• RAT (Remote Access Trojan) – трояны удаленного доступа (например, njRAT) для контроля системы жертвы.\n"
        "• Кейлоггеры и снифферы – программы для перехвата нажатий клавиш и сетевого трафика.\n"
        "• Ботнеты – сети зараженных устройств под контролем атакующего.\n"
        "• Фреймворки социальной инженерии (например, SET) – инструменты для проведения фишинг-атак и обмана."
    )
    await update.message.reply_html(message)


async def sysmon_events_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Выводит информацию о ключевых событиях Windows Sysmon."""
    if not await check_access(update):
        return
    message = (
        "💻 <b>События Sysmon</b>\n\n"
        "Sysmon – утилита для детального логирования событий в Windows. Ключевые ID событий:\n"
        "• ID 1: Запуск процесса (Process Create)\n"
        "• ID 3: Сетевое подключение (Network Connection)\n"
        "• ID 7: Загрузка драйвера (Driver Load)\n"
        "• ID 8: Создание файла (CreateFile)\n"
        "• ID 11: Изменение создания файлов (File Create)\n"
        "... и другие.\n\n"
        "Анализ журналов Sysmon помогает выявить подозрительную активность на уровне хоста."
    )
    await update.message.reply_html(message)


async def log_paths_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Выводит информацию о путях расположения логов в Windows."""
    if not await check_access(update):
        return
    message = (
        "📁 <b>Стандартные пути логов Windows</b>\n\n"
        "• Security: C:\\Windows\\System32\\Winevt\\Logs\\Security.evtx\n"
        "• System: C:\\Windows\\System32\\Winevt\\Logs\\System.evtx\n"
        "• Application: C:\\Windows\\System32\\Winevt\\Logs\\Application.evtx\n"
        "• IIS: C:\\inetpub\\logs\\LogFiles\n"
        "• PowerShell: C:\\Windows\\System32\\Winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx\n\n"
        "Знание местоположения логов важно для быстрого доступа к ним при анализе инцидентов."
    )
    await update.message.reply_html(message)


async def auth_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Выводит информацию об основных механизмах HTTP-аутентификации: Basic и Digest."""
    if not await check_access(update):
        return
    message = (
        "🔑 <b>Basic vs Digest Authentication</b>\n\n"
        "<b>Basic Auth:</b> Отправляет логин:пароль в заголовке HTTP Authorization в кодировке Base64 (нешифрованной). Требует HTTPS для безопасности.\n\n"
        "<b>Digest Auth:</b> Выполняет обмен хешами (MD5) вместо передачи пароля, использует nonce-сервер. Безопаснее Basic, но сложнее в реализации и встречается реже.\n\n"
        "Basic проще и используется чаще (особенно с HTTPS), Digest обеспечивает дополнительную защиту от перехвата учётных данных."
    )
    await update.message.reply_html(message)


async def threat_tools_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Выводит информацию об инструментах Threat Hunting и Threat Intelligence."""
    if not await check_access(update):
        return
    message = (
        "🕵️ <b>Инструменты Threat Hunting & Threat Intelligence</b>\n\n"
        "<b>Threat Hunting (проактивный поиск угроз в инфраструктуре):</b>\n"
        "• ELK/Splunk + Sysmon – централизованный сбор и анализ логов хоста\n"
        "• Zeek (Bro) – анализ сетевого трафика на подозрительную активность\n"
        "• OSQuery – запросы к состоянию системы для выявления аномалий\n\n"
        "<b>Threat Intelligence (разведка угроз):</b>\n"
        "• MISP – платформа для обмена индикаторами компрометации (IOC)\n"
        "• VirusTotal, AbuseIPDB – сервисы проверки подозрительных файлов и адресов\n"
        "• Shodan – поиск уязвимых открытых хостов и сервисов"
    )
    await update.message.reply_html(message)


async def memory_tools_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Выводит информацию об утилитах для анализа оперативной памяти."""
    if not await check_access(update):
        return
    message = (
        "💾 <b>Утилиты анализа оперативной памяти</b>\n\n"
        "1️⃣ <b>Volatility</b> – мощный фреймворк для форензики памяти (работа с дампами RAM). Пример использования: <code>volatility -f memory.dmp pslist</code>\n\n"
        "2️⃣ <b>Rekall</b> – форк Volatility с аналогичным функционалом\n\n"
        "3️⃣ <b>DumpIt</b> – утилита для быстрого снятия дампа памяти в Windows\n\n"
        "4️⃣ <b>Belkasoft Live RAM Capturer</b> – инструмент для снятия дампа памяти даже при запущенных антивирусах"
    )
    await update.message.reply_html(message)


async def disk_tools_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Выводит информацию об утилитах для анализа жестких дисков."""
    if not await check_access(update):
        return
    message = (
        "🗄️ <b>Утилиты анализа жесткого диска</b>\n\n"
        "• EnCase, FTK Imager – промышленный и бесплатный инструменты для съемки образов дисков и анализа\n"
        "• Autopsy (The Sleuth Kit) – бесплатный GUI для форензики дисков, поиск артефактов\n"
        "• WinHex – продвинутый HEX-редактор, позволяющий исследовать сырые данные диска\n"
        "• HDDSuperClone – утилита для клонирования проблемных дисков с восстановлением данных"
    )
    await update.message.reply_html(message)


async def incident_response_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Выводит информацию об этапах процесса Incident Response (реагирования на инциденты)."""
    if not await check_access(update):
        return
    message = (
        "🛡️ <b>Этапы реагирования на инциденты (Incident Response)</b>\n\n"
        "1️⃣ <b>Подготовка (Preparation)</b> – планирование стратегий реагирования, обучение команды, обеспечение инструментами.\n\n"
        "2️⃣ <b>Обнаружение и анализ (Detection & Analysis)</b> – выявление инцидента и определение его природы, масштабов, влияния.\n\n"
        "3️⃣ <b>Сдерживание (Containment)</b> – локализация инцидента (изоляция заражённых систем, блокировка вредоносного трафика).\n\n"
        "4️⃣ <b>Устранение (Eradication)</b> – удаление вредоносного кода, восстановление систем из чистых резервных копий, устранение уязвимостей.\n\n"
        "5️⃣ <b>Восстановление (Recovery)</b> – возврат систем в рабочий режим, дополнительные мониторинг и проверки перед вводом в строй.\n\n"
        "6️⃣ <b>Уроки (Lessons Learned)</b> – пост-инцидентный анализ: что произошло, что сработало/не сработало, обновление планов и политик безопасности."
    )
    await update.message.reply_html(message)


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
        # Обновляем админ-панель, если она открыта
        if "admin_msg_id" in context.user_data and "admin_chat_id" in context.user_data:
            chat_id = context.user_data["admin_chat_id"]
            msg_id = context.user_data["admin_msg_id"]
            text_panel = "👮 <b>Админ-панель</b>\n\n"
            text_panel += "Авторизованные пользователи:\n"
            if ALLOWED_USERS:
                for uid in ALLOWED_USERS:
                    text_panel += f"• {uid}\n"
            else:
                text_panel += "• (нет дополнительных пользователей)\n"
            text_panel += (
                "\nВы можете добавить или удалить пользователей с помощью кнопок ниже."
            )
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
                await context.bot.edit_message_text(
                    text_panel,
                    chat_id=chat_id,
                    message_id=msg_id,
                    reply_markup=InlineKeyboardMarkup(keyboard),
                    parse_mode="HTML",
                )
            except Exception as e:
                logging.error(f"Ошибка обновления админ-панели: {e}")
        return
    # Если ожидается ввод параметра для проверки IOC (после выбора в меню "Анализ IOC")
    if context.user_data.get("expecting_ip"):
        context.user_data["expecting_ip"] = False
        try:
            ipaddress.ip_address(text)
        except ValueError:
            await update.message.reply_text(
                "⚠️ Некорректный IP-адрес. Попробуйте снова или нажмите 'Назад' для отмены."
            )
            context.user_data["expecting_ip"] = True
            return
        context.args = [text]
        await check_ip(update, context)
        return
    if context.user_data.get("expecting_domain"):
        context.user_data["expecting_domain"] = False
        # (Опционально: добавить проверку формата домена)
        context.args = [text]
        await check_domain(update, context)
        return
    if context.user_data.get("expecting_url"):
        context.user_data["expecting_url"] = False
        context.args = [text]
        await check_url(update, context)
        return
    if context.user_data.get("expecting_hash"):
        context.user_data["expecting_hash"] = False
        context.args = [text]
        await check_hash(update, context)
        return
    if context.user_data.get("expecting_whois"):
        context.user_data["expecting_whois"] = False
        context.args = [text]
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
            [KeyboardButton("Векторы атак"), KeyboardButton("Инструменты атакующих")],
            [KeyboardButton("События Sysmon"), KeyboardButton("Пути логов")],
            [
                KeyboardButton("Basic/Digest auth"),
                KeyboardButton("Threat Hunting/Intel"),
            ],
            [KeyboardButton("Анализ памяти"), KeyboardButton("Анализ диска")],
            [KeyboardButton("Этапы IR"), KeyboardButton("Назад")],
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
    # Обработка нажатий кнопок справочного подменю ("Обучение")
    if text == "kill chain":
        await killchain_info(update, context)
    elif text == "owasp top 10":
        await owasp_info(update, context)
    elif text == "модель osi":
        await osi_model(update, context)
    elif text == "модель tcp/ip":
        await tcpip_model(update, context)
    elif text == "векторы атак":
        await attack_vectors_info(update, context)
    elif text == "инструменты атакующих":
        await attacker_tools_info(update, context)
    elif text == "события sysmon":
        await sysmon_events_info(update, context)
    elif text == "пути логов":
        await log_paths_info(update, context)
    elif text == "basic/digest auth":
        await auth_info(update, context)
    elif text == "threat hunting/intel":
        await threat_tools_info(update, context)
    elif text == "анализ памяти":
        await memory_tools_info(update, context)
    elif text == "анализ диска":
        await disk_tools_info(update, context)
    elif text == "этапы ir":
        await incident_response_info(update, context)
    else:
        # Неизвестный ввод – предлагаем команду /help
        await update.message.reply_text(
            "❓ Не понял запрос. Введите /help для списка команд."
        )


# ======= Запуск бота =======


def main():
    # Инициализация приложения Telegram
    application = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    # Регистрация обработчиков команд
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
    application.add_handler(CommandHandler("attackvectors", attack_vectors_info))
    application.add_handler(CommandHandler("attacktools", attacker_tools_info))
    application.add_handler(CommandHandler("sysmon", sysmon_events_info))
    application.add_handler(CommandHandler("logpaths", log_paths_info))
    application.add_handler(CommandHandler("auth", auth_info))
    application.add_handler(CommandHandler("threattools", threat_tools_info))
    application.add_handler(CommandHandler("memory", memory_tools_info))
    application.add_handler(CommandHandler("disk", disk_tools_info))
    application.add_handler(CommandHandler("ir", incident_response_info))
    application.add_handler(CommandHandler("admin", admin_panel))
    # Регистрация обработчиков CallbackQuery и текстовых сообщений
    application.add_handler(CallbackQueryHandler(handle_callback))
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message)
    )
    # Запуск бота (polling)
    application.run_polling()


if __name__ == "__main__":
    main()
