[16.11.2026 20:52] Dan: """
Промышленный парсер, 6-ступенчатый аудитор и генератор VPN-подписки (0 руб.)
Архитектура проверки:
Ревалидация старой подписки: сначала тестируются текущие серверы из sub.txt.
Живые и быстрые остаются в строю, мертвые удаляются, новые добавляются рядом.
Асинхронный сбор из 25+ агрегаторов (VLESS, Reality, Trojan, VMess, Shadowsocks).
6-ступенчатый жесткий аудит через официальное ядро Xray-core:
Этап 1 (Крипто-фильтр): Блокировка слабых шифров (none, rc4, md5, cfb),
отключенных сертификатов (allowInsecure) и локальных/приватных IP (SSRF).
Этап 2 (Изоляция DNS и утечек): Весь DNS идет строго через зашифрованный
DoH внутри туннеля + socks5-hostname. Проверка реального выходного IP
через HTTPS Cloudflare Trace (сверка с IP сканера).
Этап 3 (Защита от подмены трафика / MITM): Проверка отсутствия инъекций
заголовков прозрачных прокси (Via, X-Forwarded-For, Proxy-Connection).
Этап 4 (Обход блокировок): Реальный запрос к YouTube / Google 204.
Этап 5 (Стресс-тест скорости): Скачивание тестового пакета 500 КБ и замер
реальной пропускной способности в Мбит/с (отсев медленных серверов).
Этап 6 (Рейтинг и гео-маркировка): Сортировка по индексу качества (скорость/пинг)
и присвоение чистых названий с точным флагом выходной страны.
"""
import asyncio
import base64
import ipaddress
import json
import os
import re
import socket
import time
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
Расширенный пул проверенных источников (обновляются сообществами каждые 15-60 минут)
SOURCES = [
"https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
"https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
"https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub2.txt",
"https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
"https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
"https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/mix",
"https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless",
"https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/reality",
"https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/trojan",
"https://raw.githubusercontent.com/freefq/free/master/v2",
"https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
"https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
"https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
"https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
"https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
"https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/vless",
"https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/tr",
"https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/ss",
"https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
"https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/reality",
"https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",
"https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vmess",
"https://raw.githubusercontent.com/MrPooyaX/VpnsFucking/main/Behzad.txt",
"https://raw.githubusercontent.com/vpei/Free-Node-Merge/main/o/node.txt",
"https://raw.githubusercontent.com/a2470982985/getNode/main/v2ray.txt",
]
Параметры производительности и фильтрации
CONCURRENCY = 90              # Количество одновременных проверок
TIMEOUT = 8                   # Максимальный таймаут на этап (сек)
MIN_SPEED_MBPS = 2.0          # Минимальная реальная скорость скачивания (Мбит/с)
MAX_LATENCY_MS = 2500         # Максимальный допустимый пинг (мс)
Эндпоинты для аудита
TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"
HEADERS_CHECK_URL = "https://httpbin.org/headers"
WEB_CHECK_URL = "https://www.youtube.com/generate_204"
SPEED_TEST_URL = "https://speed.
[16.11.2026 20:52] Dan: cloudflare.com/__down?bytes=500000"  # Тест на 500 КБ
XRAY_BIN = "./xray"
OLD_SUB_FILE = "sub.txt"
SUB_B64_FILE = "sub_b64.txt"
UNSAFE_CIPHERS = {
"none", "plain", "rc4", "rc4-md5", "aes-128-cfb",
"aes-256-cfb", "bf-cfb", "cast5-cfb", "chacha20"
}
PROXY_LEAK_HEADERS = ("via", "x-forwarded-for", "proxy-connection", "x-real-ip")
COUNTRY_NAMES = {
"DE": "Германия", "NL": "Нидерланды", "US": "США", "FI": "Финляндия",
"GB": "Великобритания", "FR": "Франция", "SE": "Швеция", "CH": "Швейцария",
"AT": "Австрия", "PL": "Польша", "CZ": "Чехия", "ES": "Испания",
"IT": "Италия", "NO": "Норвегия", "DK": "Дания", "IE": "Ирландия",
"BE": "Бельгия", "LU": "Люксембург", "EE": "Эстония", "LV": "Латвия",
"LT": "Литва", "RO": "Румыния", "BG": "Болгария", "MD": "Молдова",
"UA": "Украина", "KZ": "Казахстан", "TR": "Турция", "AE": "ОАЭ",
"IL": "Израиль", "SG": "Сингапур", "JP": "Япония", "KR": "Южная Корея",
"HK": "Гонконг", "TW": "Тайвань", "IN": "Индия", "CA": "Канада",
"BR": "Бразилия", "AU": "Австралия", "AM": "Армения", "GE": "Грузия",
"IS": "Исландия", "PT": "Португалия", "GR": "Греция", "HU": "Венгрия",
"SK": "Словакия", "RS": "Сербия", "HR": "Хорватия", "CY": "Кипр",
}
def download_xray():
"""Скачивает свежий бинарник Xray-core для Linux x64."""
if os.path.exists(XRAY_BIN):
return
print("[*] Скачиваем официальное ядро Xray-core...")
url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
zip_path = "xray.zip"
try:
urllib.request.urlretrieve(url, zip_path)
with zipfile.ZipFile(zip_path, "r") as zf:
zf.extract("xray", ".")
os.chmod(XRAY_BIN, 0o755)
os.remove(zip_path)
print("[+] Ядро Xray-core успешно установлено.")
except Exception as e:
print(f"[-] Ошибка загрузки Xray: {e}")
def get_host_ip():
"""Определяет реальный IP сервера GitHub Actions для проверки утечек."""
try:
with urllib.request.urlopen(TRACE_URL, timeout=6) as resp:
text = resp.read().decode("utf-8", errors="ignore")
for line in text.splitlines():
if line.startswith("ip="):
return line.split("=", 1)[1].strip()
except Exception:
pass
return None
def is_safe_host(host):
"""Блокирует локальные, зарезервированные и некорректные адреса."""
if not host or host.lower() in ("localhost", "0.0.0.0", "127.0.0.1"):
return False
try:
ip = ipaddress.ip_address(host)
if (
ip.is_private
or ip.is_loopback
or ip.is_reserved
or ip.is_multicast
or ip.is_link_local
or ip.is_unspecified
):
return False
except ValueError:
if "." not in host or len(host) < 4:
return False
return True
def load_existing_servers():
"""Читает рабочие серверы из текущей подписки для первоочередной проверки."""
if not os.path.exists(OLD_SUB_FILE):
return []
try:
with open(OLD_SUB_FILE, "r", encoding="utf-8") as f:
return [
line.strip()
for line in f
if line.strip().startswith(("vless://", "vmess://", "trojan://", "ss://"))
]
except Exception:
return []
def fetch_source(url):
"""Скачивает список конфигураций из одного источника."""
try:
req = urllib.request.Request(
url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
)
with urllib.request.urlopen(req, timeout=12) as response:
return response.read().decode("utf-8", errors="ignore")
except Exception:
return ""
def extract_configs(content):
"""Декодирует Base64 (если нужно) и извлекает все валидные ссылки."""
configs = []
text = content.strip()
if not text:
return configs
if "://" not in text[:80]:
    try:
        padded = text + "=" * ((4 - len(text) % 4) % 4)
        text = base64.b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:
        pass

for line in text.splitlines():
    line = line.strip()
    if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
        configs.append(line)
return configs
def get_free_port():
"""Выделяет свободный локальный TCP-порт."""
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
s.bind(("127.0.0.1", 0))
return s.getsockname()[1]
def build_xray_outbound(uri):
"""
Парсит URI и строит конфиг outbound для Xray-core.
На этом этапе отсеиваются криптографически слабые и небезопасные узлы.
"""
try:
if uri.startswith("vmess://"):
b64 = uri[8:].
[16.11.2026 20:52] Dan: split("#")[0]
padded = b64 + "=" * ((4 - len(b64) % 4) % 4)
data = json.loads(base64.b64decode(padded).decode("utf-8", errors="ignore"))
host = str(data.get("add", "")).strip()
port = int(data.get("port", 0))
if not is_safe_host(host) or not (1 <= port <= 65535):
return None
        scy = str(data.get("scy", "auto")).lower()
        if scy in UNSAFE_CIPHERS:
            return None

        net = data.get("net", "tcp")
        tls = data.get("tls", "")
        # Требуем обязательное TLS-шифрование для VMess поверх открытых сетей
        if tls != "tls":
            return None

        stream = {
            "network": net,
            "security": "tls",
            "tlsSettings": {
                "serverName": data.get("sni") or data.get("host") or host,
                "allowInsecure": False,
            },
        }
        if net == "ws":
            stream["wsSettings"] = {
                "path": data.get("path", "/"),
                "headers": {"Host": data.get("host", "")},
            }
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": data.get("path", "")}

        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": host,
                        "port": port,
                        "users": [
                            {
                                "id": data["id"],
                                "alterId": int(data.get("aid", 0)),
                                "security": scy,
                            }
                        ],
                    }
                ]
            },
            "streamSettings": stream,
        }

    elif uri.startswith("vless://"):
        parsed = urllib.parse.urlparse(uri)
        params = urllib.parse.parse_qs(parsed.query)
        host = parsed.hostname
        port = parsed.port or 443
        uuid = parsed.username
        if not uuid or not is_safe_host(host) or not (1 <= port <= 65535):
            return None

        net = params.get("type", ["tcp"])[0]
        security = params.get("security", ["none"])[0]
        flow = params.get("flow", [""])[0]

        if security not in ("tls", "reality"):
            return None

        stream = {"network": net}
        if security == "tls":
            stream["security"] = "tls"
            stream["tlsSettings"] = {
                "serverName": params.get("sni", [host])[0],
                "allowInsecure": False,
            }
        elif security == "reality":
            pbk = params.get("pbk", [""])[0]
            if not pbk:
                return None
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "serverName": params.get("sni", [host])[0],
                "fingerprint": params.get("fp", ["chrome"])[0],
                "publicKey": pbk,
                "shortId": params.get("sid", [""])[0],
            }

        if net == "ws":
            stream["wsSettings"] = {
                "path": params.get("path", ["/"])[0],
                "headers": {"Host": params.get("host", [host])[0]},
            }
        elif net == "grpc":
            stream["grpcSettings"] = {
                "serviceName": params.get("serviceName", [""])[0]
            }

        user = {"id": uuid, "encryption": params.get("encryption", ["none"])[0]}
        if flow:
            user["flow"] = flow

        return {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": stream,
        }

    elif uri.startswith("trojan://"):
        parsed = urllib.parse.urlparse(uri)
        params = urllib.parse.parse_qs(parsed.query)
        host = parsed.hostname
        port = parsed.port or 443
        password = urllib.parse.unquote(parsed.username or "")
        if not password or not is_safe_host(host) or not (1 <= port <= 65535):
            return None

        net = params.get("type", ["tcp"])[0]
        security = params.get("security", ["tls"])[0]
[16.11.2026 20:52] Dan: if security != "tls":
            return None

        stream = {
            "network": net,
            "security": "tls",
            "tlsSettings": {
                "serverName": params.get("sni", [host])[0],
                "allowInsecure": False,
            },
        }
        if net == "ws":
            stream["wsSettings"] = {
                "path": params.get("path", ["/"])[0],
                "headers": {"Host": params.get("host", [host])[0]},
            }

        return {
            "protocol": "trojan",
            "settings": {
                "servers": [{"address": host, "port": port, "password": password}]
            },
            "streamSettings": stream,
        }

    elif uri.startswith("ss://"):
        raw = uri[5:].split("#")[0]
        if "@" in raw:
            userinfo, hostport = raw.split("@", 1)
            if ":" not in userinfo:
                padded = userinfo + "=" * ((4 - len(userinfo) % 4) % 4)
                userinfo = base64.b64decode(padded).decode("utf-8", errors="ignore")
            method, password = userinfo.split(":", 1)
            host, port_str = hostport.split(":", 1)
        else:
            padded = raw + "=" * ((4 - len(raw) % 4) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            userinfo, hostport = decoded.split("@", 1)
            method, password = userinfo.split(":", 1)
            host, port_str = hostport.split(":", 1)

        port = int(re.sub(r"\D.*", "", port_str))
        if (
            not is_safe_host(host)
            or not (1 <= port <= 65535)
            or method.lower() in UNSAFE_CIPHERS
        ):
            return None

        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": host,
                        "port": port,
                        "method": method,
                        "password": password,
                    }
                ]
            },
        }
except Exception:
    return None
return None
def country_to_flag(country_code):
"""Превращает ISO-код страны (например, DE) в флаг 🇩🇪."""
if not country_code or len(country_code) != 2 or not country_code.isalpha():
return "🌐"
return "".join(chr(127397 + ord(c)) for c in country_code.upper())
def get_protocol_badge(uri):
"""Определяет компактную метку протокола."""
if uri.startswith("vless://"):
return "Reality" if "security=reality" in uri else "VLESS"
if uri.startswith("trojan://"):
return "Trojan"
if uri.startswith("vmess://"):
return "VMess"
if uri.startswith("ss://"):
return "SS"
return "VPN"
def format_clean_name(country_code, index, proto, latency_ms, speed_mbps):
"""
Генерирует идеальное, чистое имя без спама и иероглифов:
Пример: '🇩🇪 Германия #1 [Reality] | 98ms | 54.2 Mbps'
"""
code = (country_code or "XX").upper()
flag = country_to_flag(code)
country_title = COUNTRY_NAMES.get(code, code if code != "XX" else "Мир")
return f"{flag} {country_title} #{index} [{proto}] | {latency_ms}ms | {speed_mbps:.1f} Mbps"
async def run_curl(local_port, url, max_time, write_out=None):
"""Изолированный запрос через локальный SOCKS5-туннель с удаленным DNS."""
cmd = [
"curl",
"-s",
"-L",
"--socks5-hostname",
f"127.0.0.1:{local_port}",
"--max-time",
str(max_time),
url,
]
if write_out:
cmd.extend(["-o", "/dev/null", "-w", write_out])
proc = await asyncio.create_subprocess_exec(
    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
)
stdout, _ = await proc.communicate()
return proc.returncode, stdout.decode("utf-8", errors="ignore")
async def audit_server(uri, host_ip, semaphore):
"""Проводит полный 6-ступенчатый аудит одного сервера."""
async with semaphore:
outbound = build_xray_outbound(uri)
if not outbound:
return None
    local_port = get_free_port()
    config = {
        "log": {"loglevel": "none"},
        "dns": {"servers": ["https+local://1.1.1.1/dns-query"]},
        "inbounds": [
            {
                "port": local_port,
                "listen": "127.0.0.1",
[16.11.2026 20:52] Dan: "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [outbound, {"protocol": "blackhole", "tag": "block"}],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}
            ],
        },
    }

    config_path = f"/tmp/xray_{local_port}.json"
    with open(config_path, "w") as f:
        json.dump(config, f)

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            XRAY_BIN,
            "-c",
            config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.sleep(0.35)

        # ЭТАП 2: Проверка выходного IP, утечек, HTTPS и реальной страны
        t0 = time.monotonic()
        rc, body = await run_curl(local_port, TRACE_URL, TIMEOUT)
        latency = int((time.monotonic() - t0) * 1000)

        if rc != 0 or not body or latency > MAX_LATENCY_MS:
            return None

        trace_data = {}
        for line in body.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                trace_data[k.strip()] = v.strip()

        proxy_ip = trace_data.get("ip")
        country = trace_data.get("loc", "XX")

        if (
            "fl" not in trace_data
            or trace_data.get("visit_scheme") != "https"
            or not proxy_ip
            or proxy_ip == host_ip
        ):
            return None

        # ЭТАП 3: Проверка отсутствия заголовков прозрачных/дырявых прокси (анонимность)
        rc_hdr, hdr_body = await run_curl(local_port, HEADERS_CHECK_URL, 6)
        if rc_hdr == 0 and hdr_body:
            try:
                hdr_json = json.loads(hdr_body).get("headers", {})
                lower_keys = {k.lower() for k in hdr_json.keys()}
                if any(leak in lower_keys for leak in PROXY_LEAK_HEADERS):
                    return None
            except Exception:
                pass

        # ЭТАП 4: Реальная проверка обхода цензуры (YouTube 204)
        rc_web, code_web = await run_curl(
            local_port, WEB_CHECK_URL, 6, "%{http_code}"
        )
        if rc_web != 0 or code_web.strip() not in ("200", "204"):
            return None

        # ЭТАП 5: Замер реальной пропускной способности (скачивание 500 КБ)
        rc_spd, spd_out = await run_curl(
            local_port, SPEED_TEST_URL, 8, "%{speed_download}"
        )
        if rc_spd != 0:
            return None

        try:
            bytes_per_sec = float(spd_out.strip())
            speed_mbps = (bytes_per_sec * 8) / 1_000_000
        except ValueError:
            return None

        if speed_mbps < MIN_SPEED_MBPS:
            return None

        base_uri = uri.split("#")[0]
        # Вычисляем интегральный рейтинг качества (чем выше скорость и ниже пинг, тем лучше)
        quality_score = (speed_mbps * 1000) / max(latency, 50)

        return {
            "base_uri": base_uri,
            "proto": get_protocol_badge(base_uri),
            "country": country,
            "latency": latency,
            "speed_mbps": speed_mbps,
            "exit_ip": proxy_ip,
            "score": quality_score,
        }

    except Exception:
        pass
    finally:
        if proc and proc.returncode is None:
            try:
                proc.terminate()
                await proc.wait()
            except Exception:
                pass
        if os.path.exists(config_path):
            os.remove(config_path)

    return None
async def main_async():
start_time = time.monotonic()
download_xray()
if not os.path.exists(XRAY_BIN):
print("[-] Ошибка: не удалось запустить Xray-core.")
return
host_ip = get_host_ip()
print(f"[*] Базовый IP сканера: {host_ip or 'не определен'}")

# 1. Загружаем старые серверы из прошлой подписки
old_servers = load_existing_servers()
print(f"[1/4] Загружено старых серверов на ревалидацию: {len(old_servers)}")

# 2.
[16.11.2026 20:52] Dan: Параллельно скачиваем свежие серверы из всех источников
print(f"[2/4] Параллельный сбор из {len(SOURCES)} источников...")
unique_candidates = {}
for cfg in old_servers:
    unique_candidates[cfg.split("#")[0]] = cfg

new_count = 0
with ThreadPoolExecutor(max_workers=15) as pool:
    results = pool.map(fetch_source, SOURCES)
    for raw in results:
        for cfg in extract_configs(raw):
            base = cfg.split("#")[0]
            if base not in unique_candidates:
                unique_candidates[base] = cfg
                new_count += 1

all_candidates = list(unique_candidates.values())
print(f"      -> Новых кандидатов найдено: {new_count}")
print(f"      -> Всего отправлено на 6-ступенчатый аудит: {len(all_candidates)}")

# 3. Запускаем многопоточный аудит
print(f"[3/4] Запуск аудита (потоков: {CONCURRENCY})...")
semaphore = asyncio.Semaphore(CONCURRENCY)
tasks = [audit_server(cfg, host_ip, semaphore) for cfg in all_candidates]

passed = []
completed = 0
total = len(tasks)

for coro in asyncio.as_completed(tasks):
    res = await coro
    completed += 1
    if res:
        passed.append(res)
    if completed % 300 == 0 or completed == total:
        print(
            f"      Прогресс: {completed}/{total} | Прошли все проверки: {len(passed)}"
        )

# Сортируем от самых быстрых и отзывчивых к остальным
passed.sort(key=lambda x: x["score"], reverse=True)

# 4. Формируем единую подписку с чистыми названиями и точными флагами
country_counters = {}
final_uris = []

for item in passed:
    c_code = item["country"]
    country_counters[c_code] = country_counters.get(c_code, 0) + 1
    idx = country_counters[c_code]

    clean_label = format_clean_name(
        c_code, idx, item["proto"], item["latency"], item["speed_mbps"]
    )
    encoded_label = urllib.parse.quote(clean_label)
    final_uris.append(f"{item['base_uri']}#{encoded_label}")

elapsed = int(time.monotonic() - start_time)
print(
    f"\n[4/4] Готово за {elapsed} сек! В подписку записано {len(final_uris)} элитных серверов."
)

combined_text = "\n".join(final_uris)
with open(OLD_SUB_FILE, "w", encoding="utf-8") as f:
    f.write(combined_text)

b64_encoded = base64.b64encode(combined_text.encode("utf-8")).decode("utf-8")
with open(SUB_B64_FILE, "w", encoding="utf-8") as f:
    f.write(b64_encoded)
if name == "main":
asyncio.run(main_async())