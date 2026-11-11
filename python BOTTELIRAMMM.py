```python
# -*- coding: utf-8 -*-
# بوت رفع استضافة بيبو - الجزء الأول
# التشغيل: pip install requests ثم python Bot.py

import ast
import atexit
import copy
import hashlib
import html
import importlib.util
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlparse

import requests

# ================== الإعدادات ==================
TOKEN = "9175961504:AAGS2bF6B3SlbkIJRymeawuwpS1dWX6fQz0"
OWNER_ID = 8988529781         # المالك (أدمن أساسي ولا يمكن حذفه)
API = f"https://api.telegram.org/bot{TOKEN}"
FILE_API = f"https://api.telegram.org/file/bot{TOKEN}"

# صورة القائمة: تظهر كمعاينة رابط فوق النص (الرابط نفسه مخفي)
MENU_PHOTO = "https://i.postimg.cc/3wGB8j7B/1000060550.jpg"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BOTS_DIR = os.path.join(BASE_DIR, "hosted", "bots")
SITES_DIR = os.path.join(BASE_DIR, "hosted", "sites")
os.makedirs(BOTS_DIR, exist_ok=True)
os.makedirs(SITES_DIR, exist_ok=True)

# دعم بورت Render (متغير البيئة PORT) أو الافتراضي 8080
RENDER_PORT = os.environ.get("PORT")
SITE_PORT = int(RENDER_PORT) if RENDER_PORT and RENDER_PORT.isdigit() else 8080

# القيم الافتراضية (كلها تتغير من لوحة التحكم بدون تعديل الكود)
DEFAULTS = {
    "king_url": "https://YOUR_USERNAME.github.io/king/",   # رابط صفحة index.html (HTTPS)
    "dev_url": "https://t.me/YOUR_DEV_USERNAME",
    "channel_url": "https://t.me/YOUR_DEV_CHANNEL",
    "base_url": "http://YOUR_SERVER_IP:8080",              # الرابط العام للسيرفر (للمواقع)
    "maintenance": "0",
    "cost_bot": "5",     # تكلفة رفع بوت
    "cost_site": "2",    # تكلفة رفع موقع
    "reward": "1",       # نقاط الدعوة
    "auto_mode": "0",    # 1 = قبول/رفض تلقائي بعد الفحص | 0 = يدوي
    "max_warns": "3",    # عدد التحذيرات قبل الحظر النهائي
}

MAX_FILE_SIZE = 5 * 1024 * 1024   # 5MB
TOKEN_RE = re.compile(r"\b\d{8,11}:[A-Za-z0-9_-]{30,}\b")


# =====================================================================
# ================== الفاحص (scanner) - فحص ثابت ======================
# =====================================================================
W = {"critical": 100, "high": 35, "medium": 12, "low": 3}
SEV_AR = {"critical": "حرج", "high": "عالي", "medium": "متوسط", "low": "منخفض"}
VERDICT_AR = {"safe": "آمن", "suspicious": "مشبوه", "dangerous": "خطير", "invalid": "لا يعمل (خطأ برمجي)"}
ADVICE = {
    "safe": "لم يظهر أي سلوك خطير. يمكن قبوله.",
    "suspicious": "فيه بنود تحتاج مراجعة بشرية قبل القبول.",
    "dangerous": "يُنصح بالرفض فوراً.",
    "invalid": "الملف فيه خطأ برمجي ولن يعمل.",
}

_STD_FALLBACK = {
    "os", "sys", "re", "json", "time", "datetime", "random", "math", "asyncio", "logging", "threading",
    "sqlite3", "collections", "itertools", "functools", "typing", "subprocess", "urllib", "http", "socket",
    "base64", "hashlib", "shutil", "pathlib", "string", "io", "traceback", "uuid", "copy", "csv", "html",
    "zipfile", "tempfile", "glob", "signal", "pickle", "struct", "queue", "enum", "dataclasses", "abc",
    "argparse", "textwrap", "platform", "ssl", "email", "smtplib", "secrets", "hmac", "zlib", "gzip",
    "contextlib", "inspect", "importlib", "ast", "operator", "decimal", "statistics", "heapq", "bisect",
    "codecs", "locale", "calendar", "configparser", "multiprocessing", "concurrent", "ctypes", "select",
    "xml", "webbrowser", "getpass", "pprint", "shlex", "fnmatch", "tarfile", "atexit", "errno", "stat",
    "binascii", "pty", "marshal", "builtins", "warnings", "weakref", "gc", "unittest", "tty", "telnetlib",
}
STDLIB = set(getattr(sys, "stdlib_module_names", ())) | _STD_FALLBACK

# ---------- قواعد النص (تُطبَّق على أي ملف)
TEXT_RULES = [
    (r"xmrig|stratum\+tcp|cryptonight|minerd\b|coinhive", "critical", "علامات تعدين عملات رقمية (Miner)"),
    (r"rm\s+-rf\s+(?:/|~|\*|\.)|mkfs\.|dd\s+if=\S+\s+of=/dev/|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
     "critical", "أمر تدمير للنظام (rm -rf / mkfs / fork bomb)"),
    (r"/etc/(?:passwd|shadow)|\.ssh/|id_rsa|\.bash_history|/proc/(?:self|\d+)/(?:environ|mem|maps)",
     "critical", "قراءة ملفات حساسة في السيرفر"),
    (r"Login Data|Local State|cookies\.sqlite|wallet\.dat|key4\.db|logins\.json",
     "critical", "سرقة بيانات متصفح أو محافظ"),
    (r"hosted[/\\]+(?:bots|sites)|\bBOTS_DIR\b|\bSITES_DIR\b",
     "critical", "محاولة الوصول لملفات البوتات/المواقع الأخرى في الاستضافة"),
    (r"\btdata\b", "high", "الوصول لبيانات تيليجرام (tdata)"),
    (r"discord(?:app)?\.com/api/webhooks", "high", "إرسال بيانات عبر Discord Webhook (يُستخدم غالباً للتسريب)"),
    (r"/bin/(?:ba|z)?sh\b|cmd\.exe|powershell", "high", "استدعاء شل النظام"),
    (r"\.\.[/\\]", "high", "الخروج من مجلد البوت (../)"),
    (r"slowloris|ddos|syn[_ -]?flood|udp[_ -]?flood|http[_ -]?flood", "high", "كلمات مرتبطة بهجمات حجب الخدمة DDoS"),
    (r"pastebin\.com/raw|transfer\.sh|anonfiles|gofile\.io|0x0\.st|ngrok", "medium",
     "رفع/تنزيل من مواقع مشاركة ملفات أو أنفاق"),
    (r"https?://\d{1,3}(?:\.\d{1,3}){3}", "medium", "اتصال بعنوان IP مباشر"),
]

IMPORT_RULES = {
    "ctypes": ("high", "استخدام ctypes (وصول مباشر للنظام/الذاكرة)"),
    "pynput": ("high", "مكتبة تسجيل لوحة المفاتيح/الماوس (Keylogger)"),
    "keyboard": ("high", "مكتبة التقاط لوحة المفاتيح"),
    "pyautogui": ("medium", "التحكم بالماوس والشاشة"),
    "mss": ("high", "التقاط لقطات الشاشة"),
    "pyscreenshot": ("high", "التقاط لقطات الشاشة"),
    "paramiko": ("high", "اتصال SSH بسيرفرات"),
    "pexpect": ("high", "التحكم ببرامج طرفية (pexpect)"),
    "scapy": ("high", "حزم شبكة خام (Scapy)"),
    "nmap": ("high", "فحص منافذ (Nmap)"),
    "browser_cookie3": ("critical", "سحب كوكيز المتصفحات"),
    "win32crypt": ("critical", "فك تشفير كلمات مرور ويندوز"),
    "pyperclip": ("medium", "قراءة الحافظة"),
    "pty": ("high", "استخدام pty (غالباً شل عكسي)"),
    "telnetlib": ("medium", "اتصال Telnet"),
}
FULL_IMPORT_RULES = {"PIL.ImageGrab": ("high", "التقاط لقطات الشاشة (ImageGrab)")}
``````python
# -*- coding: utf-8 -*-
# بوت رفع استضافة بيبو - الجزء الثاني

CALL_RULES = {
    "os.system": ("high", "تنفيذ أوامر نظام (os.system)"),
    "os.popen": ("high", "تنفيذ أوامر نظام (os.popen)"),
    "os.execv": ("high", "استبدال العملية (os.exec*)"), "os.execl": ("high", "استبدال العملية (os.exec*)"),
    "os.execvp": ("high", "استبدال العملية (os.exec*)"), "os.execve": ("high", "استبدال العملية (os.exec*)"),
    "os.fork": ("high", "إنشاء عمليات (os.fork)"),
    "os.kill": ("high", "إنهاء عمليات في السيرفر (قد يوقف البوت الرئيسي)"),
    "os.killpg": ("high", "إنهاء عمليات في السيرفر (قد يوقف البوت الرئيسي)"),
    "os.remove": ("medium", "حذف ملفات"), "os.unlink": ("medium", "حذف ملفات"),
    "os.rmdir": ("medium", "حذف مجلدات"), "os.removedirs": ("medium", "حذف مجلدات"),
    "shutil.rmtree": ("high", "حذف مجلدات كاملة (rmtree)"),
    "os.chmod": ("high", "تغيير صلاحيات الملفات"), "os.chown": ("high", "تغيير مالك الملفات"),
    "os.setuid": ("high", "تغيير مستخدم النظام"), "os.setgid": ("high", "تغيير مجموعة النظام"),
    "os.chdir": ("medium", "تغيير مجلد العمل"),
    "pickle.loads": ("medium", "فك تسلسل بيانات (قد ينفذ كوداً)"),
    "pickle.load": ("medium", "فك تسلسل بيانات (قد ينفذ كوداً)"),
    "marshal.loads": ("medium", "فك تسلسل كود (marshal)"), "marshal.load": ("medium", "فك تسلسل كود (marshal)"),
    "__import__": ("high", "استيراد ديناميكي مخفي (__import__)"),
    "socket.socket": ("medium", "اتصال شبكة منخفض المستوى (socket)"),
    "urllib.request.urlretrieve": ("medium", "تنزيل ملفات من الإنترنت"),
    "compile": ("medium", "تجميع كود ديناميكي (compile)"),
}
FS_FUNCS = {"os.walk", "os.listdir", "os.scandir", "glob.glob", "glob.iglob", "shutil.copytree", "shutil.copy",
            "shutil.copyfile", "shutil.make_archive", "os.chdir", "pathlib.Path", "open"}
HIDE = {"b64decode", "decompress", "loads", "unhexlify", "fromhex", "a85decode", "b85decode", "b32decode"}
BAD_PATH = re.compile(r"^(?:/|~|[A-Za-z]:[\\/])|\.\.")

BTN_CALLS = {"InlineKeyboardButton", "KeyboardButton", "InlineKeyboardButtonCallback", "KeyboardButtonCallback",
             "KeyboardButtonUrl", "InlineButton"}

FRAMEWORKS = {"telebot": "pyTelegramBotAPI", "telegram": "python-telegram-bot", "aiogram": "aiogram",
              "pyrogram": "Pyrogram", "telethon": "Telethon", "discord": "discord.py", "telepot": "telepot",
              "flask": "Flask", "fastapi": "FastAPI", "django": "Django"}
CAP = {
    "sqlite3": "يخزّن بيانات في قاعدة SQLite", "aiosqlite": "يخزّن بيانات في قاعدة SQLite",
    "pymongo": "يتصل بقاعدة MongoDB", "motor": "يتصل بقاعدة MongoDB", "redis": "يتصل بـ Redis",
    "psycopg2": "يتصل بقاعدة PostgreSQL", "mysql": "يتصل بقاعدة MySQL",
    "requests": "يتصل بالإنترنت / APIs", "aiohttp": "يتصل بالإنترنت / APIs", "httpx": "يتصل بالإنترنت / APIs",
    "urllib3": "يتصل بالإنترنت / APIs",
    "bs4": "يسحب بيانات من صفحات الويب (Scraping)", "selenium": "يتحكم بمتصفح (Selenium)",
    "scrapy": "يسحب بيانات من المواقع",
    "yt_dlp": "يحمّل فيديوهات/صوتيات", "youtube_dl": "يحمّل فيديوهات/صوتيات", "pytube": "يحمّل فيديوهات من يوتيوب",
    "openai": "يستخدم الذكاء الاصطناعي (OpenAI)", "anthropic": "يستخدم الذكاء الاصطناعي (Claude)",
    "PIL": "يعالج الصور", "cv2": "يعالج الصور/الفيديو", "moviepy": "يعالج الفيديو", "pydub": "يعالج الصوت",
    "flask": "يشغّل سيرفر ويب", "fastapi": "يشغّل سيرفر ويب", "django": "يشغّل سيرفر ويب", "uvicorn": "يشغّل سيرفر ويب",
    "schedule": "فيه مهام مجدولة", "apscheduler": "فيه مهام مجدولة",
    "smtplib": "يرسل بريداً إلكترونياً", "gtts": "يحوّل النص لصوت", "pyttsx3": "يحوّل النص لصوت",
    "qrcode": "يصنع رموز QR", "pandas": "يحلل بيانات", "numpy": "عمليات حسابية/بيانات",
    "matplotlib": "يرسم رسوماً بيانية",
    "telethon": "يستخدم Telethon (قد يعمل بجلسة حساب شخصي Userbot)",
    "pyrogram": "يستخدم Pyrogram (قد يعمل بجلسة حساب شخصي Userbot)",
    "discord": "بوت ديسكورد", "cryptography": "تشفير", "Crypto": "تشفير", "Cryptodome": "تشفير",
    "psutil": "يقرأ معلومات السيرفر", "stripe": "مدفوعات", "threading": "يشغّل مهام متوازية",
    "multiprocessing": "يشغّل عمليات متوازية",
}
ACTIONS = {
    "send_message": "إرسال رسائل", "send_photo": "إرسال صور", "send_video": "إرسال فيديو",
    "send_document": "إرسال ملفات", "send_audio": "إرسال صوتيات", "send_voice": "إرسال رسائل صوتية",
    "send_sticker": "إرسال ملصقات", "send_poll": "إنشاء استطلاعات", "send_location": "إرسال مواقع",
    "forward_message": "توجيه رسائل", "copy_message": "نسخ رسائل", "get_chat_member": "فحص عضوية القنوات",
    "ban_chat_member": "حظر أعضاء", "kick_chat_member": "طرد أعضاء", "restrict_chat_member": "تقييد أعضاء",
    "delete_message": "حذف رسائل", "answer_inline_query": "وضع Inline", "send_invoice": "فواتير/مدفوعات",
    "get_file": "تنزيل ملفات المستخدمين", "edit_message_text": "تعديل رسائل",
    "answer_callback_query": "الرد على الأزرار",
}
SAFE_SCRIPT_HOSTS = ("cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "ajax.googleapis.com",
                     "fonts.googleapis.com", "code.jquery.com", "cdn.tailwindcss.com", "telegram.org",
                     "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com", "www.googletagmanager.com")

HTML_RULES = [
    (r"coinhive|coin-hive|cryptonight|webminer|miner\.start|coinimp|jsecoin", "critical",
     "تعدين عملات داخل المتصفح (Crypto Miner)"),
    (r"eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)|document\.write\s*\(\s*unescape|new\s+Function\s*\(\s*atob",
     "high", "كود جافاسكربت مشفّر/مخفي"),
    (r"api\.telegram\.org/bot\d", "high", "إرسال بيانات لبوت تيليجرام (أسلوب تسريب/فيشنج)"),
    (r"discord(?:app)?\.com/api/webhooks", "high", "إرسال بيانات عبر Discord Webhook"),
    (r"document\.cookie[\s\S]{0,200}(?:fetch|XMLHttpRequest|sendBeacon|\.src\s*=)|"
     r"(?:fetch|XMLHttpRequest|sendBeacon)[\s\S]{0,200}document\.cookie", "high", "سحب الكوكيز وإرسالها"),
    (r"<iframe[^>]+(?:width=['\"]?0|height=['\"]?0|display\s*:\s*none|visibility\s*:\s*hidden)", "high",
     "إطار iframe مخفي"),
    (r"getUserMedia|navigator\.mediaDevices", "medium", "طلب الكاميرا/المايك"),
    (r"navigator\.geolocation", "medium", "طلب الموقع الجغرافي"),
    (r"clipboard\.readText", "medium", "قراءة الحافظة"),
    (r"(?:window\.|document\.)?location(?:\.href)?\s*=\s*['\"]https?://", "medium", "تحويل تلقائي لموقع خارجي"),
    (r"<meta[^>]+http-equiv=['\"]?refresh", "medium", "تحويل تلقائي (meta refresh)"),
    (r"href=['\"][^'\"]+\.(?:exe|apk|scr|bat|msi|jar|vbs|ps1)(?:\?[^'\"]*)?['\"]", "medium",
     "روابط تنزيل ملفات تنفيذية"),
    (r"addEventListener\(\s*['\"]key(?:down|press|up)['\"]", "low", "التقاط ضغطات لوحة المفاتيح"),
    (r"new\s+WebSocket\s*\(", "low", "اتصال WebSocket"),
]
BRANDS = r"telegram|facebook|instagram|whatsapp|google|paypal|binance|tiktok|snapchat|twitter|microsoft|apple"


# ---------- أدوات الفاحص
def _e(x):
    return html.escape(str(x))


def _add(F, sev, title, line=None):
    d = F.setdefault(title, {"sev": sev, "lines": []})
    if line and line not in d["lines"] and len(d["lines"]) < 5:
        d["lines"].append(line)


def _lineno(src, pos):
    return src.count("\n", 0, pos) + 1


def _rescore(res):
    fs = sorted(res["findings"], key=lambda f: -W[f["sev"]])
    res["findings"] = fs
    score = min(100, sum(W[f["sev"]] for f in fs))
    if any(f["sev"] == "critical" for f in fs) or score >= 70:
        v = "dangerous"
    elif score >= 30:
        v = "suspicious"
    else:
        v = "safe"
    if res.get("syntax_error") and v != "dangerous":
        v = "invalid"
    res["score"], res["verdict"] = score, v


def _push(res, F):
    for t, d in F.items():
        res["findings"].append({"sev": d["sev"], "title": t, "lines": d["lines"]})


def _sv(n):
    if isinstance(n, ast.Constant) and isinstance(n.value, str):
        return n.value
    if isinstance(n, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{…}" for v in n.values)
    return None


def _strs(n):
    if n is None:
        return []
    s = _sv(n)
    if s is not None:
        return [s]
    if isinstance(n, (ast.List, ast.Tuple, ast.Set)):
        out = []
        for x in n.elts:
            out += _strs(x)
        return out
    return []


def _dotted(n):
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
        return ".".join(reversed(parts))
    return ""


def _domains(src, limit=15):
    out = []
    for u in re.findall(r"https?://[^\s'\"<>)\]\\]+", src):
        h = urlparse(u).netloc.lower()
        if h and h not in out:
            out.append(h)
        if len(out) >= limit:
            break
    return out


# ---------- فحص بايثون
def scan_py(src, res, host_secrets):
    F = {}
    info = res["info"]
    for pat, sev, title in TEXT_RULES:
        for m in re.finditer(pat, src, re.I):
            _add(F, sev, title, _lineno(src, m.start()))
    info["tokens"] = list(dict.fromkeys(TOKEN_RE.findall(src)))[:3]
    info["urls"] = _domains(src)

    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        res["syntax_error"] = f"سطر {e.lineno}: {e.msg}"
        _push(res, F)
        return
    except Exception as e:  # noqa
        res["syntax_error"] = str(e)[:100]
        _push(res, F)
        return

    aliases, imports, full_imports = {}, set(), set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                top = a.name.split(".")[0]
                imports.add(top)
                full_imports.add(a.name)
                aliases[a.asname or top] = a.name if a.asname else top
        elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
            top = n.module.split(".")[0]
            imports.add(top)
            for a in n.names:
                full_imports.add(f"{n.module}.{a.name}")
                aliases[a.asname or a.name] = f"{n.module}.{a.name}"

    def resolve(node):
        d = _dotted(node)
        if not d:
            return ""
        head, _, rest = d.partition(".")
        real = aliases.get(head, head)
        return real + ("." + rest if rest else "")

    for m in imports:
        if m in IMPORT_RULES:
            _add(F, *IMPORT_RULES[m], 1)
    for fi in full_imports:
        if fi in FULL_IMPORT_RULES:
            _add(F, *FULL_IMPORT_RULES[fi], 1)

    called, buttons, commands, actions = set(), [], [], set()
    uses_open, writes_file, handlers, funcs, classes = False, False, 0, 0, 0

    for n in ast.walk(tree):
        ln = getattr(n, "lineno", None)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs += 1
            if n.decorator_list:
                try:
                    dec = " ".join(ast.unparse(d) for d in n.decorator_list).lower()
                except Exception:
                    dec = "handler"
                if re.search(r"handler|message|callback|command|on_|router|dp\.|bot\.|filters", dec):
                    handlers += 1
        elif isinstance(n, ast.ClassDef):
            classes += 1
        elif isinstance(n, ast.Name) and n.id == "__builtins__":
            _add(F, "medium", "وصول مباشر لـ __builtins__ (أسلوب إخفاء)", ln)
        elif isinstance(n, ast.Attribute) and resolve(n) == "os.environ":
            _add(F, "low", "قراءة متغيرات البيئة", ln)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            if len(n.value) > 300 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", n.value):
                _add(F, "medium", "نص مشفّر Base64 طويل (قد يخفي كوداً)", ln)
        elif isinstance(n, ast.While) and isinstance(n.test, ast.Constant) and n.test.value is True:
            for c in ast.walk(n):
                if isinstance(c, ast.Call) and resolve(c.func) == "os.fork":
                    _add(F, "critical", "حلقة لا نهائية تنشئ عمليات (Fork bomb)", n.lineno)
                    break
        elif isinstance(n, ast.Dict):
            keys = {_sv(k): v for k, v in zip(n.keys, n.values) if k is not None and _sv(k)}
            if "text" in keys and (set(keys) & {"callback_data", "url", "web_app"}) and _sv(keys["text"]):
                cb_, url = _sv(keys.get("callback_data")), _sv(keys.get("url"))
                buttons.append((_sv(keys["text"]), "رابط" if url else "كولباك", url or cb_ or ""))
        elif isinstance(n, ast.Call):
            fn = resolve(n.func)
            last = fn.split(".")[-1] if fn else (n.func.attr if isinstance(n.func, ast.Attribute) else "")
            called.add(fn)
            if fn in CALL_RULES:
                _add(F, *CALL_RULES[fn], ln)
            elif fn.startswith("subprocess."):
                _add(F, "high", "تشغيل برامج خارجية (subprocess)", ln)
            elif fn.startswith("ctypes."):
                _add(F, "high", "استخدام ctypes (وصول مباشر للنظام/الذاكرة)", ln)
            if fn in ("eval", "exec", "builtins.eval", "builtins.exec"):
                arg = n.args[0] if n.args else None
                hidden = arg is not None and any(
                    isinstance(x, ast.Call) and resolve(x.func).split(".")[-1] in HIDE for x in ast.walk(arg))
                if hidden:
                    _add(F, "critical", "تنفيذ كود مخفي/مشفّر (exec/eval مع فك تشفير)", ln)
                elif isinstance(arg, ast.Constant):
                    _add(F, "low", "استخدام eval/exec على نص ثابت", ln)
                else:
                    _add(F, "high", "تنفيذ كود ديناميكي (eval/exec)", ln)
            if fn == "getattr" and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id == "__builtins__":
                _add(F, "high", "استدعاء دوال مخفية عبر getattr(__builtins__)", ln)
            if fn in FS_FUNCS and n.args:
                s = _sv(n.args[0])
                if s and BAD_PATH.search(s):
                    _add(F, "high", "وصول لمسارات خارج مجلد البوت", ln)
            if fn == "open":
                uses_open = True
                mode = _sv(n.args[1]) if len(n.args) > 1 else next(
                    (_sv(k.value) for k in n.keywords if k.arg == "mode"), None)
                if mode and re.search(r"[wax+]", mode):
                    writes_file = True
            if last in BTN_CALLS or (fn.startswith(("telethon.Button", "Button.")) and last in ("inline", "url", "text")):
                kw = {k.arg: k.value for k in n.keywords if k.arg}
                text = _sv(n.args[0]) if n.args else None
                if text is None:
                    text = _sv(kw.get("text"))
                if text is not None:
                    cb_ = _sv(kw.get("callback_data")) or _sv(kw.get("data"))
                    url = _sv(kw.get("url"))
                    if len(n.args) > 1 and not (cb_ or url):
                        v = _sv(n.args[1])
                        if v:
                            if v.startswith(("http", "tg://", "t.me")):
                                url = v
                            else:
                                cb_ = v
                    kind = "رابط" if url else ("كولباك" if cb_ else "نص")
                    buttons.append((text, kind, url or cb_ or ""))
            if last in ("ReplyKeyboardMarkup",) and n.args:
                for s in _strs(n.args[0]):
                    buttons.append((s, "نص", ""))
                if isinstance(n.args[0], ast.List):
                    for row in n.args[0].elts:
                        for s in _strs(row):
                            buttons.append((s, "نص", ""))
            if isinstance(n.func, ast.Attribute) and n.func.attr in ("add", "row") and n.args:
                recv = _dotted(n.func.value).lower()
                if re.search(r"markup|kb|keyboard", recv):
                    for a in n.args:
                        for s in _strs(a):
                            buttons.append((s, "نص", ""))
            if last in ("CommandHandler", "Command", "command"):
                for a in n.args:
                    commands += _strs(a)
            if last == "CommandStart":
                commands.append("start")
            for k in n.keywords:
                if k.arg == "commands":
                    commands += _strs(k.value)
            if last in ACTIONS:
                actions.add(ACTIONS[last])

    crypto = any(c.split(".")[-1] in ("Fernet", "AES", "new") and ("crypt" in c.lower() or "AES" in c) for c in called)
    walks = any(c in ("os.walk", "glob.glob", "glob.iglob", "os.listdir") for c in called)
    destroys = any(c in ("os.remove", "os.unlink", "os.rename", "os.replace", "shutil.move") for c in called)
    if crypto and walks and destroys:
        _add(F, "critical", "سلوك برنامج فدية (تشفير ملفات + حذف الأصل)", 1)
    if "socket.socket" in called and (
            {"os.dup2", "pty.spawn"} & called or any(c.startswith("subprocess.") or c == "os.system" for c in called)
            and re.search(r"\.connect\(", src)):
        _add(F, "critical", "شبهة شل عكسي (socket + تنفيذ أوامر)", 1)

    for s in host_secrets:
        if s and s in src:
            _add(F, "critical", "الملف يحتوي توكن/سر البوت الرئيسي للاستضافة", _lineno(src, src.index(s)))

    _push(res, F)

    third = sorted(m for m in imports if m not in STDLIB)
    info.update(
        functions=funcs, classes=classes, handlers=handlers,
        imports=sorted(imports), third_party=third,
        frameworks=sorted({FRAMEWORKS[m] for m in imports if m in FRAMEWORKS}),
        buttons=list(dict.fromkeys(buttons)),
        commands=list(dict.fromkeys(commands)),
        capabilities=[CAP[m] for m in sorted(imports) if m in CAP],
        actions=sorted(actions),
        file_io="يقرأ/يكتب ملفات" if writes_file else ("يقرأ ملفات" if uses_open else ""),
        doc=(ast.get_docstring(tree) or "")[:300],
    )
    if not info["doc"]:
        head = [l.strip("# ").strip() for l in src.splitlines()[:6] if l.strip().startswith("#") and "coding" not in l]
        info["doc"] = " | ".join(h for h in head if h)[:300]
``````python
# -*- coding: utf-8 -*-
# بوت رفع استضافة بيبو - الجزء الثالث

class _H(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self._t = "", False
        self.scripts, self.inline_scripts = [], 0
        self.links, self.forms, self.buttons, self.iframes = [], [], [], []
        self.inputs, self._btn, self._a = [], None, None
        self.text = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self._t = True
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self.inline_scripts += 1
        elif tag == "a":
            self._a = [a.get("href", "") or "", ""]
        elif tag == "button":
            self._btn = [""]
        elif tag == "form":
            self.forms.append({"action": a.get("action", "") or "", "method": (a.get("method") or "get").lower(),
                               "inputs": []})
        elif tag == "input":
            t = (a.get("type") or "text").lower()
            self.inputs.append(t)
            if self.forms:
                self.forms[-1]["inputs"].append(t)
            if t in ("button", "submit") and a.get("value"):
                self.buttons.append(a["value"])
        elif tag == "iframe":
            self.iframes.append(a.get("src", "") or "")

    def handle_endtag(self, tag):
        if tag == "title":
            self._t = False
        elif tag == "a" and self._a:
            self.links.append((self._a[1].strip(), self._a[0]))
            self._a = None
        elif tag == "button" and self._btn is not None:
            if self._btn[0].strip():
                self.buttons.append(self._btn[0].strip())
            self._btn = None

    def handle_data(self, d):
        if self._t:
            self.title += d
        if self._a:
            self._a[1] += d
        if self._btn is not None:
            self._btn[0] += d
        self.text.append(d)


def scan_html(src, res, host_secrets):
    F = {}
    for pat, sev, title in HTML_RULES:
        for m in re.finditer(pat, src, re.I):
            _add(F, sev, title, _lineno(src, m.start()))
    for pat, sev, title in TEXT_RULES[:5] + TEXT_RULES[6:7]:
        for m in re.finditer(pat, src, re.I):
            _add(F, sev, title, _lineno(src, m.start()))
    p = _H()
    try:
        p.feed(src)
    except Exception:
        pass
    ext_scripts = []
    for s in p.scripts:
        h = urlparse(s).netloc.lower()
        if h and not h.endswith(SAFE_SCRIPT_HOSTS):
            ext_scripts.append(h)
    if ext_scripts:
        _add(F, "low", "سكربتات من نطاقات غير معروفة: " + ", ".join(sorted(set(ext_scripts))[:3]), 1)
    has_pw = "password" in p.inputs
    if has_pw:
        _add(F, "medium", "الصفحة تحتوي حقل كلمة مرور", 1)
        for f in p.forms:
            if "password" in f["inputs"] and re.match(r"https?://", f["action"] or ""):
                _add(F, "high", "نموذج كلمة مرور يرسل البيانات لموقع خارجي (فيشنج)", 1)
        if re.search(BRANDS, (p.title + " " + " ".join(p.text[:200])), re.I):
            _add(F, "high", "صفحة تسجيل دخول تنتحل اسم خدمة معروفة", 1)
    for s in host_secrets:
        if s and s in src:
            _add(F, "critical", "الملف يحتوي توكن/سر البوت الرئيسي للاستضافة", 1)
    _push(res, F)
    res["info"].update(
        title=p.title.strip()[:100], scripts=sorted(set(urlparse(s).netloc or "(محلي)" for s in p.scripts)),
        inline_scripts=p.inline_scripts, buttons=[(b, "زر", "") for b in dict.fromkeys(p.buttons)],
        links=[(t[:40], h[:80]) for t, h in p.links if h][:30],
        forms=p.forms[:10], iframes=[i for i in p.iframes if i][:10], urls=_domains(src), tokens=[],
    )


def _scan_req_text(text):
    F, pk = {}, []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("-"):
            if not re.match(r"(?:-r|--requirement|-c|--constraint)\b", s):
                _add(F, "high", "خيار pip مشبوه داخل requirements (مثل --index-url أو -e)", n)
        elif "://" in s or s.startswith("git+"):
            _add(F, "high", "تثبيت حزمة من رابط خارجي", n)
        else:
            pk.append(re.split(r"[=<>!~\[; ]", s)[0])
    return F, pk


def merge_requirements(res, data):
    text = data.decode("utf-8", "replace")
    F, pk = _scan_req_text(text)
    _push(res, F)
    res["info"]["requirements"] = pk[:40]
    _rescore(res)


def scan(data, filename="file", host_secrets=(), req_data=None):
    low = (filename or "file").lower()
    res = {"filename": filename, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
           "findings": [], "info": {}, "syntax_error": None, "score": 0, "verdict": "safe"}
    src = data.decode("utf-8-sig", "replace")
    res["lines"] = src.count("\n") + 1
    head = src[:3000].lower()

    if data[:2] == b"MZ" or data[:4] == b"\x7fELF":
        kind = "bin"
        _push(res, {"ملف تنفيذي (exe/elf) وليس نصاً": {"sev": "critical", "lines": []}})
    elif data[:2] == b"PK":
        kind = "bin"
        _push(res, {"ملف مضغوط (zip) غير مدعوم": {"sev": "medium", "lines": []}})
    elif low.endswith(".py"):
        kind = "py"
    elif low.endswith((".html", ".htm")):
        kind = "html"
    elif low.endswith(".txt"):
        kind = "req"
    elif "<html" in head or "<!doctype html" in head:
        kind = "html"
    else:
        try:
            ast.parse(src)
            kind = "py"
        except Exception:
            kind = "unknown"
    res["kind"] = kind

    if kind == "py":
        scan_py(src, res, host_secrets)
    elif kind == "html":
        scan_html(src, res, host_secrets)
    elif kind == "req":
        F, pk = _scan_req_text(src)
        _push(res, F)
        res["info"]["requirements"] = pk[:60]
    elif kind == "unknown":
        F = {}
        for pat, sev, title in TEXT_RULES:
            for m in re.finditer(pat, src, re.I):
                _add(F, sev, title, _lineno(src, m.start()))
        _push(res, F)
    if req_data:
        merge_requirements(res, req_data)
    _rescore(res)
    return res


def risk_bar(score):
    n = min(10, (score + 9) // 10)
    return "▰" * n + "▱" * (10 - n)


def badge(res):
    return (f"<b>━━ ◉ الحكم: {VERDICT_AR[res['verdict']]} ◉ ━━</b>\n"
            f"<b>{risk_bar(res['score'])}  ({res['score']}/100)</b>")


def _fline(f, with_lines=True):
    t = f"• [{SEV_AR[f['sev']]}] {_e(f['title'][:80])}"
    if with_lines and f["lines"]:
        t += " — سطر " + ", ".join(str(x) for x in f["lines"][:4])
    return t


def short_summary(res, n=4, budget=480):
    out, used = [badge(res)], 0
    if res.get("syntax_error"):
        out.append(f"<b>خطأ برمجي:</b> {_e(res['syntax_error'][:60])}")
    for f in res["findings"][:n]:
        t = _fline(f, False)
        if used + len(t) > budget:
            break
        out.append(t)
        used += len(t) + 1
    if not res["findings"]:
        out.append("لا توجد ملاحظات خطيرة")
    elif len(res["findings"]) > n:
        out.append(f"<i>+ {len(res['findings']) - n} بنود أخرى في التقرير الكامل</i>")
    return "\n".join(out)


def _clip(lines, limit=2800):
    out, used = [], 0
    for l in lines:
        if used + len(l) > limit:
            out.append(f"<i>... و{len(lines) - len(out)} أخرى</i>")
            break
        out.append(l)
        used += len(l) + 1
    return "\n".join(out)


KIND_AR = {"py": "بوت بايثون (.py)", "html": "صفحة موقع (HTML)", "req": "ملف مكتبات (requirements)",
           "bin": "ملف ثنائي", "unknown": "غير معروف"}


def full_report(res, token_info=None):
    info = res["info"]
    sec = []
    size = res["size"]
    sz = f"{size / 1024:.1f} KB" if size >= 1024 else f"{size} B"
    sec.append("<b>🔍 تقرير فحص الملف</b>\n\n"
               f"<b>الملف:</b> <code>{_e(res['filename'])}</code>\n"
               f"<b>النوع:</b> {KIND_AR.get(res['kind'], '-')}\n"
               f"<b>الحجم:</b> {sz}  |  <b>الأسطر:</b> {res['lines']}\n"
               f"<b>SHA256:</b> <code>{res['sha256'][:24]}…</code>")
    sec.append(badge(res) + f"\n<b>التوصية:</b> {ADVICE[res['verdict']]}")
    if res.get("syntax_error"):
        sec.append(f"<b>❌ خطأ برمجي:</b> {_e(res['syntax_error'])}")

    if res["findings"]:
        sec.append("<b>⚠️ ما وجده الفحص:</b>\n" + _clip([_fline(f) for f in res["findings"]]))
    else:
        sec.append("<b>✅ لا توجد أي ملاحظات.</b>")

    if res["kind"] == "py":
        desc = []
        if info.get("doc"):
            desc.append(f"<i>{_e(info['doc'])}</i>")
        if info.get("frameworks"):
            desc.append("<b>المكتبة الأساسية:</b> " + _e("، ".join(info["frameworks"])))
        caps = info.get("capabilities", []) + ([info["file_io"]] if info.get("file_io") else [])
        if caps:
            desc.append("<b>القدرات:</b>\n" + "\n".join("• " + _e(c) for c in caps))
        if info.get("actions"):
            desc.append("<b>إجراءات تيليجرام:</b> " + _e("، ".join(info["actions"])))
        desc.append(f"<b>الدوال:</b> {info.get('functions', 0)}  |  <b>الهاندلرز:</b> {info.get('handlers', 0)}"
                    f"  |  <b>الكلاسات:</b> {info.get('classes', 0)}")
        sec.append("<b>🤖 ماذا يفعل البوت؟</b>\n" + "\n".join(desc))
        if info.get("third_party"):
            sec.append("<b>📦 المكتبات الخارجية:</b>\n<code>" + _e(", ".join(info["third_party"])) + "</code>")
        if info.get("commands"):
            sec.append("<b>⌨️ الأوامر:</b>\n" + _clip(["• /" + _e(c.lstrip("/")) for c in info["commands"]], 1200))
    elif res["kind"] == "html":
        d = []
        if info.get("title"):
            d.append(f"<b>العنوان:</b> {_e(info['title'])}")
        d.append(f"<b>سكربتات داخلية:</b> {info.get('inline_scripts', 0)}  |  "
                 f"<b>خارجية:</b> {_e('، '.join(info.get('scripts', [])) or 'لا يوجد')}")
        if info.get("forms"):
            d.append("<b>النماذج:</b>\n" + "\n".join(
                f"• {f['method'].upper()} → {_e(f['action'] or '(نفس الصفحة)')} | حقول: {_e(', '.join(f['inputs']) or '-')}"
                for f in info["forms"]))
        if info.get("iframes"):
            d.append("<b>iframes:</b> " + _e("، ".join(info["iframes"])))
        sec.append("<b>🌐 ماذا تفعل الصفحة؟</b>\n" + "\n".join(d))
        if info.get("links"):
            sec.append("<b>🔗 الروابط:</b>\n" + _clip([f"• {_e(t or '-')} ← {_e(h)}" for t, h in info["links"]], 1500))
    elif res["kind"] == "req" or info.get("requirements"):
        sec.append("<b>📦 المكتبات المطلوبة:</b>\n<code>" + _e(", ".join(info.get("requirements", [])) or "-") + "</code>")

    if info.get("buttons"):
        lines = []
        for t, k, v in info["buttons"]:
            lines.append(f"• <b>{_e(t)}</b>" + (f" ← {k}: <code>{_e(v[:50])}</code>" if v else f" ({k})"))
        sec.append(f"<b>🔘 الأزرار ({len(info['buttons'])}):</b>\n" + _clip(lines, 2600))
    if info.get("urls"):
        sec.append("<b>🌍 النطاقات التي يتصل بها:</b>\n" + _clip([f"• <code>{_e(u)}</code>" for u in info["urls"]], 1200))
    if info.get("tokens"):
        masked = [f"<code>{_e(t[:10])}…{_e(t[-4:])}</code>" for t in info["tokens"]]
        sec.append("<b>🔑 توكنات داخل الملف:</b>\n" + "\n".join("• " + m for m in masked)
                   + ("\n" + "\n".join("• " + _e(x) if "<" not in x else "• " + x for x in token_info) if token_info else ""))
    sec.append("<i>ملاحظة: الفحص ثابت (لا يشغّل الملف) ولا يضمن اكتشاف كل أنواع الإخفاء، فلا تعتمد عليه وحده.</i>")
    return "\n\n".join(sec)
``````python
# -*- coding: utf-8 -*-
# بوت رفع استضافة بيبو - الجزء الرابع والأخير

db = sqlite3.connect("bot.db", check_same_thread=False)
db.executescript("""
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, points INTEGER DEFAULT 0, invited_by INTEGER,
    banned INTEGER DEFAULT 0, joined INTEGER DEFAULT 0, name TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS channels (username TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS uploads (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, kind TEXT,
    file_id TEXT, file_name TEXT, status TEXT DEFAULT 'pending', created INTEGER, run INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS btn_edits (key TEXT PRIMARY KEY, style TEXT, emoji_id TEXT);
CREATE TABLE IF NOT EXISTS text_edits (key TEXT PRIMARY KEY, emoji_id TEXT);
""")
for _tbl, _col, _ddl in (("users", "banned", "INTEGER DEFAULT 0"),
                         ("users", "joined", "INTEGER DEFAULT 0"),
                         ("users", "name", "TEXT DEFAULT ''"),
                         ("users", "warns", "INTEGER DEFAULT 0"),
                         ("uploads", "run", "INTEGER DEFAULT 0"),
                         ("uploads", "req_id", "TEXT")):
    try:
        db.execute(f"ALTER TABLE {_tbl} ADD COLUMN {_col} {_ddl}")
    except sqlite3.OperationalError:
        pass
db.commit()

REQS = {}
STATE = {}
EDIT = {}


def one(sql, args=()):
    return db.execute(sql, args).fetchone()


def rows(sql, args=()):
    return db.execute(sql, args).fetchall()


def get_setting(k):
    r = one("SELECT value FROM settings WHERE key=?", (k,))
    return r[0] if r else DEFAULTS[k]


def set_setting(k, v):
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, str(v)))
    db.commit()


def geti(k):
    return int(get_setting(k))


def is_admin(uid):
    return uid == OWNER_ID or bool(one("SELECT 1 FROM admins WHERE id=?", (uid,)))


def get_points(uid):
    r = one("SELECT points FROM users WHERE id=?", (uid,))
    return r[0] if r else 0


def register(uid, name, inviter=None):
    if one("SELECT 1 FROM users WHERE id=?", (uid,)):
        db.execute("UPDATE users SET name=? WHERE id=?", (name, uid))
        db.commit()
        return False
    valid = inviter if inviter and inviter != uid and one(
        "SELECT 1 FROM users WHERE id=?", (inviter,)) else None
    db.execute("INSERT INTO users (id, points, invited_by, joined, name) VALUES (?, 0, ?, ?, ?)",
               (uid, valid, int(time.time()), name))
    if valid:
        db.execute("UPDATE users SET points = points + ? WHERE id=?", (geti("reward"), valid))
    db.commit()
    return valid


def nqta(n):
    return "نقطتان" if n == 2 else ("نقطة" if n == 1 else f"{n} نقاط")


def strip_icons(markup):
    m = copy.deepcopy(markup)
    for row in m.get("inline_keyboard", []):
        for b in row:
            b.pop("icon_custom_emoji_id", None)
    return m


TGEMOJI_RE = re.compile(r'<tg-emoji emoji-id="\d+">(.*?)</tg-emoji>', re.S)
EMOJI_ANY = re.compile(
    r"[\U0001F000-\U0001FAFF\u2600-\u27BF\u231A\u231B\u23E9-\u23F3\u23F8-\u23FA"
    r"\u25AA\u25AB\u25B6\u25C0\u25FB-\u25FE\u2139\u203C\u2049\uFE0F\u200D\u20E3]+ ?")
LABEL_FALLBACK = {"✅": "قبول", "❌": "رفض"}


def strip_all_emoji(text):
    parts = re.split(r'(<tg-emoji emoji-id="\d+">.*?</tg-emoji>)', text, flags=re.S)
    out = "".join(p if p.startswith("<tg-emoji") else EMOJI_ANY.sub("", p) for p in parts)
    return re.sub(r" +(?=\n|</)", "", out)


def clean_label(t):
    s = strip_all_emoji(t).strip()
    return s or LABEL_FALLBACK.get(t.strip(), t)


TEXT_LEAD = re.compile(
    r"^[\s•\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF\u2190-\u21FF\u2300-\u23FF\u25A0-\u25FF\uFE0F\u200D]+")


def apply_text_edits(text):
    if not text:
        return text
    for key, eid in db.execute("SELECT key, emoji_id FROM text_edits").fetchall():
        lead = TEXT_LEAD.match(key)
        body = key[lead.end():] if lead else key
        fb = ((lead.group(0).replace("•", "").strip()) if lead else "") or "⭐"
        tag = f'<tg-emoji emoji-id="{eid}">{fb}</tg-emoji> '
        pat = re.compile(r"(?m)^((?:<(?:b|i|u|s)>)*)" + re.escape(key))
        text = pat.sub(lambda m: m.group(1) + tag + body, text)
    return text


def call(method, **params):
    params = {k: v for k, v in params.items() if v is not None}
    if method == "answerCallbackQuery" and isinstance(params.get("text"), str):
        t = strip_all_emoji(params["text"]).strip()
        if t:
            params["text"] = t
        else:
            params.pop("text")
    if params.get("parse_mode") == "HTML":
        for f in ("text", "caption"):
            if isinstance(params.get(f), str):
                params[f] = strip_all_emoji(apply_text_edits(params[f]))
    data = {"ok": False}
    for attempt in range(2):
        try:
            data = requests.post(f"{API}/{method}", json=params, timeout=60).json()
        except Exception as e:
            print("request error:", method, e)
            return {"ok": False}
        if data.get("ok"):
            return data
        print("API error:", method, data)
        if attempt == 0:
            changed = False
            rm = params.get("reply_markup")
            if rm and "icon_custom_emoji_id" in json.dumps(rm):
                params["reply_markup"] = strip_icons(rm)
                changed = True
            for f in ("text", "caption"):
                if isinstance(params.get(f), str) and "<tg-emoji" in params[f]:
                    params[f] = TGEMOJI_RE.sub("", params[f])
                    changed = True
            if changed:
                continue
        break
    return data


EMOJI_EDGE = re.compile(
    r"^[\s\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF\u2190-\u21FF\u2300-\u23FF\u25A0-\u25FF\uFE0F\u200D]+"
    r"|[\s\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF\u2190-\u21FF\u2300-\u23FF\u25A0-\u25FF\uFE0F\u200D]+$")


def strip_emoji(t):
    s = EMOJI_EDGE.sub("", t).strip()
    return s or t


def norm(t):
    return re.sub(r"\s+", " ", strip_emoji(t)).strip().casefold()


def get_edit(key):
    return one("SELECT style, emoji_id FROM btn_edits WHERE key=?", (key,))


def save_edit(key, style=None, emoji_id=None):
    if style is not None:
        db.execute("INSERT INTO btn_edits (key, style) VALUES (?, ?) "
                   "ON CONFLICT(key) DO UPDATE SET style=excluded.style", (key, style))
    if emoji_id is not None:
        db.execute("INSERT INTO btn_edits (key, emoji_id) VALUES (?, ?) "
                   "ON CONFLICT(key) DO UPDATE SET emoji_id=excluded.emoji_id", (key, emoji_id))
    db.commit()


def btn(text, style=None, data=None, url=None, web_app=None, key=None):
    b = {"text": clean_label(text)}
    ov = get_edit(key or text)
    if ov:
        if ov[0]:
            style = ov[0]
        if ov[1]:
            b["icon_custom_emoji_id"] = ov[1]
    if web_app:
        b["web_app"] = {"url": web_app}
    elif url:
        b["url"] = url
    else:
        b["callback_data"] = data
    if style:
        b["style"] = style
    return b


def preview():
    return {"is_disabled": False, "url": MENU_PHOTO,
            "show_above_text": True, "prefer_large_media": True}


def ans(cb, text=None, alert=False):
    call("answerCallbackQuery", callback_query_id=cb["id"], text=text, show_alert=alert or None)


def edit_to(cb, text, keyboard=None):
    m = cb["message"]
    call("editMessageText", chat_id=m["chat"]["id"], message_id=m["message_id"], text=text,
         parse_mode="HTML", reply_markup=keyboard, link_preview_options=preview())


def say(chat_id, text, keyboard=None):
    call("sendMessage", chat_id=chat_id, text=text, parse_mode="HTML",
         reply_markup=keyboard, link_preview_options={"is_disabled": True})


def send_long(chat_id, text, limit=3800):
    parts, cur = [], ""
    for p in text.split("\n\n"):
        if cur and len(cur) + len(p) + 2 > limit:
            parts.append(cur)
            cur = p
        else:
            cur = (cur + "\n\n" + p) if cur else p
    if cur:
        parts.append(cur)
    for x in parts:
        say(chat_id, x)


LINE = "<b>━━━━━━━━━━━━━━━━━━━</b>"


def norm_link(t):
    t = t.strip()
    if t.startswith("@"):
        return "https://t.me/" + t[1:]
    if t.startswith("http"):
        return t
    return "https://t.me/" + t


PROCS = {}
GEN = {}

PIP_NAMES = {
    "telebot": "pyTelegramBotAPI", "telegram": "python-telegram-bot", "bs4": "beautifulsoup4",
    "cv2": "opencv-python", "PIL": "pillow", "yaml": "pyyaml", "dotenv": "python-dotenv",
    "Crypto": "pycryptodome", "sklearn": "scikit-learn", "dateutil": "python-dateutil",
    "serial": "pyserial", "discord": "discord.py", "googletrans": "googletrans==4.0.0rc1",
    "youtube_dl": "youtube-dl", "yt_dlp": "yt-dlp", "pymongo": "pymongo", "jwt": "pyjwt",
}


def bot_dir(i):
    return os.path.join(BOTS_DIR, str(i))


def site_dir(i):
    return os.path.join(SITES_DIR, str(i))


_PUBIP = None


def public_base():
    global _PUBIP
    b = get_setting("base_url").rstrip("/")
    if "YOUR_SERVER_IP" not in b:
        return b
    if not _PUBIP:
        try:
            _PUBIP = requests.get("https://api.ipify.org", timeout=10).text.strip()
        except Exception:
            pass
    return f"http://{_PUBIP}:{SITE_PORT}" if _PUBIP else b


def site_url(i):
    return f"{public_base()}/s/{i}/"


def report_start(i, owner, p, gen, off=0):
    time.sleep(10)
    if GEN.get(i) == gen and PROCS.get(i) is p and p.poll() is None:
        try:
            with open(os.path.join(bot_dir(i), "bot.log"), "rb") as f:
                f.seek(off)
                tail = f.read().decode("utf-8", "replace")
        except Exception:
            tail = ""
        if re.search(r"Conflict|terminated by other|Unauthorized|Traceback|Error|error", tail):
            msg = (f"<b>🟡 بوتك #{i} شغال لكن فيه أخطاء في السجل:</b>\n"
                   f"<pre>{html.escape(tail[-900:])}</pre>")
            say(owner, msg)
            if owner != OWNER_ID:
                say(OWNER_ID, msg)
        else:
            say(owner, f"<b>🟢 بوتك #{i} شغال الآن ✅</b>")


def preflight(i, owner):
    try:
        with open(os.path.join(bot_dir(i), "main.py"), "r", encoding="utf-8", errors="replace") as f:
            code = f.read()
        toks = list(dict.fromkeys(TOKEN_RE.findall(code)))[:2]
        for t in toks:
            api = f"https://api.telegram.org/bot{t}"
            r = requests.get(f"{api}/getMe", timeout=15).json()
            if not r.get("ok"):
                say(owner, f"<b>❌ توكن البوت #{i} غير صالح ({html.escape(str(r.get('description')))}) — "
                           f"<code>{t[:12]}...</code>\nلن يعمل حتى يُستبدل التوكن.</b>")
                continue
            info = requests.get(f"{api}/getWebhookInfo", timeout=15).json().get("result", {})
            if info.get("url"):
                requests.get(f"{api}/deleteWebhook", timeout=15)
                say(owner, "<b>🔧 تم حذف webhook قديم كان يمنع عمل البوت.</b>")
            say(owner, f"<b>🔑 التوكن صالح — @{html.escape(r['result'].get('username', ''))}</b>")
    except Exception as e:
        print("preflight error:", e)


def kill_stale(folder):
    pf = os.path.join(folder, "bot.pid")
    try:
        pid = int(open(pf).read().strip())
    except Exception:
        return
    try:
        cmd = open(f"/proc/{pid}/cmdline", "rb").read()
        if b"main.py" not in cmd:
            return
    except FileNotFoundError:
        if os.path.exists("/proc"):
            return
    except Exception:
        pass
    for sig in (signal.SIGTERM, getattr(signal, "SIGKILL", signal.SIGTERM)):
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(pid), sig)
            else:
                os.kill(pid, sig)
        except Exception:
            break
        time.sleep(1.5)


def stop_all():
    for i in list(PROCS):
        GEN[i] = GEN.get(i, 0) + 1
        kill_proc(PROCS.pop(i, None))


def report_crash(i, owner, code):
    tail = read_log(i, 1500)
    msg = (f"<b>❌ البوت #{i} توقف (كود {code}). آخر السجل:</b>\n"
           f"<pre>{html.escape(tail[-1500:] or 'فارغ')}</pre>")
    say(owner, msg)
    if owner != OWNER_ID:
        say(OWNER_ID, msg)


def fetch_file(file_id):
    r = call("getFile", file_id=file_id)
    if not r.get("ok"):
        return None
    try:
        resp = requests.get(f"{FILE_API}/{r['result']['file_path']}", timeout=60)
        return resp.content if resp.status_code == 200 else None
    except Exception as e:
        print("download error:", e)
        return None


LAST_PIP_ERR = ""


def pip_install(pkg, req=False):
    global LAST_PIP_ERR
    target = ["-r", pkg] if req else [pkg]
    for extra in ([], ["--break-system-packages"]):
        try:
            r = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", *target, *extra],
                               capture_output=True, timeout=900)
            if r.returncode == 0:
                return True
            LAST_PIP_ERR = (r.stderr or r.stdout or b"").decode("utf-8", "replace")[-600:]
        except Exception as e:
            LAST_PIP_ERR = str(e)
            print("pip error:", pkg, e)
    return False


def install_deps(path, notify=None):
    folder = os.path.dirname(path)
    req_path = os.path.join(folder, "requirements.txt")
    if os.path.exists(req_path) and not os.path.exists(os.path.join(folder, ".req_done")):
        if notify:
            notify("<b>📦 جاري تثبيت المكتبات من requirements.txt ...</b>")
        if pip_install(req_path, req=True):
            open(os.path.join(folder, ".req_done"), "w").close()
        elif notify:
            notify(f"<b>⚠️ فشل تثبيت requirements.txt:</b>\n<pre>{html.escape(LAST_PIP_ERR)}</pre>")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            tree = ast.parse(f.read())
    except Exception:
        return
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods.add(node.module.split(".")[0])
    missing = []
    for m in sorted(mods):
        try:
            if importlib.util.find_spec(m) is not None:
                continue
        except Exception:
            pass
        missing.append(m)
    if not missing:
        return
    if notify:
        notify("<b>📦 تم إنشاء requirements.txt تلقائياً، جاري تثبيت: " + html.escape(", ".join(missing)) + "</b>")
    names = [PIP_NAMES.get(m, m) for m in missing]
    gen_path = os.path.join(folder, "requirements.auto.txt")
    with open(gen_path, "w", encoding="utf-8") as f:
        f.write("\n".join(names) + "\n")
    if not os.path.exists(req_path):
        try:
            with open(req_path, "w", encoding="utf-8") as f:
                f.write("\n".join(names) + "\n")
        except Exception:
            pass
    if pip_install(gen_path, req=True):
        return
    for m in missing:
        if not pip_install(PIP_NAMES.get(m, m)) and notify:
            notify(f"<b>⚠️ فشل تثبيت المكتبة {html.escape(m)}:</b>\n<pre>{html.escape(LAST_PIP_ERR)}</pre>")


def missing_module(folder):
    try:
        with open(os.path.join(folder, "bot.log"), "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 4000))
            tail = f.read().decode("utf-8", "replace")
    except Exception:
        return None
    m = re.findall(r"No module named '([\w\.]+)'", tail)
    return m[-1].split(".")[0] if m else None


def kill_proc(p):
    if p is None or p.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        else:
            p.terminate()
        p.wait(timeout=5)
    except Exception:
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            else:
                p.kill()
        except Exception:
            pass


def is_running(i):
    p = PROCS.get(i)
    return bool(p and p.poll() is None)


def supervise(i, owner, gen):
    try:
        _supervise(i, owner, gen)
    except Exception:
        tb = traceback.format_exc()
        print(tb)
        for t in {owner, OWNER_ID}:
            say(t, f"<b>❌ خطأ داخلي أثناء تشغيل البوت #{i}:</b>\n<pre>{html.escape(tb[-1500:])}</pre>")


def _supervise(i, owner, gen):
    folder = bot_dir(i)
    script = os.path.join(folder, "main.py")
    fails = 0
    say(owner, f"<b>⏳ جاري تشغيل بوتك #{i}...</b>")
    threading.Thread(target=preflight, args=(i, owner), daemon=True).start()
    while GEN.get(i) == gen:
        install_deps(script, lambda t: say(owner, t))
        if GEN.get(i) != gen:
            return
        kill_stale(folder)
        logpath = os.path.join(folder, "bot.log")
        off = os.path.getsize(logpath) if os.path.exists(logpath) else 0
        logf = open(logpath, "ab")
        started = time.time()
        try:
            env = dict(os.environ, PYTHONUNBUFFERED="1")
            p = subprocess.Popen([sys.executable, "-u", "main.py"], cwd=folder, stdout=logf,
                                 stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env,
                                 start_new_session=(os.name == "posix"))
        except Exception as e:
            logf.close()
            print("spawn error:", e)
            say(owner, f"<b>❌ تعذر تشغيل البوت #{i}.</b>")
            return
        PROCS[i] = p
        try:
            with open(os.path.join(folder, "bot.pid"), "w") as pf:
                pf.write(str(p.pid))
        except Exception:
            pass
        threading.Thread(target=report_start, args=(i, owner, p, gen, off), daemon=True).start()
        code = p.wait()
        logf.close()
        if GEN.get(i) != gen or PROCS.get(i) is not p:
            return
        if code == 0:
            PROCS.pop(i, None)
            say(owner, f"<b>ℹ️ انتهى تشغيل البوت #{i} من تلقاء نفسه.</b>")
            return
        fails = 0 if time.time() - started > 60 else fails + 1
        if fails == 1:
            report_crash(i, owner, code)
        mod = missing_module(folder)
        if mod and fails <= 3:
            pip_install(PIP_NAMES.get(mod, mod))
        if fails >= 5:
            PROCS.pop(i, None)
            say(owner, f"<b>⚠️ البوت #{i} يتوقف باستمرار بسبب خطأ في الكود، تم إيقافه.</b>\n"
                       "<b>افتح بوتاتي ← السجل لمعرفة السبب.</b>")
            return
        time.sleep(3 * max(fails, 1))


def start_bot(i, owner):
    if is_running(i):
        return
    if not os.path.exists(os.path.join(bot_dir(i), "main.py")):
        return
    GEN[i] = GEN.get(i, 0) + 1
    db.execute("UPDATE uploads SET run=1 WHERE id=?", (i,))
    db.commit()
    threading.Thread(target=supervise, args=(i, owner, GEN[i]), daemon=True).start()


def stop_bot(i):
    GEN[i] = GEN.get(i, 0) + 1
    p = PROCS.pop(i, None)
    kill_proc(p)
    db.execute("UPDATE uploads SET run=0 WHERE id=?", (i,))
    db.commit()


def restart_bot(i, owner):
    stop_bot(i)
    time.sleep(1)
    start_bot(i, owner)


def read_log(i, limit=3300):
    try:
        with open(os.path.join(bot_dir(i), "bot.log"), "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - limit))
            return f.read().decode("utf-8", "replace")
    except Exception:
        return ""


def diag():
    L = ["<b>🩺 فحص السيرفر</b>\n"]
    L.append(f"<b>Python:</b> {html.escape(sys.version.split()[0])} — <code>{html.escape(sys.executable)}</code>")
    L.append(f"<b>النظام:</b> {html.escape(sys.platform)}")
    try:
        r = subprocess.run([sys.executable, "-c", "print('ok')"], capture_output=True, timeout=20)
        good = r.stdout.strip() == b"ok"
        L.append("<b>تشغيل برامج جانبية:</b> " + (
            "✅" if good else f"❌ {html.escape(r.stderr.decode('utf-8', 'replace')[-200:])}"))
    except Exception as e:
        L.append(f"<b>تشغيل برامج جانبية:</b> ❌ {html.escape(str(e))}")
    try:
        r = subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True, timeout=30)
        L.append("<b>pip:</b> " + ("✅ " + html.escape(r.stdout.decode().split(" from")[0]) if r.returncode == 0
                                   else "❌ غير موجود: " + html.escape(r.stderr.decode('utf-8', 'replace')[-200:])))
    except Exception as e:
        L.append(f"<b>pip:</b> ❌ {html.escape(str(e))}")
    try:
        resp = requests.get("https://pypi.org/simple/pip/", timeout=15)
        L.append(f"<b>الاتصال بـ PyPI (تثبيت المكتبات):</b> "
                 f"{'✅' if resp.status_code == 200 else '❌ ' + str(resp.status_code)}")
    except Exception as e:
        L.append(f"<b>الاتصال بـ PyPI (تثبيت المكتبات):</b> ❌ {html.escape(str(e)[:150])}")
    try:
        test = os.path.join(BOTS_DIR, ".w")
        open(test, "w").write("x")
        os.remove(test)
        L.append("<b>الكتابة في مجلد الاستضافة:</b> ✅")
    except Exception as e:
        L.append(f"<b>الكتابة في مجلد الاستضافة:</b> ❌ {html.escape(str(e))}")
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{SITE_PORT}/s/0/", timeout=5)
    except urllib.error.HTTPError:
        L.append(f"<b>سيرفر المواقع (منفذ {SITE_PORT}):</b> ✅ يعمل")
    except Exception as e:
        L.append(f"<b>سيرفر المواقع (منفذ {SITE_PORT}):</b> ❌ {html.escape(str(e)[:100])}")
    L.append(f"<b>رابط المواقع:</b> {html.escape(public_base())}")
    running = [i for i in list(PROCS) if is_running(i)]
    L.append(f"<b>بوتات تعمل الآن:</b> {len(running)}")
    return "\n".join(L)


def restore_hosted():
    for i, owner in rows("SELECT id, user_id FROM uploads WHERE kind='bot' AND status='approved' AND run=1"):
        start_bot(i, owner)


class SiteHandler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        path = urllib.parse.unquote(path.split("?", 1)[0].split("#", 1)[0])
        parts = [p for p in path.split("/") if p and p not in (".", "..")]
        if len(parts) < 2 or parts[0] != "s" or not parts[1].isdigit():
            return os.path.join(SITES_DIR, "__none__")
        rest = [p for p in parts[2:] if "\\" not in p] or ["index.html"]
        return os.path.join(SITES_DIR, parts[1], *rest)

    def list_directory(self, path):
        self.send_error(404)
        return None

    def log_message(self, *a):
        pass


def start_site_server():
    try:
        srv = ThreadingHTTPServer(("0.0.0.0", SITE_PORT), SiteHandler)
    except OSError as e:
        print("site server error:", e)
        return
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"Site server on port {SITE_PORT}")


def check_token(t):
    try:
        r = requests.get(f"https://api.telegram.org/bot{t}/getMe", timeout=15).json()
    except Exception as e:
        return None, str(e)[:100]
    if not r.get("ok"):
        return None, str(r.get("description", "توكن غير صالح"))
    return r["result"], None


def bot_info_text(t):
    res, err = check_token(t)
    masked = f"<code>{html.escape(t[:10])}…{html.escape(t[-4:])}</code>"
    if not res:
        return f"<b>❌ توكن غير صالح</b> {masked}\n<b>السبب: {html.escape(err or '-')}</b>"
    yn = lambda v: "نعم" if v else "لا"
    return ("<b>🔎 نتيجة فحص البوت</b>\n\n"
            f"{LINE}\n"
            f"<b>🤖 الاسم: {html.escape(res.get('first_name', '-'))}</b>\n"
            f"<b>🔗 اليوزر: @{html.escape(res.get('username', '-'))}</b>\n"
            f"<b>🆔 الايدي: <code>{res.get('id')}</code></b>\n"
            f"{LINE}\n"
            f"<b>الانضمام للمجموعات: {yn(res.get('can_join_groups'))}</b>\n"
            f"<b>وضع Inline: {yn(res.get('supports_inline_queries'))}</b>\n"
            f"<b>🔑 التوكن: {masked}</b>")


def menu_text(points, name):
    name = html.escape(name)
    return (
        f"<b>✨أهلاً بـك في بوت ࢪفع استضافـه بيبو {name}!</b>\n\n"
        f"{LINE}\n"
        f"<b>✨نقــاطك: {points} نقطة</b>\n\n"
        "<b>✨نـظام النـقاط:</b>\n"
        f"<b>✨كل رفع ملف يكلف {geti('cost_bot')} نقـاط</b>\n"
        f"<b>✨كل دعوة تمـنحك {geti('reward')} نقـطة</b>\n\n"
        f"{LINE}\n"
        "<b>✨اخـتـار من القائمـة 👇🏻</b>"
    )


def menu_keyboard(uid):
    rows_ = [
        [btn("رفع بـوت", "success", "upload_bot")],
        [btn("بوتـاتي", "primary", "my_bots")],
        [btn("رفع موقع", "success", "upload_site"),
         btn("مـواقعي المرفوعه", "primary", "my_sites")],
        [btn("نقـاطي", "primary", "points"),
         btn("رابـط الدعوة", "primary", "invite")],
        [btn("⦿ 𝙆𝙸𝙽𝙶 ⦿", "primary", web_app=get_setting("king_url"))],
        [btn("المطـور", "danger", url=get_setting("dev_url")),
         btn("قـناة المطـور", "danger", url=get_setting("channel_url"))],
    ]
    if is_admin(uid):
        rows_.append([btn("🎛 لوحة التحكم", "primary", "admin")])
    return {"inline_keyboard": rows_}


def back_keyboard():
    return {"inline_keyboard": [[btn("رجـوع 👋", "primary", "back")]]}


def send_menu(chat_id, uid, name):
    call("sendMessage", chat_id=chat_id, text=menu_text(get_points(uid), name), parse_mode="HTML",
         reply_markup=menu_keyboard(uid), link_preview_options=preview())


def upload_text():
    return (
        "<b>✨أرسل ملف بـوت بلغه(.py) فقـط</b>\n\n"
        "<b>✨ملاحظات:</b>\n"
        "• سيتم خصم النقاط بعد الموافقة\n"
        "• يجب موافقـة الإدارة أولاً\n"
        "• بعد الموافقة يتم تشغيل بوتك تلقائياً\n"
        "• المكتبات تُثبَّت تلقائياً (اختيارياً ارفع requirements.txt قبل الملف)\n"
        "• تأكد من أن بـوتك يعمل"
    )


def unsubscribed(uid):
    missing = []
    for (ch,) in rows("SELECT username FROM channels"):
        r = call("getChatMember", chat_id=ch, user_id=uid)
        if r.get("ok") and r["result"].get("status") in ("left", "kicked"):
            missing.append(ch)
    return missing


def gate(uid):
    if is_admin(uid):
        return None
    r = one("SELECT banned FROM users WHERE id=?", (uid,))
    if r and r[0]:
        return ("<b>🚫 أنت محظور من استخدام البوت.</b>", None)
    if get_setting("maintenance") == "1":
        return ("<b>🛠 البوت تحت الصيانة حالياً، حاول مرة أخرى لاحقاً.</b>", None)
    missing = unsubscribed(uid)
    if missing:
        kb = [[btn(f"📢 {c}", "primary", url="https://t.me/" + c.lstrip("@"), key=f"ch:{c}")] for c in missing]
        kb.append([btn("✅ تحقق من الاشتراك", "success", "check_sub")])
        return ("<b>📢 يجب الاشتراك في القنوات التالية أولاً لاستخدام البوت ثم اضغط تحقق.</b>",
                {"inline_keyboard": kb})
    return None


def back_panel():
    return {"inline_keyboard": [[btn("رجـوع 👋", "primary", "admin")]]}


def done_panel():
    return {"inline_keyboard": [[btn("🎛 لوحة التحكم", "primary", "admin")]]}


def panel_text(name):
    return (
        f"<b>👑 أهلاً بك يا {html.escape(name)} في لوحة التحكم</b>\n\n"
        "<b>من هنا تتحكم في البوت بالكامل: المستخدمين، الرصيد، الاشتراك الإجباري، "
        "الصيانة، الطلبات، والأسعار.</b>\n\n"
        f"{LINE}\n"
        "<b>✨ اختر القسم الذي تريده 👇🏻</b>"
    )


def panel_keyboard():
    maint = get_setting("maintenance") == "1"
    return {"inline_keyboard": [
        [btn("📊 إحصائيات البوت", "primary", "a_stats"),
         btn("💰 قسم الرصيد", "primary", "a_balance")],
        [btn("📢 الاشتراك الإجباري", "primary", "a_channels"),
         btn("🚫 قسم الحظر", "primary", "a_ban")],
        [btn("👮 قسم الأدمن", "primary", "a_admins"),
         btn("🛠 الصيانة: " + ("مفعّلة 🔴" if maint else "متوقفة 🟢"),
             "danger" if maint else "success", "a_maint", key="🛠 الصيانة")],
        [btn("📂 الملفات المرفوعة", "primary", "a_files"),
         btn("⏳ الطلبات غير المكتملة", "primary", "a_pending")],
        [btn("📨 إذاعة", "primary", "a_bc"),
         btn("👤 معلومات مستخدم", "primary", "a_user")],
        [btn("⚙️ تغيير الروابط", "primary", "a_links"),
         btn("💲 الأسعار", "primary", "a_prices")],
        [btn("🛡 وضع القبول: " + ("تلقائي" if get_setting("auto_mode") == "1" else "يدوي"),
             "success" if get_setting("auto_mode") == "1" else "primary", "a_mode", key="🛡 وضع القبول")],
        [btn("🔎 فحص بوت", "success", "a_chk"),
         btn("✏️ قسم التعديل", "primary", "a_edit")],
        [btn("رجـوع 👋", "primary", "back")],
    ]}


PROMPTS = {
    "a_bal_add": ("bal_add", "أرسل ايدي المستخدم ثم عدد النقاط\nمثال: 123456789 10"),
    "a_bal_sub": ("bal_sub", "أرسل ايدي المستخدم ثم عدد النقاط المراد خصمها\nمثال: 123456789 5"),
    "a_bal_all": ("bal_all", "أرسل عدد النقاط التي تريد إضافتها لكل المستخدمين"),
    "a_ch_add": ("ch_add", "أرسل يوزر القناة مثل @channel\n(يجب أن يكون البوت أدمن فيها)"),
    "a_ch_del": ("ch_del", "أرسل يوزر القناة المراد حذفها"),
    "a_ban_add": ("ban", "أرسل ايدي المستخدم المراد حظره"),
    "a_ban_del": ("unban", "أرسل ايدي المستخدم المراد فك حظره"),
    "a_adm_add": ("adm_add", "أرسل ايدي الشخص المراد إضافته كأدمن"),
    "a_adm_del": ("adm_del", "أرسل ايدي الأدمن المراد حذفه"),
    "a_bc": ("bc", "أرسل الرسالة التي تريد إذاعتها لكل المستخدمين (نص أو صورة أو أي شيء)"),
    "a_user": ("user_info", "أرسل ايدي المستخدم"),
    "a_set_dev": ("set_dev", "أرسل يوزر المطور الجديد مثل @username"),
    "a_set_channel": ("set_channel", "أرسل يوزر قناة المطور الجديد مثل @channel"),
    "a_set_king": ("set_king", "أرسل رابط صفحة KING الجديد (يبدأ بـ https://)"),
    "a_set_base": ("set_base", "أرسل رابط السيرفر العام الذي تُعرض عليه المواقع\n"
                               "مثال: http://123.45.67.89:8080 أو https://sites.mydomain.com"),
    "a_cost_bot": ("cost_bot", "أرسل تكلفة رفع بوت (رقم)"),
    "a_cost_site": ("cost_site", "أرسل تكلفة رفع موقع (رقم)"),
    "a_reward": ("reward", "أرسل عدد نقاط الدعوة (رقم)"),
    "a_warn_reset": ("warn_reset", "أرسل ايدي المستخدم لتصفير تحذيراته (وفك حظره إن كان محظوراً)"),
    "a_maxwarn": ("max_warns", "أرسل عدد التحذيرات قبل الحظر النهائي (رقم، 1 أو أكثر)"),
    "a_chk": ("bot_check", "أرسل توكن البوت (أو ملف .py فيه التوكن) وسأعرض لك اسم البوت ويوزره وايديه"),
}
OWNER_ONLY = {"a_adm_add", "a_adm_del", "a_admins"}


def stats_text():
    now = int(time.time())
    n = lambda sql, a=(): one(sql, a)[0]
    return (
        "<b>📊 إحصائيات البوت</b>\n\n"
        f"{LINE}\n"
        f"<b>👥 المستخدمين: {n('SELECT COUNT(*) FROM users')}</b>\n"
        f"<b>🆕 جدد آخر 24 ساعة: {n('SELECT COUNT(*) FROM users WHERE joined>=?', (now - 86400,))}</b>\n"
        f"<b>🚫 المحظورين: {n('SELECT COUNT(*) FROM users WHERE banned=1')}</b>\n"
        f"<b>💰 مجموع النقاط: {n('SELECT COALESCE(SUM(points),0) FROM users')}</b>\n\n"
        f"{LINE}\n"
        f"<b>⏳ طلبات معلقة: {n('SELECT COUNT(*) FROM uploads WHERE status=?', ('pending',))}</b>\n"
        f"<b>✅ مقبولة: {n('SELECT COUNT(*) FROM uploads WHERE status=?', ('approved',))}</b>\n"
        f"<b>❌ مرفوضة: {n('SELECT COUNT(*) FROM uploads WHERE status=?', ('rejected',))}</b>\n"
        f"<b>🟢 بوتات تعمل الآن: {sum(1 for i in list(PROCS) if is_running(i))}</b>\n\n"
        f"{LINE}\n"
        f"<b>📢 قنوات الاشتراك: {n('SELECT COUNT(*) FROM channels')}</b>\n"
        f"<b>👮 الأدمن: {n('SELECT COUNT(*) FROM admins') + 1}</b>\n"
        f"<b>🛠 الصيانة: {'مفعّلة' if get_setting('maintenance') == '1' else 'متوقفة'}</b>\n"
        f"<b>🛡 وضع القبول: {'تلقائي' if get_setting('auto_mode') == '1' else 'يدوي'}</b>"
    )


def pending_view():
    items = rows("SELECT id, kind, file_name FROM uploads WHERE status='pending' ORDER BY id LIMIT 8")
    if not items:
        return "<b>✨ لا توجد طلبات معلقة.</b>", back_panel()
    kb = []
    for i, kind, fname in items:
        kb.append([btn(f"📄 #{i} {'بوت' if kind == 'bot' else 'موقع'}", "primary", f"gf:{i}", key="📄 ملف"),
                   btn("تقرير", "primary", f"sc:{i}", key="🔍 تقرير كامل"),
                   btn("✅", "success", f"ap:{i}"), btn("❌", "danger", f"rj:{i}")])
    kb.append([btn("رجـوع 👋", "primary", "admin")])
    total = one("SELECT COUNT(*) FROM uploads WHERE status='pending'")[0]
    return (f"<b>⏳ الطلبات غير المكتملة ({total})</b>\n\n"
            "<b>اضغط على الملف لاستلامه ثم قبول أو رفض 👇🏻</b>"), {"inline_keyboard": kb}


def files_view():
    items = rows("SELECT id, kind, file_name FROM uploads WHERE status='approved' ORDER BY id DESC LIMIT 10")
    if not items:
        return "<b>✨ لا توجد ملفات مرفوعة بعد.</b>", back_panel()
    kb = []
    for i, k, f in items:
        row = [btn(f"📄 #{i} • {'بوت' if k == 'bot' else 'موقع'} • {(f or '')[:18]}", "primary", f"gf:{i}",
                   key="📄 ملف")]
        if k == "bot":
            row.append(btn(("يعمل" if is_running(i) else "متوقف") + " - إدارة", "primary", f"mb:{i}",
                           key="إدارة البوت"))
        kb.append(row)
    kb.append([btn("رجـوع 👋", "primary", "admin")])
    return "<b>📂 آخر الملفات المرفوعة (المقبولة)</b>\n\n<b>اضغط على أي ملف لاستلامه 👇🏻</b>", \
           {"inline_keyboard": kb}


def bot_view(i, uid):
    r = one("SELECT file_name, user_id FROM uploads WHERE id=?", (i,))
    running = is_running(i)
    text = (f"<b>🤖 البوت #{i}</b>\n\n"
            f"<b>الملف: {html.escape(r[0] or '-')}</b>\n"
            f"<b>الحالة: {'🟢 يعمل' if running else '🔴 متوقف'}</b>")
    back = "my_bots" if r[1] == uid else "a_files"
    kb = {"inline_keyboard": [
        [btn("▶️ تشغيل", "success", f"bs:{i}"), btn("⏹ إيقاف", "danger", f"bx:{i}")],
        [btn("🔄 إعادة تشغيل", "primary", f"br:{i}"), btn("📜 السجل", "primary", f"bl:{i}")],
        [btn("رجـوع 👋", "primary", back)]]}
    return text, kb


def scan_upload(file_id, fname, req_id=None):
    try:
        data = fetch_file(file_id)
        if data is None:
            return None
        rdata = fetch_file(req_id) if req_id else None
        return scan(data, fname or "file", [TOKEN], rdata)
    except Exception:
        traceback.print_exc()
        return None


def notify_admins_upload(upload_id, uid, name, kind, fname, file_id, res=None, note=None, buttons=True):
    caption = (f"<b>📥 طلب جديد #{upload_id}</b>\n"
               f"<b>النوع: {'بوت (.py)' if kind == 'bot' else 'موقع (html)'}</b>\n"
               f"<b>المستخدم: {html.escape(name)} (<code>{uid}</code>)</b>\n"
               f"<b>الملف: {html.escape(fname)}</b>")
    if note:
        caption += f"\n<b>{note}</b>"
    if res:
        full = caption + "\n\n" + short_summary(res, 3, 300)
        caption = full if len(full) <= 1000 else caption + "\n\n" + badge(res)
    rows_kb = [[btn("🔍 تقرير كامل", "primary", f"sc:{upload_id}")]]
    if buttons:
        rows_kb.insert(0, [btn("✅ قبول", "success", f"ap:{upload_id}"),
                           btn("❌ رفض", "danger", f"rj:{upload_id}")])
    kb = {"inline_keyboard": rows_kb}
    ids = {OWNER_ID} | {a for (a,) in rows("SELECT id FROM admins")}
    for aid in ids:
        call("sendDocument", chat_id=aid, document=file_id, caption=caption,
             parse_mode="HTML", reply_markup=kb)


def notify_new_user(uid, name, username, inviter):
    total = one("SELECT COUNT(*) FROM users")[0]
    uname = f"@{html.escape(username)}" if username else "لا يوجد"
    inv = f"<code>{inviter}</code>" if inviter else "دخل مباشرة"
    text = ("<b>🆕 مستخدم جديد دخل البوت</b>\n\n"
            f"{LINE}\n"
            f"<b>👤 الاسم: {html.escape(name)}</b>\n"
            f"<b>🔗 اليوزر: {uname}</b>\n"
            f"<b>🆔 الايدي: <code>{uid}</code></b>\n"
            f"<b>📩 الدعوة: {inv}</b>\n"
            f"{LINE}\n"
            f"<b>👥 إجمالي المستخدمين: {total}</b>")
    ids = {OWNER_ID} | {a for (a,) in rows("SELECT id FROM admins")}
    for aid in ids:
        if aid != uid:
            say(aid, text)


def do_approve(upload_id):
    r = one("SELECT user_id, kind, status, file_id, file_name, req_id FROM uploads WHERE id=?", (upload_id,))
    if not r or r[2] != "pending":
        return False, "⚠️ هذا الطلب تمت معالجته مسبقاً", True
    user_id, kind, _, file_id, fname, req_id = r
    cost = geti("cost_bot") if kind == "bot" else geti("cost_site")
    if get_points(user_id) < cost:
        return False, f"❌ رصيد المستخدم غير كافٍ (المطلوب {cost})", True
    data = fetch_file(file_id)
    if data is None:
        return False, "❌ تعذر تنزيل الملف من تيليجرام، حاول مرة أخرى", True
    if kind == "bot":
        try:
            compile(data, fname or "main.py", "exec")
        except (SyntaxError, ValueError) as e:
            return False, f"❌ الملف فيه خطأ برمجي (سطر {getattr(e, 'lineno', '?')}) ولن يعمل. ارفضه.", True
        folder, target = bot_dir(upload_id), "main.py"
    else:
        folder, target = site_dir(upload_id), "index.html"
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, target), "wb") as f:
        f.write(data)
    if kind == "bot" and req_id:
        rdata = fetch_file(req_id)
        if rdata:
            with open(os.path.join(folder, "requirements.txt"), "wb") as f:
                f.write(rdata)
    db.execute("UPDATE users SET points = points - ? WHERE id=?", (cost, user_id))
    db.execute("UPDATE uploads SET status='approved' WHERE id=?", (upload_id,))
    db.commit()
    if kind == "bot":
        start_bot(upload_id, user_id)
        say(user_id, f"<b>✅ تمت الموافقة على طلبك #{upload_id} وتم خصم {cost} نقاط من رصيدك.</b>\n"
                     "<b>🚀 تم تشغيل بوتك الآن، تحكم فيه من «بوتـاتي».</b>")
        return True, "✅ تمت الموافقة وتم تشغيل البوت", False
    say(user_id, f"<b>✅ تمت الموافقة على طلبك #{upload_id} وتم خصم {cost} نقاط من رصيدك.</b>\n"
                 f"<b>🌐 موقعك شغال الآن على:</b>\n{html.escape(site_url(upload_id))}")
    warn = "\n⚠️ اضبط رابط الاستضافة من تغيير الروابط" if "YOUR_SERVER_IP" in site_url(upload_id) else ""
    return True, "✅ تمت الموافقة وتم نشر الموقع" + warn, bool(warn)


def do_reject(upload_id, user_msg=None):
    r = one("SELECT user_id FROM uploads WHERE id=?", (upload_id,))
    if not r:
        return
    db.execute("UPDATE uploads SET status='rejected' WHERE id=?", (upload_id,))
    db.commit()
    say(r[0], f"<b>{user_msg}</b>" if user_msg
        else f"<b>❌ تم رفض طلبك #{upload_id} من الإدارة، لم يتم خصم أي نقاط.</b>")


def process_upload(cb, upload_id, approve):
    if approve:
        ok_, text, alert = do_approve(upload_id)
        ans(cb, text, alert)
        return ok_
    r = one("SELECT status FROM uploads WHERE id=?", (upload_id,))
    if not r or r[0] != "pending":
        ans(cb, "⚠️ هذا الطلب تمت معالجته مسبقاً", True)
        return False
    do_reject(upload_id)
    ans(cb, "❌ تم الرفض")
    return True


def add_warn(uid):
    db.execute("UPDATE users SET warns = warns + 1 WHERE id=?", (uid,))
    db.commit()
    w = one("SELECT warns FROM users WHERE id=?", (uid,))[0]
    lim = geti("max_warns")
    banned = w >= lim
    if banned:
        db.execute("UPDATE users SET banned=1 WHERE id=?", (uid,))
        db.commit()
    return w, lim, banned


def auto_review(upload_id, uid, name, kind, fname, file_id, res):
    def admins_note(note, buttons=False):
        notify_admins_upload(upload_id, uid, name, kind, fname, file_id, res, note=note, buttons=buttons)

    if res is None:
        say(uid, "<b>⏳ تعذر الفحص التلقائي، طلبك تحت مراجعة الإدارة.</b>")
        admins_note("⚠️ تعذر الفحص التلقائي، راجعه يدوياً", True)
        return
    v = res["verdict"]
    if v == "safe":
        ok_, text, _ = do_approve(upload_id)
        if ok_:
            admins_note("✅ قُبل تلقائياً (الفحص: آمن)")
        else:
            do_reject(upload_id, f"❌ تعذر قبول طلبك #{upload_id}: {text}")
            admins_note(f"❌ فشل القبول التلقائي: {text}")
    elif v == "dangerous":
        if is_admin(uid):
            do_reject(upload_id, f"🚫 تم رفض طلبك #{upload_id} تلقائياً لأن الملف خطير.")
            admins_note("🚫 رُفض تلقائياً (خطير) — صاحبه أدمن فلم يُحذَّر")
        else:
            w, lim, banned = add_warn(uid)
            tail = ("🔒 وصلت للحد الأقصى من التحذيرات وتم حظرك نهائياً من البوت."
                    if banned else f"⚠️ عند وصولك إلى {lim} تحذيرات سيتم حظرك نهائياً من البوت.")
            do_reject(upload_id, f"🚫 تم رفض طلبك #{upload_id} تلقائياً لأن الملف يحتوي سلوكاً خطيراً.\n"
                                 f"⚠️ تحذير {w}/{lim}\n{tail}")
            admins_note(f"🚫 رُفض تلقائياً (خطير) — تحذير {w}/{lim}" + (" — تم حظر المستخدم" if banned else ""))
    elif v == "invalid":
        do_reject(upload_id, f"❌ تم رفض طلبك #{upload_id} لأن الملف فيه خطأ برمجي ولن يعمل.\n"
                             "لا يوجد تحذير على هذا الرفض، صحّح الملف وأعد رفعه.")
        admins_note("❌ رُفض تلقائياً (خطأ برمجي) بدون تحذير")
    else:
        say(uid, f"<b>⏳ طلبك #{upload_id} يحتاج مراجعة يدوية من الإدارة، انتظر القرار.</b>")
        admins_note("⚠️ الفحص: مشبوه — يحتاج مراجعتك (قبول/رفض)", True)


def mode_view():
    auto = get_setting("auto_mode") == "1"
    lim = geti("max_warns")
    warned = rows("SELECT id, name, warns FROM users WHERE warns>0 ORDER BY warns DESC LIMIT 10")
    lst = "\n".join(f"<b>• {html.escape(n or '-')} (<code>{i}</code>) — {w}/{lim}</b>"
                    for i, n, w in warned) or "<b>لا يوجد محذَّرون.</b>"
    text = ("<b>🛡 وضع القبول</b>\n\n"
            f"{LINE}\n"
            f"<b>الوضع الحالي: {'🤖 تلقائي' if auto else '👤 يدوي'}</b>\n\n"
            "<b>🤖 تلقائي: البوت يفحص كل ملف؛ الآمن يُقبل ويُشغَّل فوراً، الخطير يُرفض مع تحذير للمستخدم "
            f"(بعد {lim} تحذيرات يُحظر نهائياً)، والمشبوه يصلك للمراجعة.</b>\n\n"
            "<b>👤 يدوي: كل الطلبات تصلك مع نتيجة الفحص وأنت تقبل أو ترفض.</b>\n\n"
            f"{LINE}\n<b>⚠️ آخر المحذَّرين:</b>\n{lst}")
    kb = {"inline_keyboard": [
        [btn("◉ تلقائي" if auto else "🤖 تلقائي", "success" if auto else "primary", "a_mode_auto", key="🤖 تلقائي"),
         btn("◉ يدوي" if not auto else "👤 يدوي", "success" if not auto else "primary", "a_mode_manual",
             key="👤 يدوي")],
        [btn("♻️ تصفير تحذيرات مستخدم", "primary", "a_warn_reset")],
        [btn("⚠️ حد التحذيرات", "primary", "a_maxwarn")],
        [btn("رجـوع 👋", "primary", "admin")]]}
    return text, kb


_EDITABLE_RAW = [
    "رفع بـوت", "بوتـاتي", "رفع موقع", "مـواقعي المرفوعه", "نقـاطي", "رابـط الدعوة",
    "⦿ 𝙆𝙸𝙽𝙶 ⦿", "المطـور", "قـناة المطـور", "🎛 لوحة التحكم", "رجـوع 👋",
    "مشاركة رابط دعوة", "✅ تحقق من الاشتراك",
    "📊 إحصائيات البوت", "💰 قسم الرصيد", "📢 الاشتراك الإجباري", "🚫 قسم الحظر", "👮 قسم الأدمن",
    "🛠 الصيانة", "📂 الملفات المرفوعة", "⏳ الطلبات غير المكتملة", "📨 إذاعة", "👤 معلومات مستخدم",
    "⚙️ تغيير الروابط", "💲 الأسعار", "✏️ قسم التعديل", "🔎 فحص بوت",
    "🛡 وضع القبول", "🤖 تلقائي", "👤 يدوي", "♻️ تصفير تحذيرات مستخدم", "⚠️ حد التحذيرات",
    "➖ خصم رصيد", "➕ إضافة رصيد", "🎁 إضافة نقاط للجميع", "🗑 حذف قناة", "➕ إضافة قناة",
    "✅ فك حظر", "🚫 حظر مستخدم", "🗑 حذف أدمن", "➕ إضافة أدمن",
    "📢 قناة المطور", "👨‍💻 يوزر المطور", "👑 رابط KING", "🌐 رابط الاستضافة",
    "🌐 تكلفة موقع", "🤖 تكلفة بوت", "🎁 مكافأة الدعوة",
    "📄 ملف", "✅", "❌", "✅ قبول", "❌ رفض", "🔍 تقرير كامل",
    "▶️ تشغيل", "⏹ إيقاف", "🔄 إعادة تشغيل", "📜 السجل", "إدارة البوت",
]
EDITABLE = list(dict.fromkeys(_EDITABLE_RAW))
EDIT_PAGE = 10


def find_key(text):
    n = norm(text)
    for k in EDITABLE:
        if k == text or norm(k) == n:
            return k
    return None


def edit_list_view(page):
    total = max(1, (len(EDITABLE) + EDIT_PAGE - 1) // EDIT_PAGE)
    page = max(0, min(page, total - 1))
    chunk = EDITABLE[page * EDIT_PAGE:(page + 1) * EDIT_PAGE]
    lst = "\n".join(f"<code>{html.escape(x)}</code>" for x in chunk)
    text = (f"<b>✏️ قسم التعديل</b>\n\n"
            f"<b>الأزرار — صفحة {page + 1}/{total}:</b>\n\n{lst}\n\n{LINE}\n"
            "<b>✨ انسخ اسم الزر وأرسله لي 👇🏻</b>\n<b>(للإلغاء أرسل /cancel)</b>")
    nav = []
    if page > 0:
        nav.append(btn("◀️ السابق", "primary", f"ed_pg:{page - 1}", key="ed_nav_prev"))
    if page < total - 1:
        nav.append(btn("التالي ▶️", "primary", f"ed_pg:{page + 1}", key="ed_nav_next"))
    kb = [nav] if nav else []
    kb.append([btn("🔄 إعادة ضبط كل التعديلات", "danger", "ed_reset", key="ed_reset_all")])
    kb.append([btn("رجـوع 👋", "primary", "a_edit")])
    return text, {"inline_keyboard": kb}


def color_view(key):
    kb = {"inline_keyboard": [
        [btn("🟢 أخضر", "success", "ed_c:success", key="ed_c_green"),
         btn("🔴 أحمر", "danger", "ed_c:danger", key="ed_c_red"),
         btn("🔵 أزرق", "primary", "ed_c:primary", key="ed_c_blue")],
        [btn("تخطي ⏭", None, "ed_skipc", key="ed_skip_c")]]}
    return f"<b>🎨 اختر لون الزر:</b>\n\n<b>{html.escape(key)}</b>", kb


def preview_row(key):
    return [btn(key, None, "ed_noop")]


def emoji_view(key, head):
    kb = {"inline_keyboard": [
        preview_row(key),
        [btn("تخطي ⏭", None, "ed_skipe", key="ed_skip_e")]]}
    return (f"<b>{head}</b>\n\n<b>✨ حابب تضيف إيموجي مميز؟ أرسله الآن</b>\n"
            "<b>(سيتم حذف الإيموجي العادي من الزر تلقائياً)</b>"), kb


def done_view(key, head):
    kb = {"inline_keyboard": [
        preview_row(key),
        [btn("✏️ تعديل زر آخر", "primary", "a_edit", key="ed_another")],
        [btn("🎛 لوحة التحكم", "primary", "admin")]]}
    return f"<b>{head}</b>\n\n<b>هذا شكل الزر الآن 👆</b>", kb


TEXTS = [
    "✨أهلاً بـك في بوت ࢪفع استضافـه بيبو", "✨نقــاطك:", "✨نـظام النـقاط:", "✨كل رفع ملف يكلف",
    "✨كل دعوة تمـنحك", "✨اخـتـار من القائمـة 👇🏻",
    "✨أرسل ملف بـوت بلغه(.py) فقـط", "✨ملاحظات:", "• سيتم خصم النقاط بعد الموافقة",
    "• يجب موافقـة الإدارة أولاً", "• بعد الموافقة يتم تشغيل بوتك تلقائياً", "• تأكد من أن بـوتك يعمل",
    "✨أرسـل مـلـف بـ لغة html فقـط", "✨ نقاطك غير كافية!", "✨ نقاطك الحالية:", "✨ المطلوب:",
    "✨ كيف تحصل على نقاط؟", "✨ ليـس لديـك نقاط الكافيه لـرفـع موقـع، لـ رفع موقع لازم ان يكون لديك",
    "✅ تم إرسال طلبك #", "❌ ملف غير مدعوم، أرسل", "❌ حجم الملف كبير جداً (الحد الأقصى 5MB).",
    "❌ نقاطك غير كافية، المطلوب",
    "✨ لم ترفع أي بوت بعد.", "✨ اضغط على \"رفع بوت\" للبـدء عزيزي", "✨ بوتاتك المرفوعة:",
    "اضغط على بوت للتحكم به 👇🏻", "✨ ليـس لديك مواقع مرفوعه عزيزي.", "✨ مواقعك المرفوعة:",
    "🤖 البوت #", "📜 سجل البوت #", "📜 السجل فارغ (لا توجد مخرجات بعد).",
    "✨نقاطك", "✨الرصيد الحالي:", "✨عدد دعواتك:", "✨سجل النقاط:", "• كل رفع: -", "• كل دعوة: +",
    "✨شارك رابـط دعوتك حب لڪسب نقاط", "✨شارك رابط الدعوة مع أصدقائك",
    "✨كل شخص يدخل من رابطك ستحصل على", "✨رابط الدعوة الخاص بك:", "✨ستحصل على",
    "✨تم إضافة", "✨شخص جديد انضم عبر رابط دعوتك...",
    "✅ تمت الموافقة على طلبك #", "🚀 تم تشغيل بوتك الآن، تحكم فيه من «بوتـاتي».",
    "🌐 موقعك شغال الآن على:", "❌ تم رفض طلبك #", "🟢 بوتك #", "❌ البوت #", "⚠️ البوت #",
    "افتح بوتاتي ← السجل لمعرفة السبب.", "ℹ️ انتهى تشغيل البوت #", "❌ تعذر تشغيل البوت #",
    "🚫 أنت محظور من استخدام البوت.", "🛠 البوت تحت الصيانة حالياً، حاول مرة أخرى لاحقاً.",
    "📢 يجب الاشتراك في القنوات التالية أولاً لاستخدام البوت ثم اضغط تحقق.", "✅ تم الإلغاء.",
    "🎁 تم إضافة", "➖ تم خصم", "📨 جاري الإذاعة لـ",
    "👑 أهلاً بك يا", "من هنا تتحكم في البوت بالكامل", "✨ اختر القسم الذي تريده 👇🏻",
    "✨ أرسل", "📊 إحصائيات البوت", "👥 المستخدمين:", "🆕 جدد آخر 24 ساعة:", "🚫 المحظورين:",
    "💰 مجموع النقاط:", "⏳ طلبات معلقة:", "✅ مقبولة:", "❌ مرفوضة:", "🟢 بوتات تعمل الآن:",
    "📢 قنوات الاشتراك:", "👮 الأدمن:", "🛠 الصيانة:",
    "💰 قسم الرصيد", "تحكم في نقاط المستخدمين من هنا 👇🏻", "📢 قنوات الاشتراك الإجباري",
    "ملاحظة: يجب أن يكون البوت أدمن في القناة.", "🚫 قسم الحظر", "👮 قسم الأدمن",
    "⚙️ تغيير الروابط", "💲 الأسعار والمكافآت", "👤 معلومات المستخدم",
    "📥 طلب جديد #", "⏳ الطلبات غير المكتملة", "اضغط على الملف لاستلامه ثم قبول أو رفض 👇🏻",
    "✨ لا توجد طلبات معلقة.", "📂 آخر الملفات المرفوعة (المقبولة)", "اضغط على أي ملف لاستلامه 👇🏻",
    "✨ لا توجد ملفات مرفوعة بعد.", "🆕 مستخدم جديد دخل البوت", "🔎 نتيجة فحص البوت",
    "✏️ قسم التعديل", "✨ انسخ اسم الزر وأرسله لي 👇🏻", "🎨 اختر لون الزر:",
    "✨ حابب تضيف إيموجي مميز؟ أرسله الآن", "هذا شكل الزر الآن 👆", "✅ تم تلوين الزر",
    "⏭ تم تخطي اللون", "✅ تم حفظ التعديلات", "✅ تم إضافة الإيموجي المميز",
]
TEXTS = list(dict.fromkeys(TEXTS))


def find_text_key(text):
    n = norm(text)
    for k in TEXTS:
        if k == text or norm(k) == n:
            return k
    return None


def edit_menu_view():
    kb = {"inline_keyboard": [
        [btn("🔘 تعديل الأزرار", "primary", "ed_m:btn", key="ed_menu_btn"),
         btn("📝 تعديل النصوص", "primary", "ed_m:txt", key="ed_menu_txt")],
        [btn("رجـوع 👋", "primary", "admin")]]}
    return "<b>✏️ قسم التعديل</b>\n\n<b>اختر ما تريد تعديله 👇🏻</b>", kb


def text_list_view(page):
    total = max(1, (len(TEXTS) + EDIT_PAGE - 1) // EDIT_PAGE)
    page = max(0, min(page, total - 1))
    chunk = TEXTS[page * EDIT_PAGE:(page + 1) * EDIT_PAGE]
    lst = "\n".join(f"<code>{html.escape(x)}</code>" for x in chunk)
    text = (f"<b>📝 نصوص البوت — صفحة {page + 1}/{total}:</b>\n\n{lst}\n\n{LINE}\n"
            "<b>✨ انسخ النص كما هو وأرسله لي لإضافة إيموجي مميز عليه 👇🏻</b>\n"
            "<b>(للإلغاء أرسل /cancel)</b>")
    nav = []
    if page > 0:
        nav.append(btn("◀️ السابق", "primary", f"ed_tp:{page - 1}", key="ed_nav_prev"))
    if page < total - 1:
        nav.append(btn("التالي ▶️", "primary", f"ed_tp:{page + 1}", key="ed_nav_next"))
    kb = [nav] if nav else []
    kb.append([btn("🔄 إعادة ضبط النصوص", "danger", "ed_treset", key="ed_treset_all")])
    kb.append([btn("رجـوع 👋", "primary", "a_edit")])
    return text, {"inline_keyboard": kb}


def text_emoji_view(key):
    kb = {"inline_keyboard": [
        [btn("🗑 حذف الإيموجي المميز", "danger", "ed_tdel", key="ed_t_del")],
        [btn("تخطي ⏭", None, "ed_tskip", key="ed_t_skip")]]}
    return (f"<b>📝 النص المختار:</b>\n\n<code>{html.escape(key)}</code>\n\n"
            "<b>✨ أرسل الإيموجي المميز الذي تريده عليه</b>\n"
            "<b>(سيُحذف الإيموجي العادي تلقائياً، ولو عليه إيموجي مميز سيُستبدل بالجديد)</b>"), kb


def edidef edit_flow(uid, chat, ed, msg):
    text = (msg.get("text") or "").strip()
    if ed["step"] == "name" and ed.get("mode") == "txt":
        key = find_text_key(text)
        if not key:
            say(chat, "<b>❌ هذا النص غير موجود، انسخه من القائمة كما هو.</b>")
            return
        ed.update(step="temoji", key=key)
        say(chat, *text_emoji_view(key))
        return
    if ed["step"] == "temoji":
        ids = [e["custom_emoji_id"] for e in (msg.get("entities") or [])
               if e.get("type") == "custom_emoji" and e.get("custom_emoji_id")]
        if not ids:
            say(chat, "<b>❌ أرسل إيموجي مميز (Premium) فقط، أو اضغط تخطي.</b>")
            return
        db.execute("INSERT INTO text_edits (key, emoji_id) VALUES (?, ?) "
                   "ON CONFLICT(key) DO UPDATE SET emoji_id=excluded.emoji_id", (ed["key"], ids[0]))
        db.commit()
        key = ed["key"]
        ed.update(step="name")
        ed.pop("key", None)
        say(chat, f"<b>{html.escape(key)}</b>")
        say(chat, "<b>✅ تم، هذا شكل النص الآن 👆</b>\n\n<b>أرسل نصاً آخر لتعديله، أو /cancel للإنهاء.</b>",
            {"inline_keyboard": [[btn("📝 قائمة النصوص", "primary", "ed_m:txt", key="ed_menu_txt")],
                                 [btn("🎛 لوحة التحكم", "primary", "admin")]]})
        return
    if ed["step"] == "name":
        key = find_key(text)
        if not key:
            say(chat, "<b>❌ هذا الاسم غير موجود، انسخه من القائمة كما هو.</b>")
            return
        ed.update(step="color", key=key)
        say(chat, *color_view(key))
    elif ed["step"] == "color":
        say(chat, "<b>🎨 اختر اللون من الأزرار أعلاه أو اضغط تخطي.</b>")
    elif ed["step"] == "emoji":
        ids = [e["custom_emoji_id"] for e in (msg.get("entities") or [])
               if e.get("type") == "custom_emoji" and e.get("custom_emoji_id")]
        if not ids:
            say(chat, "<b>❌ أرسل إيموجي مميز (Premium) فقط، أو اضغط تخطي.</b>")
            return
        save_edit(ed["key"], emoji_id=ids[0])
        EDIT.pop(uid, None)
        say(chat, *done_view(ed["key"], "✅ تم إضافة الإيموجي المميز"))


# ================== معالجة الرسائل ==================
def get_bot_username():
    for _ in range(5):
        r = call("getMe")
        if r.get("ok"):
            return r["result"]["username"]
        desc = str(r.get("description", "تعذر الاتصال بتيليجرام"))
        if r.get("error_code") == 401 or "Unauthorized" in desc:
            print("❌ التوكن غير صالح (Unauthorized).")
            sys.exit(1)
        time.sleep(3)
    sys.exit(1)


BOT_USERNAME = get_bot_username()


def on_message(msg):
    if msg["chat"]["type"] != "private":
        return
    uid = msg["from"]["id"]
    chat = msg["chat"]["id"]
    name = msg["from"].get("first_name", "")
    text = (msg.get("text") or "").strip()

    if text.startswith("/start"):
        STATE.pop(uid, None)
        EDIT.pop(uid, None)
        parts = text.split()
        inviter = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        is_new = not one("SELECT 1 FROM users WHERE id=?", (uid,))
        rewarded = register(uid, name, inviter)
        if is_new:
            notify_new_user(uid, name, msg["from"].get("username"), inviter if rewarded else None)
        if rewarded:
            say(rewarded, f"<b>✨تم إضافة {geti('reward')} نقطة لحسابك!</b>\n"
                          "<b>✨شخص جديد انضم عبر رابط دعوتك...</b>")
        block = gate(uid)
        if block:
            say(chat, *block)
            return
        send_menu(chat, uid, name)
        return

    if text == "/diag" and is_admin(uid):
        say(chat, "<b>⏳ جاري فحص السيرفر...</b>")
        say(chat, diag())
        return

    if text == "/cancel":
        STATE.pop(uid, None)
        EDIT.pop(uid, None)
        say(chat, "<b>✅ تم الإلغاء.</b>", done_panel() if is_admin(uid) else None)
        return

    ed = EDIT.get(uid)
    if ed and is_admin(uid):
        edit_flow(uid, chat, ed, msg)
        return

    st = STATE.get(uid)
    if not st:
        if msg.get("document"):
            say(chat, "<b>✨ اضغط على «رفع بـوت» أو «رفع موقع» من القائمة أولاً ثم أرسل الملف.</b>")
        return
    if st in ("up_bot", "up_site"):
        handle_upload(uid, chat, name, st, msg)
    elif is_admin(uid):
        admin_action(uid, st, msg)


def handle_upload(uid, chat, name, st, msg):
    block = gate(uid)
    if block:
        say(chat, *block)
        return
    doc = msg.get("document")
    if not doc:
        return
    kind = "bot" if st == "up_bot" else "site"
    fname = doc.get("file_name", "file")
    low = fname.lower()
    if kind == "bot" and low.endswith(".txt"):
        if doc.get("file_size", 0) > 200 * 1024:
            say(chat, "<b>❌ ملف requirements.txt كبير جداً.</b>")
            return
        REQS[uid] = doc["file_id"]
        say(chat, "<b>✅ تم استلام requirements.txt، سيتم تثبيت مكتباته تلقائياً.</b>\n"
                  "<b>الآن أرسل ملف البوت (.py)</b>")
        return
    ok = low.endswith(".py") if kind == "bot" else low.endswith((".html", ".htm"))
    if not ok:
        say(chat, "<b>❌ ملف غير مدعوم، أرسل " +
            ("ملف بوت بلغة (.py) فقط" if kind == "bot" else "ملف بلغة html فقط") + "</b>")
        return
    if doc.get("file_size", 0) > MAX_FILE_SIZE:
        say(chat, "<b>❌ حجم الملف كبير جداً (الحد الأقصى 5MB).</b>")
        return
    cost = geti("cost_bot") if kind == "bot" else geti("cost_site")
    if get_points(uid) < cost:
        STATE.pop(uid, None)
        say(chat, f"<b>❌ نقاطك غير كافية، المطلوب {cost} نقاط.</b>")
        return
    req_id = REQS.pop(uid, None) if kind == "bot" else None
    cur = db.execute("INSERT INTO uploads (user_id, kind, file_id, file_name, created, req_id) "
                     "VALUES (?, ?, ?, ?, ?, ?)",
                     (uid, kind, doc["file_id"], fname, int(time.time()), req_id))
    db.commit()
    STATE.pop(uid, None)
    up_id = cur.lastrowid
    auto = get_setting("auto_mode") == "1"
    if auto:
        say(chat, f"<b>✅ تم استلام طلبك #{up_id}، جاري فحص الملف تلقائياً...</b>", back_keyboard())
    else:
        say(chat, f"<b>✅ تم إرسال طلبك #{up_id} للإدارة، انتظر الموافقة.</b>\n"
                  f"<b>سيتم خصم {cost} نقاط بعد الموافقة.</b>", back_keyboard())
    res = scan_upload(doc["file_id"], fname, req_id)
    if auto:
        auto_review(up_id, uid, name, kind, fname, doc["file_id"], res)
    else:
        notify_admins_upload(up_id, uid, name, kind, fname, doc["file_id"], res)


def ints(text, n):
    try:
        vals = [int(p) for p in text.split()]
    except ValueError:
        return None
    return vals if len(vals) == n else None


def admin_action(uid, st, msg):
    text = (msg.get("text") or "").strip()
    chat = msg["chat"]["id"]

    def bad(t):
        say(chat, f"<b>❌ {t}</b>\n<b>جرّب مرة أخرى أو أرسل /cancel</b>")

    def ok(t):
        STATE.pop(uid, None)
        say(chat, f"<b>✅ {t}</b>", done_panel())

    if st == "bot_check":
        src = text
        doc = msg.get("document")
        if doc:
            if doc.get("file_size", 0) > MAX_FILE_SIZE:
                return bad("حجم الملف كبير جداً")
            data = fetch_file(doc["file_id"])
            if data is None:
                return bad("تعذر تنزيل الملف")
            src = data.decode("utf-8", "replace")
        tokens = list(dict.fromkeys(TOKEN_RE.findall(src)))[:5]
        if not tokens:
            return bad("لم أجد أي توكن بوت. أرسل التوكن نفسه أو ملف فيه التوكن")
        say(chat, f"<b>⏳ جاري فحص {len(tokens)} توكن...</b>")
        for t in tokens:
            say(chat, bot_info_text(t))
        say(chat, "<b>✨ أرسل توكن آخر لفحصه، أو ارجع للوحة التحكم.</b>", done_panel())
        return

    if st == "warn_reset":
        v = ints(text, 1)
        if not v or not one("SELECT 1 FROM users WHERE id=?", (v[0],)):
            return bad("ايدي غير موجود في المستخدمين")
        db.execute("UPDATE users SET warns=0, banned=0 WHERE id=?", (v[0],))
        db.commit()
        say(v[0], "<b>✅ تم تصفير تحذيراتك من الإدارة.</b>")
        return ok("تم تصفير التحذيرات وفك الحظر")

    if st == "bc":
        users = [u for (u,) in rows("SELECT id FROM users WHERE banned=0")]
        sent = 0
        say(chat, f"<b>📨 جاري الإذاعة لـ {len(users)} مستخدم...</b>")
        for u in users:
            if call("copyMessage", chat_id=u, from_chat_id=chat, message_id=msg["message_id"]).get("ok"):
                sent += 1
            time.sleep(0.05)
        ok(f"تمت الإذاعة بنجاح لـ {sent} من {len(users)}")
        return

    if st in ("bal_add", "bal_sub"):
        v = ints(text, 2)
        if not v or not one("SELECT 1 FROM users WHERE id=?", (v[0],)):
            return bad("أرسل ايدي موجود ثم العدد، مثال: 123456789 10")
        amt = abs(v[1])
        if st == "bal_add":
            db.execute("UPDATE users SET points = points + ? WHERE id=?", (amt, v[0]))
            say(v[0], f"<b>🎁 تم إضافة {amt} نقطة لرصيدك من الإدارة.</b>")
        else:
            db.execute("UPDATE users SET points = MAX(points - ?, 0) WHERE id=?", (amt, v[0]))
            say(v[0], f"<b>➖ تم خصم {amt} نقطة من رصيدك من الإدارة.</b>")
        db.commit()
        return ok(f"تم. رصيد المستخدم الآن: {get_points(v[0])}")

    if st == "bal_all":
        v = ints(text, 1)
        if not v or v[0] <= 0:
            return bad("أرسل رقم صحيح أكبر من صفر")
        db.execute("UPDATE users SET points = points + ? WHERE banned=0", (v[0],))
        db.commit()
        return ok(f"تمت إضافة {v[0]} نقطة لكل المستخدمين")

    if st == "ch_add":
        ch = text if text.startswith("@") else "@" + text
        if not call("getChat", chat_id=ch).get("ok"):
            return bad("تعذر الوصول للقناة، تأكد من اليوزر وأن البوت أدمن فيها")
        db.execute("INSERT OR IGNORE INTO channels (username) VALUES (?)", (ch,))
        db.commit()
        return ok(f"تمت إضافة القناة {ch} للاشتراك الإجباري")

    if st == "ch_del":
        ch = text if text.startswith("@") else "@" + text
        if not one("SELECT 1 FROM channels WHERE username=?", (ch,)):
            return bad("هذه القناة غير موجودة في القائمة")
        db.execute("DELETE FROM channels WHERE username=?", (ch,))
        db.commit()
        return ok(f"تم حذف القناة {ch}")

    if st in ("ban", "unban"):
        v = ints(text, 1)
        if not v or not one("SELECT 1 FROM users WHERE id=?", (v[0],)):
            return bad("ايدي غير موجود في المستخدمين")
        if v[0] == OWNER_ID:
            return bad("لا يمكن حظر المالك")
        db.execute("UPDATE users SET banned=? WHERE id=?", (1 if st == "ban" else 0, v[0]))
        db.commit()
        return ok("تم حظر المستخدم" if st == "ban" else "تم فك الحظر")

    if st in ("adm_add", "adm_del"):
        if uid != OWNER_ID:
            return bad("هذا القسم للمالك فقط")
        v = ints(text, 1)
        if not v:
            return bad("أرسل ايدي صحيح")
        if st == "adm_add":
            db.execute("INSERT OR IGNORE INTO admins (id) VALUES (?)", (v[0],))
        else:
            db.execute("DELETE FROM admins WHERE id=?", (v[0],))
        db.commit()
        return ok("تمت إضافة الأدمن" if st == "adm_add" else "تم حذف الأدمن")

    if st == "user_info":
        v = ints(text, 1)
        r = v and one("SELECT points, banned, joined, name, invited_by, warns FROM users WHERE id=?", (v[0],))
        if not r:
            return bad("المستخدم غير موجود")
        inv = one("SELECT COUNT(*) FROM users WHERE invited_by=?", (v[0],))[0]
        ups = one("SELECT COUNT(*) FROM uploads WHERE user_id=? AND status='approved'", (v[0],))[0]
        STATE.pop(uid, None)
        say(chat,
            "<b>👤 معلومات المستخدم</b>\n\n"
            f"<b>الاسم: {html.escape(r[3] or '-')}</b>\n"
            f"<b>الايدي: <code>{v[0]}</code></b>\n"
            f"<b>النقاط: {r[0]}</b>\n"
            f"<b>عدد دعواته: {inv}</b>\n"
            f"<b>ملفاته المقبولة: {ups}</b>\n"
            f"<b>التحذيرات: {r[5]}/{geti('max_warns')}</b>\n"
            f"<b>الحالة: {'محظور 🚫' if r[1] else 'نشط ✅'}</b>\n"
            f"<b>تاريخ الانضمام: {time.strftime('%Y-%m-%d', time.localtime(r[2])) if r[2] else '-'}</b>",
            done_panel())
        return

    if st in ("set_dev", "set_channel"):
        if not text:
            return bad("أرسل يوزر صحيح")
        set_setting("dev_url" if st == "set_dev" else "channel_url", norm_link(text))
        return ok("تم تغيير الرابط")

    if st == "set_king":
        if not text.startswith("https://"):
            return bad("الرابط لازم يبدأ بـ https://")
        set_setting("king_url", text)
        return ok("تم تغيير رابط KING")

    if st == "set_base":
        if not text.startswith(("http://", "https://")):
            return bad("الرابط لازم يبدأ بـ http:// أو https://")
        set_setting("base_url", text.rstrip("/"))
        return ok("تم تغيير رابط الاستضافة")

    if st in ("cost_bot", "cost_site", "reward", "max_warns"):
        v = ints(text, 1)
        if not v or v[0] < (1 if st == "max_warns" else 0):
            return bad("أرسل رقم صحيح")
        set_setting(st, v[0])
        return ok("تم حفظ القيمة الجديدة")


# ================== معالجة الأزرار ==================
def on_callback(cb):
    uid = cb["from"]["id"]
    data = cb["data"]
    name = cb["from"].get("first_name", "")

    if data != "check_sub":
        block = gate(uid)
        if block:
            ans(cb)
            edit_to(cb, *block)
            return

    admin_data = data == "admin" or data.startswith(("a_", "ap:", "rj:", "gf:", "sc:", "ed_"))
    if admin_data and not is_admin(uid):
        ans(cb, "⛔ هذا الزر للأدمن فقط", True)
        return
    if data in OWNER_ONLY and uid != OWNER_ID:
        ans(cb, "⛔ هذا القسم للمالك فقط", True)
        return

    STATE.pop(uid, None)
    if not data.startswith("ed_"):
        EDIT.pop(uid, None)

    if data == "check_sub":
        block = gate(uid)
        if block:
            ans(cb, "❌ لم تشترك في كل القنوات بعد", True)
            edit_to(cb, *block)
        else:
            ans(cb)
            edit_to(cb, menu_text(get_points(uid), name), menu_keyboard(uid))

    elif data == "back":
        ans(cb)
        edit_to(cb, menu_text(get_points(uid), name), menu_keyboard(uid))

    elif data == "upload_bot":
        pts, cost = get_points(uid), geti("cost_bot")
        if pts < cost:
            ans(cb, f"❌ لا تملك نقاط كافية! تحتاج {cost} نقاط", True)
            edit_to(cb,
                    "<b>✨ نقاطك غير كافية!</b>\n\n"
                    f"<b>✨ نقاطك الحالية: {pts}</b>\n"
                    f"<b>✨ المطلوب: {cost} نقاط</b>\n\n"
                    f"{LINE}\n"
                    "<b>✨ كيف تحصل على نقاط؟</b>\n"
                    "اضغط على \"رابط الدعوة\" وشارك الرابط مع أصدقائك!\n"
                    f"كل شخص ينضم = {geti('reward')} نقطة لك",
                    back_keyboard())
        else:
            STATE[uid] = "up_bot"
            ans(cb)
            edit_to(cb, upload_text(), back_keyboard())

    elif data == "upload_site":
        cost = geti("cost_site")
        if get_points(uid) < cost:
            edit_to(cb,
                    "<b>✨ ليـس لديـك نقاط الكافيه لـرفـع موقـع، "
                    f"لـ رفع موقع لازم ان يكون لديك {nqta(cost)} على الاقل.</b>",
                    back_keyboard())
        else:
            STATE[uid] = "up_site"
            edit_to(cb, "<b>✨أرسـل مـلـف بـ لغة html فقـط</b>", back_keyboard())
        ans(cb)

    elif data == "my_bots":
        items = rows("SELECT id, file_name FROM uploads WHERE user_id=? AND kind='bot' AND status='approved'",
                     (uid,))
        if not items:
            edit_to(cb, "<b>✨ لم ترفع أي بوت بعد.</b>\n\n<b>✨ اضغط على \"رفع بوت\" للبـدء عزيزي</b>",
                    back_keyboard())
        else:
            kb = [[btn(f"{'يعمل' if is_running(i) else 'متوقف'} #{i} • {(f or '')[:22]}", "primary", f"mb:{i}",
                       key="إدارة البوت")] for i, f in items]
            kb.append([btn("رجـوع 👋", "primary", "back")])
            edit_to(cb, "<b>✨ بوتاتك المرفوعة:</b>\n\n<b>اضغط على بوت للتحكم به 👇🏻</b>",
                    {"inline_keyboard": kb})
        ans(cb)

    elif data == "my_sites":
        items = rows("SELECT id, file_name FROM uploads WHERE user_id=? AND kind='site' AND status='approved'",
                     (uid,))
        if not items:
            text = "<b>✨ ليـس لديك مواقع مرفوعه عزيزي.</b>"
        else:
            lst = "\n\n".join(f"<b>• {html.escape(f or '-')}</b>\n{html.escape(site_url(i))}" for i, f in items)
            text = "<b>✨ مواقعك المرفوعة:</b>\n\n" + lst
        edit_to(cb, text, back_keyboard())
        ans(cb)

    elif data.startswith(("mb:", "bs:", "bx:", "br:", "bl:")):
        act, i = data[:2], int(data[3:])
        r = one("SELECT user_id, kind, status FROM uploads WHERE id=?", (i,))
        if not r or r[1] != "bot" or r[2] != "approved" or (r[0] != uid and not is_admin(uid)):
            ans(cb, "⛔ غير متاح", True)
            return
        if act == "bs":
            start_bot(i, r[0])
            ans(cb, "▶️ جاري التشغيل")
            time.sleep(2)
        elif act == "bx":
            stop_bot(i)
            ans(cb, "⏹ تم الإيقاف")
        elif act == "br":
            restart_bot(i, r[0])
            ans(cb, "🔄 جاري إعادة التشغيل")
            time.sleep(2)
        elif act == "bl":
            tail = read_log(i)
            say(uid, f"<b>📜 سجل البوت #{i}</b>\n<pre>{html.escape(tail)}</pre>" if tail.strip()
                else "<b>📜 السجل فارغ (لا توجد مخرجات بعد).</b>")
            ans(cb)
            return
        else:
            ans(cb)
        edit_to(cb, *bot_view(i, uid))

    elif data == "points":
        invites = one("SELECT COUNT(*) FROM users WHERE invited_by=?", (uid,))[0]
        edit_to(cb,
                "<b>✨نقاطك</b>\n\n"
                f"{LINE}\n"
                f"<b>✨الرصيد الحالي: {get_points(uid)} نقطة</b>\n"
                f"<b>✨عدد دعواتك: {invites} شخص</b>\n\n"
                f"{LINE}\n"
                "<b>✨سجل النقاط:</b>\n"
                f"<b>• كل رفع: -{geti('cost_bot')} نقاط</b>\n"
                f"<b>• كل دعوة: +{geti('reward')} نقطة</b>\n\n"
                f"{LINE}\n"
                "<b>✨شارك رابـط دعوتك حب لڪسب نقاط</b>",
                back_keyboard())
        ans(cb)

    elif data == "invite":
        link = f"https://t.me/{BOT_USERNAME}?start={uid}"
        share = ("https://t.me/share/url?url=" + quote(link, safe="")
                 + "&text=" + quote("✨ انضم لبوت رفع الاستضافة 👇"))
        r = geti("reward")
        edit_to(cb,
                "<b>✨شارك رابط الدعوة مع أصدقائك</b>\n\n"
                f"<b>✨كل شخص يدخل من رابطك ستحصل على {r} نقطة</b>\n\n"
                "<b>✨رابط الدعوة الخاص بك:</b>\n"
                f"<code>{link}</code>\n\n"
                f"<b>✨ستحصل على {r} نقطة لكل عضو</b>",
                {"inline_keyboard": [[btn("مشاركة رابط دعوة", "success", url=share)],
                                     [btn("رجـوع 👋", "primary", "back")]]})
        ans(cb)

    elif data == "admin":
        ans(cb)
        edit_to(cb, panel_text(name), panel_keyboard())

    elif data in PROMPTS:
        action, prompt = PROMPTS[data]
        STATE[uid] = action
        ans(cb)
        edit_to(cb, f"<b>✨ {prompt}</b>\n\n<b>(للإلغاء أرسل /cancel)</b>", back_panel())

    elif data == "a_edit":
        STATE.pop(uid, None)
        EDIT.pop(uid, None)
        ans(cb)
        edit_to(cb, *edit_menu_view())

    elif data in ("ed_m:btn", "ed_m:txt"):
        STATE.pop(uid, None)
        ans(cb)
        if data.endswith("btn"):
            EDIT[uid] = {"step": "name", "mode": "btn"}
            edit_to(cb, *edit_list_view(0))
        else:
            EDIT[uid] = {"step": "name", "mode": "txt"}
            edit_to(cb, *text_list_view(0))

    elif data.startswith("ed_pg:"):
        STATE.pop(uid, None)
        EDIT[uid] = {"step": "name", "mode": "btn"}
        ans(cb)
        edit_to(cb, *edit_list_view(int(data[6:])))

    elif data.startswith("ed_tp:"):
        STATE.pop(uid, None)
        EDIT[uid] = {"step": "name", "mode": "txt"}
        ans(cb)
        edit_to(cb, *text_list_view(int(data[6:])))

    elif data == "ed_tskip":
        EDIT[uid] = {"step": "name", "mode": "txt"}
        ans(cb)
        edit_to(cb, *text_list_view(0))

    elif data == "ed_tdel":
        ed = EDIT.get(uid)
        if ed and ed.get("key"):
            db.execute("DELETE FROM text_edits WHERE key=?", (ed["key"],))
            db.commit()
        EDIT[uid] = {"step": "name", "mode": "txt"}
        ans(cb, "🗑 تم حذف الإيموجي المميز")
        edit_to(cb, *text_list_view(0))

    elif data == "ed_treset":
        db.execute("DELETE FROM text_edits")
        db.commit()
        EDIT[uid] = {"step": "name", "mode": "txt"}
        ans(cb, "🔄 تمت إعادة ضبط كل النصوص")
        edit_to(cb, *text_list_view(0))

    elif data.startswith("ed_c:"):
        ed = EDIT.get(uid)
        if not ed or ed["step"] != "color":
            ans(cb, "⚠️ انتهت الجلسة، ابدأ من قسم التعديل", True)
            return
        save_edit(ed["key"], style=data[5:])
        ed["step"] = "emoji"
        ans(cb, "🎨 تم تلوين الزر")
        edit_to(cb, *emoji_view(ed["key"], "✅ تم تلوين الزر"))

    elif data == "ed_skipc":
        ed = EDIT.get(uid)
        if not ed or ed["step"] != "color":
            ans(cb, "⚠️ انتهت الجلسة، ابدأ من قسم التعديل", True)
            return
        ed["step"] = "emoji"
        ans(cb)
        edit_to(cb, *emoji_view(ed["key"], "⏭ تم تخطي اللون"))

    elif data == "ed_skipe":
        ed = EDIT.pop(uid, None)
        if not ed:
            ans(cb, "⚠️ انتهت الجلسة، ابدأ من قسم التعديل", True)
            return
        ans(cb)
        edit_to(cb, *done_view(ed["key"], "✅ تم حفظ التعديلات"))

    elif data == "ed_noop":
        ans(cb, "👆 هذا شكل الزر")

    elif data == "ed_reset":
        db.execute("DELETE FROM btn_edits")
        db.commit()
        EDIT[uid] = {"step": "name"}
        ans(cb, "🔄 تمت إعادة ضبط كل الأزرار")
        edit_to(cb, *edit_list_view(0))

    elif data == "a_mode":
        ans(cb)
        edit_to(cb, *mode_view())

    elif data in ("a_mode_auto", "a_mode_manual"):
        set_setting("auto_mode", "1" if data == "a_mode_auto" else "0")
        ans(cb, "🤖 تم تفعيل الوضع التلقائي" if data == "a_mode_auto" else "👤 تم تفعيل الوضع اليدوي")
        edit_to(cb, *mode_view())

    elif data == "a_stats":
        ans(cb)
        edit_to(cb, stats_text(), back_panel())

    elif data == "a_balance":
        ans(cb)
        edit_to(cb, "<b>💰 قسم الرصيد</b>\n\n<b>تحكم في نقاط المستخدمين من هنا 👇🏻</b>",
                {"inline_keyboard": [
                    [btn("➖ خصم رصيد", "danger", "a_bal_sub"), btn("➕ إضافة رصيد", "success", "a_bal_add")],
                    [btn("🎁 إضافة نقاط للجميع", "primary", "a_bal_all")],
                    [btn("رجـوع 👋", "primary", "admin")]]})

    elif data == "a_channels":
        chs = [c for (c,) in rows("SELECT username FROM channels")]
        lst = "\n".join(f"<b>• {c}</b>" for c in chs) or "<b>لا توجد قنوات مضافة.</b>"
        ans(cb)
        edit_to(cb, f"<b>📢 قنوات الاشتراك الإجباري</b>\n\n{lst}\n\n"
                    "<b>ملاحظة: يجب أن يكون البوت أدمن في القناة.</b>",
                {"inline_keyboard": [
                    [btn("🗑 حذف قناة", "danger", "a_ch_del"), btn("➕ إضافة قناة", "success", "a_ch_add")],
                    [btn("رجـوع 👋", "primary", "admin")]]})

    elif data == "a_ban":
        banned = rows("SELECT id, name FROM users WHERE banned=1 LIMIT 30")
        lst = "\n".join(f"<b>• {html.escape(n or '-')} (<code>{i}</code>)</b>" for i, n in banned) \
            or "<b>لا يوجد محظورين.</b>"
        ans(cb)
        edit_to(cb, f"<b>🚫 قسم الحظر</b>\n\n{lst}",
                {"inline_keyboard": [
                    [btn("✅ فك حظر", "success", "a_ban_del"), btn("🚫 حظر مستخدم", "danger", "a_ban_add")],
                    [btn("رجـوع 👋", "primary", "admin")]]})

    elif data == "a_admins":
        adm = [str(a) for (a,) in rows("SELECT id FROM admins")]
        lst = f"<b>• <code>{OWNER_ID}</code> (المالك)</b>\n" + "\n".join(f"<b>• <code>{a}</code></b>" for a in adm)
        ans(cb)
        edit_to(cb, f"<b>👮 قسم الأدمن</b>\n\n{lst}",
                {"inline_keyboard": [
                    [btn("🗑 حذف أدمن", "danger", "a_adm_del"), btn("➕ إضافة أدمن", "success", "a_adm_add")],
                    [btn("رجـوع 👋", "primary", "admin")]]})

    elif data == "a_maint":
        set_setting("maintenance", "0" if get_setting("maintenance") == "1" else "1")
        ans(cb, "🛠 تم تفعيل الصيانة" if get_setting("maintenance") == "1" else "✅ تم إيقاف الصيانة")
        edit_to(cb, panel_text(name), panel_keyboard())

    elif data == "a_links":
        ans(cb)
        edit_to(cb, "<b>⚙️ تغيير الروابط</b>\n\n"
                    f"<b>المطور: {html.escape(get_setting('dev_url'))}</b>\n"
                    f"<b>القناة: {html.escape(get_setting('channel_url'))}</b>\n"
                    f"<b>KING: {html.escape(get_setting('king_url'))}</b>\n"
                    f"<b>الاستضافة: {html.escape(get_setting('base_url'))}</b>",
                {"inline_keyboard": [
                    [btn("📢 قناة المطور", "primary", "a_set_channel"),
                     btn("👨‍💻 يوزر المطور", "primary", "a_set_dev")],
                    [btn("👑 رابط KING", "primary", "a_set_king")],
                    [btn("🌐 رابط الاستضافة", "primary", "a_set_base")],
                    [btn("رجـوع 👋", "primary", "admin")]]})

    elif data == "a_prices":
        ans(cb)
        edit_to(cb, "<b>💲 الأسعار والمكافآت</b>\n\n"
                    f"<b>تكلفة رفع بوت: {geti('cost_bot')} نقاط</b>\n"
                    f"<b>تكلفة رفع موقع: {geti('cost_site')} نقاط</b>\n"
                    f"<b>مكافأة الدعوة: {geti('reward')} نقطة</b>",
                {"inline_keyboard": [
                    [btn("🌐 تكلفة موقع", "primary", "a_cost_site"),
                     btn("🤖 تكلفة بوت", "primary", "a_cost_bot")],
                    [btn("🎁 مكافأة الدعوة", "success", "a_reward")],
                    [btn("رجـوع 👋", "primary", "admin")]]})

    elif data == "a_pending":
        ans(cb)
        edit_to(cb, *pending_view())

    elif data == "a_files":
        ans(cb)
        edit_to(cb, *files_view())

    elif data.startswith("gf:"):
        r = one("SELECT file_id, file_name FROM uploads WHERE id=?", (int(data[3:]),))
        if r:
            call("sendDocument", chat_id=uid, document=r[0], caption=f"<b>📄 {html.escape(r[1] or '')}</b>",
                 parse_mode="HTML")
        ans(cb)

    elif data.startswith("sc:"):
        r = one("SELECT file_id, file_name, req_id FROM uploads WHERE id=?", (int(data[3:]),))
        if not r:
            ans(cb, "⚠️ الطلب غير موجود", True)
            return
        ans(cb, "⏳ جاري الفحص...")
        res = scan_upload(r[0], r[1], r[2])
        if res:
            send_long(uid, full_report(res))
        else:
            say(uid, "<b>❌ تعذر تنزيل الملف أو فحصه.</b>")

    elif data.startswith(("ap:", "rj:")):
        done = process_upload(cb, int(data[3:]), data.startswith("ap:"))
        if done:
            if "document" in cb["message"]:
                call("editMessageCaption", chat_id=cb["message"]["chat"]["id"],
                     message_id=cb["message"]["message_id"], parse_mode="HTML",
                     caption=f"<b>{'✅ تمت الموافقة' if data.startswith('ap:') else '❌ تم الرفض'} "
                             f"على الطلب #{data[3:]}</b>")
            else:
                edit_to(cb, *pending_view())

    else:
        ans(cb, "🚧 هذه الميزة قيد التطوير", True)


def main():
    print(f"Bot @{BOT_USERNAME} is running...")
    atexit.register(stop_all)
    try:
        signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    except Exception:
        pass
    start_site_server()
    restore_hosted()
    say(OWNER_ID, "<b>✅ البوت اشتغل وجاهز.</b>")
    offset = 0
    while True:
        try:
            res = requests.post(f"{API}/getUpdates", json={
                "offset": offset, "timeout": 30,
                "allowed_updates": ["message", "callback_query"]}, timeout=40).json()
        except Exception as e:
            print("network error:", e)
            time.sleep(3)
            continue
        for upd in res.get("result", []):
            offset = upd["update_id"] + 1
            try:
                if "message" in upd:
                    on_message(upd["message"])
                elif "callback_query" in upd:
                    on_callback(upd["callback_query"])
            except Exception:
                traceback.print_exc()


if __name__ == "__main__" or os.environ.get("BOT_NO_AUTORUN") != "1":
    try:
        main()
    except KeyboardInterrupt:
        print("تم إيقاف البوت.")
