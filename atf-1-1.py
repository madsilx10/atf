"""
ATF Miners Bot - Multi Account
Requirements: pip install tonsdk requests pyrogram tgcrypto

wallet.txt  -> satu wallet per blok (dipisah baris kosong)
sessions.txt -> satu string session per baris
Urutan wallet dan session harus sama.
"""

import asyncio
import base64
import hashlib
import re
import struct
import time
import uuid

import requests
from pyrogram import Client
from pyrogram.raw.functions.messages import RequestAppWebView
from pyrogram.raw.types import InputBotAppShortName
from pyrogram.types import User
from tonsdk.crypto import mnemonic_to_wallet_key
from tonsdk.contract.wallet import WalletVersionEnum, Wallets
from nacl.signing import SigningKey

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
API_ID   = 0        # ganti
API_HASH = ""       # ganti

BOT_USERNAME = "ATF_AIRDROP_bot"
BOT_SHORT    = "ATFMiner"
START_PARAM  = ""

BASE_URL = "https://atfminers.asloni.online/miner/index.php"
DOMAIN   = "atftoken.com"

UA = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36"

PERIODIC_TASKS = [
    "youtube_like_comment",
    "twitter_retweet",
    "website_visit",
    "telegram_react_latest",
]

ONETIME_TASKS = [
    "telegram_join_fa",
    "youtube_subscribe",
    "telegram_join",
]

TASK_START_DELAY = 5

# ─────────────────────────────────────────────────────────────────────────────
# FILE LOADER
# ─────────────────────────────────────────────────────────────────────────────
def load_sessions(path="sessions.txt"):
    with open(path) as f:
        return [l.strip() for l in f if l.strip()]

def load_wallets(path="wallet.txt"):
    with open(path) as f:
        content = f.read()
    return [b.strip() for b in re.split(r"\n\s*\n", content) if b.strip()]

# ─────────────────────────────────────────────────────────────────────────────
# PYROGRAM
# ─────────────────────────────────────────────────────────────────────────────
async def get_init_data(session_str: str):
    client = Client(
        name="atf_session",
        api_id=API_ID,
        api_hash=API_HASH,
        session_string=session_str,
        in_memory=True,
    )
    async with client:
        me: User = await client.get_me()
        tg_id    = str(me.id)
        username = me.username or me.first_name or str(me.id)
        bot_peer = await client.resolve_peer(BOT_USERNAME)
        app      = InputBotAppShortName(bot_id=bot_peer, short_name=BOT_SHORT)
        result   = await client.invoke(
            RequestAppWebView(
                peer=bot_peer,
                app=app,
                platform="android",
                start_param=START_PARAM,
                write_allowed=True,
            )
        )
        from urllib.parse import unquote
        match = re.search(r"tgWebAppData=([^&]+)", result.url)
        if not match:
            raise ValueError("tgWebAppData tidak ditemukan")
        init_data = unquote(match.group(1))
    return init_data, tg_id, username

# ─────────────────────────────────────────────────────────────────────────────
# TON WALLET
# ─────────────────────────────────────────────────────────────────────────────
def derive_wallet(mnemonic_str: str):
    words = mnemonic_str.strip().split()
    pub_key, priv_key = mnemonic_to_wallet_key(words)

    # Buat wallet v4r2
    mnemonics, pub_k, priv_k, wallet = Wallets.from_mnemonics(
        words, WalletVersionEnum.v4r2, workchain=0
    )
    addr = wallet.address

    # Format address
    address_friendly = addr.to_string(True, True, False)  # non-bounceable
    address_raw      = f"0:{addr.hash_part.hex()}"
    state_init_cell  = wallet.create_state_init()["state_init"]
    state_init       = base64.b64encode(bytes(state_init_cell.to_boc(False))).decode()
    pub_hex          = pub_key.hex()

    return priv_key, pub_hex, address_friendly, address_raw, state_init

def sign_proof(priv_key: bytes, address_raw: str, domain: str, timestamp: int, payload: str) -> str:
    prefix   = b"ton-proof-item-v2/"
    wc, ahex = address_raw.split(":")
    addr_b   = bytes.fromhex(ahex)
    domain_b = domain.encode()
    msg = (prefix + struct.pack(">i", int(wc)) + addr_b
           + struct.pack("<I", len(domain_b)) + domain_b
           + struct.pack("<q", timestamp) + payload.encode())
    h   = hashlib.sha256(b"\xff\x00" + hashlib.sha256(msg).digest()).digest()
    signing_key = SigningKey(priv_key[:32])
    signed      = signing_key.sign(h)
    return base64.b64encode(signed.signature).decode()

# ─────────────────────────────────────────────────────────────────────────────
# ATF SESSION
# ─────────────────────────────────────────────────────────────────────────────
class ATFSession:
    def __init__(self, init_data, tg_id, username, priv_key, pub_hex,
                 address_friendly, address_raw, state_init):
        self.init_data         = init_data
        self.tg_id             = tg_id
        self.username          = username
        self.priv_key          = priv_key
        self.pub_hex           = pub_hex
        self.address_friendly  = address_friendly
        self.address_raw       = address_raw
        self.state_init        = state_init
        self.device_id         = "dev-" + str(uuid.uuid4())
        self.tma_session       = None
        self.http = requests.Session()
        self.http.headers.update({
            "Content-Type":      "application/json",
            "Accept":            "*/*",
            "Accept-Encoding":   "gzip, deflate, br",
            "Origin":            "https://atfminers.asloni.online",
            "Referer":           "https://atfminers.asloni.online/miner/index.html",
            "User-Agent":        UA,
            "X-Requested-With":  "XMLHttpRequest",
            "Sec-Ch-Ua":         '"Chromium";v="137", "Not/A)Brand";v="24"',
            "Sec-Ch-Ua-Mobile":  "?1",
            "Sec-Ch-Ua-Platform":'"Android"',
            "Sec-Fetch-Dest":    "empty",
            "Sec-Fetch-Mode":    "cors",
            "Sec-Fetch-Site":    "same-origin",
        })

    def _headers(self):
        h = {"X-Telegram-Init-Data": self.init_data}
        if self.tma_session:
            h["X-Atf-Tma-Session"] = self.tma_session
        return h

    def _post(self, action, payload) -> dict:
        url  = f"{BASE_URL}?action={action}&t={int(time.time())}"
        resp = self.http.post(url, json=payload, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        sc = resp.headers.get("Set-Cookie", "")
        m  = re.search(r"atf_tma_session=([^;]+)", sc)
        if m:
            self.tma_session = m.group(1)
        return resp.json()

    def _p(self, extra=None):
        p = {"device_id": self.device_id, "initData": self.init_data,
             "request_id": str(uuid.uuid4()), "tg_id": self.tg_id}
        if extra:
            p.update(extra)
        return p

    def login(self) -> dict:
        r = self._post("login", self._p({"username": self.username}))
        if r.get("status") != "success":
            raise Exception(f"Login gagal: {r}")
        self.tma_session = r.get("tma_session_token", self.tma_session)
        return r

    def get_proof_payload(self, force=False) -> str:
        r = self._post("get_wallet_proof_payload", self._p({"force": 1 if force else 0}))
        if r.get("status") != "success":
            raise Exception(f"get_proof_payload gagal: {r}")
        return r["payload"]

    def sync_wallet(self, nonce: str) -> dict:
        ts  = int(time.time())
        sig = sign_proof(self.priv_key, self.address_raw, DOMAIN, ts, nonce)
        return self._post("sync_wallet", self._p({
            "network": "-239",
            "proof": {
                "timestamp": ts,
                "domain":    {"lengthBytes": len(DOMAIN), "value": DOMAIN},
                "payload":   nonce,
                "signature": sig,
            },
            "public_key":        self.pub_hex,
            "refresh_holding":   0,
            "wallet":            self.address_raw,
            "wallet_state_init": self.state_init,
        }))

    def get_math_challenge(self):
        r = self._post("get_math_challenge", self._p({"scope": "start_mine"}))
        if r.get("status") != "success":
            raise Exception(f"math_challenge gagal: {r}")
        q   = r["question"]
        cid = r["challenge_id"]
        m   = re.match(r"(\d+)\s*([+\-*])\s*(\d+)", q)
        if not m:
            raise ValueError(f"Soal tidak dikenal: {q}")
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        ans = a + b if op == "+" else (a - b if op == "-" else a * b)
        print(f"    captcha: {q} -> {ans}")
        return cid, ans

    def start_mine(self):
        cid, ans = self.get_math_challenge()
        r = self._post("start_mine", self._p({
            "math_answer":       str(ans),
            "math_challenge_id": cid,
        }))
        print(f"    mining: {r.get('status')} | freezes_at: {r.get('mining_freezes_at','-')}")
        return r

    def do_task(self, task_id: str):
        self._post("start_task", self._p({
            "client_started_at": int(time.time()),
            "task_id": task_id,
        }))
        time.sleep(TASK_START_DELAY)
        r = self._post("claim_task", self._p({
            "client_started_at": 0,
            "task_id": task_id,
        }))
        print(f"    task {task_id}: {r.get('status')} | reward: {r.get('reward',0)}")
        return r

# ─────────────────────────────────────────────────────────────────────────────
# RUNNER
# ─────────────────────────────────────────────────────────────────────────────
def run_account(idx, session_str, mnemonic_str, mode):
    print(f"\n{'─'*50}")
    print(f" Akun {idx+1}")
    print(f"{'─'*50}")

    init_data, tg_id, username = asyncio.run(get_init_data(session_str))
    priv_key, pub_hex, addr_f, addr_r, state_init = derive_wallet(mnemonic_str)
    print(f"  user   : {username}")
    print(f"  wallet : {addr_f}")

    s = ATFSession(init_data, tg_id, username, priv_key, pub_hex, addr_f, addr_r, state_init)

    login_res       = s.login()
    user_data       = login_res.get("user", {})
    wallet_verified = int(user_data.get("wallet_verified", 0))
    print(f"  login  : OK | wallet_verified: {wallet_verified}")

    # wallet sync
    if mode == "full" and not wallet_verified:
        print("  wallet : belum verified, sync...")
        nonce = login_res.get("wallet_proof_payload") or s.get_proof_payload()
        r     = s.sync_wallet(nonce)
        print(f"  wallet : {r.get('status')} {r.get('message','')}")
    elif wallet_verified:
        print("  wallet : sudah verified, skip")

    # tasks
    if mode in ("full", "task"):
        tasks = []
        if mode == "full":
            completed = user_data.get("completed_tasks", [])
            tasks += [t for t in ONETIME_TASKS if t not in completed]
        tasks += PERIODIC_TASKS
        print(f"  tasks  : {tasks}")
        for t in tasks:
            try:
                s.do_task(t)
            except Exception as e:
                print(f"    task {t}: error - {e}")
            time.sleep(1)

    # mining
    if mode in ("full", "mining"):
        try:
            s.start_mine()
        except Exception as e:
            print(f"  mining : error - {e}")

    print(f" Akun {idx+1} selesai")

# ─────────────────────────────────────────────────────────────────────────────
# MENU INTERAKTIF
# ─────────────────────────────────────────────────────────────────────────────
def prompt(label, options):
    print(f"\n{label}")
    for i, o in enumerate(options, 1):
        print(f"  {i}. {o}")
    while True:
        try:
            val = int(input("Pilih: "))
            if 1 <= val <= len(options):
                return val - 1
        except (ValueError, KeyboardInterrupt):
            pass
        print("  Input tidak valid.")

def ask_int(label, min_v, max_v):
    while True:
        try:
            val = int(input(f"{label} ({min_v}-{max_v}): "))
            if min_v <= val <= max_v:
                return val
        except (ValueError, KeyboardInterrupt):
            pass
        print("  Input tidak valid.")

def main():
    sessions = load_sessions()
    wallets  = load_wallets()
    n        = len(sessions)

    if n != len(wallets):
        print(f"[!] Jumlah session ({n}) != wallet ({len(wallets)}), cek file.")
        return

    print("=" * 50)
    print("  ATF Miners Bot")
    print("=" * 50)
    print(f"  Total akun: {n}")

    # Pilih mode
    mode_idx = prompt("Mode:", ["Full (wallet + task + mining)", "Mining aja", "Task aja"])
    mode     = ["full", "mining", "task"][mode_idx]

    # Pilih akun
    akun_mode = prompt("Akun:", ["1 akun", "Semua", "Dari X sampai akhir"])

    if akun_mode == 0:
        num = ask_int("Akun ke berapa?", 1, n)
        indices = [num - 1]
    elif akun_mode == 1:
        indices = list(range(n))
    else:
        start = ask_int("Mulai dari akun berapa?", 1, n)
        indices = list(range(start - 1, n))

    print(f"\nMode   : {mode.upper()}")
    print(f"Akun   : {[i+1 for i in indices]}")
    input("\nTekan Enter untuk mulai...")

    for i in indices:
        try:
            run_account(i, sessions[i], wallets[i], mode)
        except Exception as e:
            print(f"[!] Akun {i+1} error: {e}")
        time.sleep(2)

    print("\nSemua selesai.")

if __name__ == "__main__":
    main()
