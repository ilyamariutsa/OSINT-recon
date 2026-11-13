"""Запуск как настольного приложения: локальный сервер + окно (WebView2), резерв — Edge в режиме приложения."""
import ctypes
import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request

from . import config

APP_ID = "OSINTRecon.Desktop"
ICON = os.path.join(os.path.dirname(__file__), "static", "app.ico")


def _log_setup() -> logging.Logger:
    os.makedirs(config.DATA_DIR, exist_ok=True)
    logging.basicConfig(filename=os.path.join(config.DATA_DIR, "app.log"), level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", encoding="utf-8")
    return logging.getLogger("desktop")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _message(text: str) -> None:
    try:
        ctypes.windll.user32.MessageBoxW(None, text, "OSINT Recon", 0x10)
    except Exception:
        print(text, file=sys.stderr)


def _start_server(log: logging.Logger):
    import uvicorn
    from .main import app

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning",
                                           log_config=None, access_log=False))
    th = threading.Thread(target=server.run, name="uvicorn", daemon=True)
    th.start()
    url = f"http://127.0.0.1:{port}/"
    for _ in range(150):
        try:
            with urllib.request.urlopen(url + "api/health", timeout=1) as r:
                if r.status == 200:
                    log.info("server ready on %s", url)
                    return server, url
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("локальный сервер не запустился")


def _set_icon(window, log):
    try:
        import clr  # noqa: F401 — pythonnet уже загружен pywebview
        from System import Action
        from System.Drawing import Icon
        form = window.native
        form.Invoke(Action(lambda: setattr(form, "Icon", Icon(ICON))))
    except Exception as e:  # иконка окна — не критично
        log.info("window icon not set: %r", e)
    try:  # тёмный заголовок окна (Windows 10 20H1+ / 11)
        hwnd = window.native.Handle.ToInt64()
        val = ctypes.c_int(1)
        for attr in (20, 19):
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(ctypes.c_void_p(hwnd), attr, ctypes.byref(val),
                                                          ctypes.sizeof(val)) == 0:
                break
        cap = ctypes.c_int(0x001C110C)  # цвет заголовка (COLORREF BGR) = #0C111C, Windows 11
        ctypes.windll.dwmapi.DwmSetWindowAttribute(ctypes.c_void_p(hwnd), 35, ctypes.byref(cap), 4)
    except Exception as e:
        log.info("dark title not set: %r", e)


def _run_webview(url: str, log) -> bool:
    try:
        import webview
    except Exception as e:
        log.warning("pywebview unavailable: %r", e)
        return False
    try:
        webview.settings["ALLOW_DOWNLOADS"] = True
        webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
        win = webview.create_window("OSINT Recon", url, width=1440, height=920, min_size=(960, 620),
                                    background_color="#0b0f1a", text_select=True)
        win.events.shown += lambda: _set_icon(win, log)
        webview.start(gui="edgechromium", private_mode=False,
                      storage_path=os.path.join(config.DATA_DIR, "webview"))
        return True
    except Exception as e:
        log.exception("webview failed: %r", e)
        return False


def _run_edge(url: str, log) -> bool:
    cands = [shutil.which("msedge"),
             os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
             os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
             shutil.which("chrome"),
             os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe")]
    exe = next((c for c in cands if c and os.path.isfile(c)), None)
    if not exe:
        return False
    prof = os.path.join(config.DATA_DIR, "browser-profile")
    log.info("fallback browser: %s", exe)
    p = subprocess.Popen([exe, f"--app={url}", f"--user-data-dir={prof}", "--no-first-run",
                          "--window-size=1440,920"])
    p.wait()
    return True


def main() -> None:
    log = _log_setup()
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except Exception:
        pass
    try:
        server, url = _start_server(log)
    except Exception as e:
        log.exception("server start failed")
        _message(f"Не удалось запустить OSINT Recon:\n{e}\n\nЖурнал: {config.DATA_DIR}\\app.log")
        return
    try:
        if "--browser" in sys.argv or not _run_webview(url, log):
            if not _run_edge(url, log):
                import webbrowser
                webbrowser.open(url)
                _message("Приложение открыто в браузере. Закройте это окно, чтобы остановить сервер.")
    finally:
        server.should_exit = True
        time.sleep(0.5)


if __name__ == "__main__":
    main()
