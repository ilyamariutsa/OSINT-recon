"""Точка входа ярлыка: окно приложения без консоли."""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("OSINT_DATA_DIR", os.path.join(ROOT, "data"))
sys.path.insert(0, os.path.join(ROOT, "app"))

from osint_recon.desktop import main  # noqa: E402

main()
