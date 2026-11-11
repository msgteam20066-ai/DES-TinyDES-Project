"""Điểm vào chương trình demo TinyDES:  python main.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if hasattr(sys.stdout, "reconfigure"):          # hiển thị tiếng Việt trên Windows
    sys.stdout.reconfigure(encoding="utf-8")

from app.cli import main

if __name__ == "__main__":
    main()
