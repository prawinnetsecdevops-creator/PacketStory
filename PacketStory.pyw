"""Double-click launcher: runs the analyzer app without a console window."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import main

main()
