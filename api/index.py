import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from backend.app import app
handler = app
