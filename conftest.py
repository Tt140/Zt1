import sys
from pathlib import Path

# Ensure src directory is in sys.path for test discovery
sys.path.insert(0, str(Path(__file__).parent / "src"))
