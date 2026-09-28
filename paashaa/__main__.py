import logging
import sys

from . import __version__
from .config import LOG_PATH


def main() -> None:
    logging.basicConfig(filename=LOG_PATH, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if "--version" in sys.argv:
        print(f"PaaShaa {__version__}")
        return
    try:
        from .gui.app import App
    except ImportError as e:
        sys.exit(f"Missing dependency or Tkinter: {e}\nInstall with: pip install -r requirements.txt")
    App().mainloop()


if __name__ == "__main__":
    main()
