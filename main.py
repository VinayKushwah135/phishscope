"""PhishScope entry point:  python main.py [optional-file.eml]"""
import sys

from PyQt5.QtWidgets import QApplication

from gui import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("PhishScope")
    app.setStyle("Fusion")            # consistent base; the modern theme is applied in gui.STYLE
    win = MainWindow()
    win.show()
    if len(sys.argv) > 1:
        win.load_file(sys.argv[1])
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
