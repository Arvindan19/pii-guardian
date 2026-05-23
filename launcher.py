import sys
import os


def resource_path(relative_path):
    """Return absolute path — works for dev and for PyInstaller bundle."""
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative_path)


if __name__ == '__main__':
    app_path = resource_path('app.py')
    sys.argv = ['streamlit', 'run', app_path, '--server.port=8501']
    from streamlit.web import cli as stcli
    sys.exit(stcli.main())
