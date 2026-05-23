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
    os.environ['STREAMLIT_GLOBAL_DEVELOPMENT_MODE'] = 'false'
    os.environ['STREAMLIT_SERVER_HEADLESS'] = 'true'
    os.environ['STREAMLIT_BROWSER_GATHER_USAGE_STATS'] = 'false'

    app_path = resource_path('app.py')
    sys.argv = ['streamlit', 'run', app_path, '--server.port=8501']
    from streamlit.web import cli as stcli
    sys.exit(stcli.main())
