import os
import json
import logging
import sys
import socket
import requests
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, redirect, render_template, request, send_from_directory, Response, make_response
from pythonjsonlogger import jsonlogger

# Configuration: Remote ELK shipping
REMOTE_ELK_ENABLE = os.getenv('REMOTE_ELK_ENABLE', 'false').lower() == 'true'
ELK_URL = os.getenv('ELK_URL', 'https://elk.example.com:9200')
ELK_INDEX = os.getenv('ELK_INDEX', 'tpot-logs-%{+YYYY.MM.dd}')
ELK_USER = os.getenv('ELK_USER', None)
ELK_PASS = os.getenv('ELK_PASS', None)
ELK_USE_SSL = os.getenv('ELK_USE_SSL', 'true').lower() == 'true'

class ElasticsearchHandler(logging.Handler):
    """
    Logging handler to ship JSON payloads directly to Elasticsearch.
    """
    def __init__(self, elk_url, index, user=None, password=None, use_ssl=True):
        super().__init__()
        self.elk_url = elk_url.rstrip('/')
        self.index = index
        self.auth = (user, password) if user and password else None
        self.verify = use_ssl

    def emit(self, record):
        payload = record.__dict__.get('extra', {}) or {}
        payload.setdefault('@timestamp', datetime.now(timezone.utc).isoformat())
        url = f"{self.elk_url}/{self.index}/_doc/"
        headers = {'Content-Type': 'application/json'}
        try:
            resp = requests.post(
                url,
                json=payload,
                headers=headers,
                auth=self.auth,
                verify=self.verify
            )
            resp.raise_for_status()
        except Exception:
            self.handleError(record)

# Setup logger

def setup_logger():
    logger = logging.getLogger('honeypot')
    logger.setLevel(logging.INFO)
    fmt = '%(asctime)s %(name)s %(levelname)s %(message)s'
    json_fmt = jsonlogger.JsonFormatter(fmt)

    # stdout handler (Filebeat/T-Pot)
    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(json_fmt)
    logger.addHandler(sh)

    # local file handler
    # Clear existing log file on startup
    try:
        open('dumpass.log', 'w').close()
    except Exception:
        pass
    fh = logging.FileHandler('dumpass.log')
    fh.setLevel(logging.INFO)
    fh.setFormatter(json_fmt)
    logger.addHandler(fh)

    # optional remote ELK handler
    if REMOTE_ELK_ENABLE:
        es = ElasticsearchHandler(ELK_URL, ELK_INDEX, ELK_USER, ELK_PASS, ELK_USE_SSL)
        es.setLevel(logging.INFO)
        logger.addHandler(es)

    return logger

logger = setup_logger()

def detect_exploit(req):
    """Placeholder for future exploit signature detection."""
    return None

# Build Flask app
def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(SECRET_KEY=os.getenv('SECRET_KEY', 'dev'))
    os.makedirs(app.instance_path, exist_ok=True)

    def log_event(**fields):
        data = {
            '@timestamp': datetime.now(timezone.utc).isoformat(),
            'client_ip': request.remote_addr,
            'method': request.method,
            'uri_path': request.path,
            'query_string': request.query_string.decode('utf-8'),
            'status_code': fields.get('status_code'),
            'user_agent': request.headers.get('User-Agent'),
            'auth_type': fields.get('auth_type'),
            'username': fields.get('username', ''),
            'password': fields.get('password', ''),
            'password_text': fields.get('password_text', ''),
            'raw_body': request.get_data(as_text=True),
            'attempted_endpoints': fields.get('attempted_endpoints', []),
            'exploit_signature': detect_exploit(request),
            'cve_id': fields.get('cve_id'),
        }
        logger.info('owa_event', extra={'extra': data})

    def add_headers(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            resp = make_response(f(*args, **kwargs))
            for k, v in {'Server': 'Microsoft-IIS/7.5', 'X-Powered-By': 'ASP.NET'}.items():
                resp.headers[k] = v
            return resp
        return wrapped

    # Error handlers
    @app.errorhandler(404)
    @add_headers
    def not_found(e):
        log_event(status_code=404)
        return render_template('404.html'), 404

    @app.errorhandler(403)
    @add_headers
    def forbidden(e):
        log_event(status_code=403)
        return render_template('403.html'), 403

    @app.errorhandler(401)
    @add_headers
    def unauthorized(e):
        log_event(status_code=401)
        return render_template('401.html'), 401

    # Basic auth stub decorator
    def check_auth(username, password):
        log_event(auth_type='basic', username=username, password=password)
        return False

    def authenticate():
        return Response('Login required', 401,
                        {'WWW-Authenticate': 'Basic realm="Login Required"'})

    def requires_auth(f):
        @wraps(f)
        def dec(*args, **kwargs):
            auth = request.authorization
            if not auth or not check_auth(auth.username, auth.password):
                return authenticate()
            return f(*args, **kwargs)
        return dec

    # OWA login flow with explicit blank user/pass handling
    @app.route('/owa/auth.owa', methods=['GET', 'POST'])
    @add_headers
    def auth():
        if request.method == 'GET':
            log_event(status_code=200)
            # Initial GET should not display an error
            return render_template('outlook_web.html', error=None, username=''), 200

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        log_event(auth_type='form', username=username, password=password, status_code=200)

        if not username:
            error = "You didn't enter a user name. Please try again."
        elif not password:
            error = "You didn't enter a password. Please try again."
        else:
            error = "The user name or password you entered isn't correct. Try entering it again."

        return render_template('outlook_web.html', error=error, username=username), 200

    # Alias logon.aspx
    @app.route('/owa/auth/logon.aspx')
    @add_headers
    def owa_logon():
        return redirect('/owa/auth.owa'), 302

    # Static assets
    @app.route('/owa/auth/15.1.1466/themes/resources/segoeui-regular.ttf')
    @add_headers
    def font_regular():
        return send_from_directory(app.static_folder, 'segoeui-regular.ttf', conditional=True)

    @app.route('/owa/auth/15.1.1466/themes/resources/segoeui-semilight.ttf')
    @add_headers
    def font_semilight():
        return send_from_directory(app.static_folder, 'segoeui-semilight.ttf', conditional=True)

    @app.route('/owa/auth/15.1.1466/themes/resources/favicon.ico')
    @add_headers
    def favicon():
        return send_from_directory(app.static_folder, 'favicon.ico', conditional=True)

    # Stub endpoints
    stub_paths = [
        '/Abs/', '/aspnet_client/', '/Autodiscover/', '/AutoUpdate/', '/CertEnroll/',
        '/CertSrv/', '/Conf/', '/DeviceUpdateFiles_Ext/', '/DeviceUpdateFiles_Int/',
        '/ecp/', '/Etc/', '/EWS/', '/Exchweb/', '/GroupExpansion/',
        '/Microsoft-Server-ActiveSync/', '/OAB/', '/ocsp/', '/PhoneConferencing/',
        '/PowerShell/', '/Public/', '/RequestHandler/', '/RequestHandlerExt/',
        '/Rgs/', '/Rpc/', '/RpcWithCert/', '/UnifiedMessaging/'
    ]
    for idx, path in enumerate(stub_paths):
        endpoint = f'stub_{idx}'
        def mkview(p):
            @add_headers
            @requires_auth
            def view():
                log_event(auth_type='basic', attempted_endpoints=[p], status_code=302)
                return redirect('/owa/auth.owa')
            return view
        app.add_url_rule(path, endpoint, mkview(path))

    # Root & alias routes
    @app.route('/')
    @app.route('/exchange/')
    @app.route('/webmail/')
    @app.route('/exchange')
    @app.route('/webmail')
    @add_headers
    def index():
        log_event(status_code=302)
        return redirect('/owa/auth.owa'), 302

    return app

if __name__ == '__main__':
    create_app().run(host='0.0.0.0', port=80)
