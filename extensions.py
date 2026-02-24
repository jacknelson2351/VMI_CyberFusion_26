"""
Flask app and SocketIO instances — imported by every other module that needs them.
Nothing else lives here to avoid circular imports.
"""
from flask import Flask
from flask_socketio import SocketIO

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "ctf-agent-secret"
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024  # 256 MB max upload

# Flask 3.x removed RequestContext.session setter; disable server-managed sessions
# to avoid Socket.IO setting ctx.session (not needed here).
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", manage_session=False)
