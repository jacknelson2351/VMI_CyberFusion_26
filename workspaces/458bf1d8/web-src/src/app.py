import requests
import bleach
import markdown2
from markupsafe import Markup
from flask import Flask, render_template, request

app = Flask(__name__)

@app.get("/")
def index():
    md = request.args.get("markdown", "# Hello world")

    # remove xss attempts
    safe_md = bleach.clean(
        md,
        tags=[],
        attributes={},
        protocols=[],
        strip=True,
        strip_comments=True,
    )

    # Convert markdown to html
    # use safe_mode to prevent further xss attempts
    html = Markup(markdown2.markdown(safe_md, safe_mode="escape"))

    response = render_template(
        "index.html",
        markdown_input=md,
        html_output=html,
    )

    response = app.make_response(response)
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "style-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "object-src 'none';"
    )

    return response

@app.post("/report")
def report():
    url = request.form.get("url")
    if not url:
        return {"result": "no url"}
    return {"result": requests.post("http://localhost:3000/report", json={"url": url}).text}