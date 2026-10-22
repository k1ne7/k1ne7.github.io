"""Local-only, harmless demonstrations. No network listener or OS commands."""
from importlib.metadata import version
import json

from flask import Flask, render_template_string, request
from jinja2 import Environment
from werkzeug.routing import Rule

env = Environment()
assert env.from_string("{{ 7 * 7 }}").render() == "49"
assert env.from_string("{[7*7]}").render() == "{[7*7]}"
print("PASS: default Jinja delimiters")

data_app = Flask("fixed-template-demo")
with data_app.app_context():
    assert render_template_string("Hello {{ name }}!", name="{{ 7 * 7 }}") == "Hello {{ 7 * 7 }}!"
print("PASS: data is not recursively evaluated as a template")

state = {"hits": 0}
def record_visit():
    state["hits"] += 1
    return ""
assert env.from_string("{{ record_visit() }}").render(record_visit=record_visit) == ""
assert state["hits"] == 1
print("PASS: empty output can accompany a state change")

namespace = {"marker": "demo-ok"}
handler = eval("lambda: marker", namespace)
assert handler() == "demo-ok" and handler.__globals__ is namespace
print("PASS: function retains its globals dictionary")

app = Flask("routing-demo")
def marker_view():
    return "marker-ok"
app.url_map.add(Rule("/marker", endpoint="marker", methods=["GET"]))
app.view_functions["marker"] = marker_view
with app.test_client() as client:
    assert client.get("/marker").get_data(as_text=True) == "marker-ok"
print("PASS: URL rule and endpoint mapping select the registered function")
try:
    app.add_url_rule("/too-late", endpoint="too_late", view_func=lambda: "late")
except AssertionError:
    print("PASS: normal setup API rejects registration after a request")
else:
    raise AssertionError("Expected setup timing check in the tested version")

context_app = Flask("request-context-demo")
request_proxy = request
def echo_marker():
    return request_proxy.args.get("marker", "missing")
context_app.add_url_rule("/echo", endpoint="echo", view_func=echo_marker)
with context_app.test_client() as client:
    assert client.get("/echo?marker=first").get_data(as_text=True) == "first"
    assert client.get("/echo?marker=second").get_data(as_text=True) == "second"
try:
    request_proxy.args
except RuntimeError:
    print("PASS: request proxy is context-local and unavailable outside context")
else:
    raise AssertionError("Expected missing request context")

print("VERSIONS:", json.dumps({name: version(name) for name in ("Flask", "Jinja2", "Werkzeug")}))
from functools import wraps

events = []
def trace(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        events.append("before:" + func.__name__)
        result = func(*args, **kwargs)
        events.append("after:" + func.__name__)
        return result
    return wrapper

@trace
def hello(name):
    return "hello " + name
assert hello("k1ne") == "hello k1ne"
assert hello.__name__ == "hello" and hello.__wrapped__.__name__ == "hello"
assert events == ["before:hello", "after:hello"]
assert hello.__closure__ is not None
print("PASS: decorator forwards arguments/results, retains closure and metadata")

decorated_app = Flask("decorator-order-demo")
@decorated_app.route("/wrapped")
@trace
def wrapped_view():
    return "wrapped"

@trace
@decorated_app.route("/original")
def original_view():
    return "original"

assert decorated_app.view_functions["wrapped_view"] is wrapped_view
assert decorated_app.view_functions["original_view"] is original_view.__wrapped__
events.clear()
with decorated_app.test_client() as client:
    assert client.get("/wrapped").get_data(as_text=True) == "wrapped"
    assert client.get("/original").get_data(as_text=True) == "original"
assert events == ["before:wrapped_view", "after:wrapped_view"]
print("PASS: decorator order determines which function Flask registers")

print("All nine mechanism checks passed; original CTF environment was not reproduced.")
