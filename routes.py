from datetime import datetime, timezone
import hmac
import hashlib
import json
import base64
import os

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    abort,
    current_app,
)

from CTFd.utils.decorators import authed_only, admins_only
from CTFd.utils.user import get_current_user, is_admin
from CTFd.utils import get_config, set_config

PLUGIN_NAME = "ctfd_cert_redirector"
ALLOW_BEFORE_END_KEY = "cert_redirector:allow_before_end"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_token(payload: dict, secret: str) -> str:
    """
    token = base64url(JSON(payload)) + "." + base64url(HMAC-SHA256(body, secret))
    """
    body = b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    return body + "." + b64u(sig)


def get_allow_before_end() -> bool:
    val = get_config(ALLOW_BEFORE_END_KEY)
    if val is None:
        val = os.environ.get("CTFDBRIDGE_ALLOW_BEFORE_END", "false")
    return str(val).lower() in ("1", "true", "yes", "on")


def set_allow_before_end(value: bool) -> None:
    set_config(ALLOW_BEFORE_END_KEY, "true" if value else "false")


def get_settings():
    """
    Read core settings from app.config, which is populated in __init__.py.
    """
    cfg = current_app.config
    external_url = str(cfg.get("CTFDBRIDGE_EXTERNAL_URL", "")).strip()
    shared_secret = str(cfg.get("CTFDBRIDGE_SHARED_SECRET", "")).strip()
    ttl = int(cfg.get("CTFDBRIDGE_TTL", 600))
    aud = str(cfg.get("CTFDBRIDGE_AUD", "chronos-cert"))
    allow_before_end = get_allow_before_end()
    return external_url, shared_secret, ttl, aud, allow_before_end


def ctf_has_ended() -> bool:
    """
    Compare current time with CTF 'end' configuration.
    """
    end = get_config("end")
    if not end:
        return False
    try:
        dt = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
        return datetime.now(timezone.utc) >= dt
    except Exception:
        return False


def init_blueprints(app):
    user_bp = Blueprint(
        f"{PLUGIN_NAME}_user",
        __name__,
        url_prefix="/certificates",
        template_folder="templates",
    )
    admin_bp = Blueprint(
        f"{PLUGIN_NAME}_admin",
        __name__,
        url_prefix="/admin/certificates",
        template_folder="templates",
    )

    # ----------------------------------------------------------------------
    # User-facing
    # ----------------------------------------------------------------------

    # /certificates and /certificates/
    @user_bp.route("", methods=["GET"], strict_slashes=False)
    @authed_only
    def certificates_index():
        external_url, shared_secret, ttl, aud, allow_before_end = get_settings()
        ready = bool(external_url and shared_secret)
        ended = ctf_has_ended()
        allow = ended or allow_before_end or is_admin()
        return render_template(
            "certificates_user.html",
            ready=ready,
            ended=ended,
            allow=allow,
        )

    # /certificates/claim
    @user_bp.route("/claim", methods=["GET"], strict_slashes=False)
    @authed_only
    def certificates_claim():
        external_url, shared_secret, ttl, aud, allow_before_end = get_settings()
        if not (external_url and shared_secret):
            abort(503)

        if not (ctf_has_ended() or allow_before_end or is_admin()):
            abort(403)

        user = get_current_user()
        if user is None:
            abort(401)

        now_ts = int(datetime.now(timezone.utc).timestamp())

        # MINIMAL payload:
        # - uid: CTFd user id
        # - aud: audience
        # - ts: issued-at time
        # - ttl: validity window in seconds
        payload = {
            "aud": aud,
            "uid": int(user.id),
            "ts": now_ts,
            "ttl": int(ttl),
        }

        token = make_token(payload, shared_secret)
        dest = f"{external_url}?token={token}"
        return redirect(dest, code=302)

    # ----------------------------------------------------------------------
    # Admin
    # ----------------------------------------------------------------------

    # /admin/certificates and /admin/certificates/
    @admin_bp.route("", methods=["GET"], strict_slashes=False)
    @admins_only
    def admin_index():
        external_url, shared_secret, ttl, aud, allow_before_end = get_settings()
        ready = bool(external_url and shared_secret)

        # Simple GET-based toggle, no nonce, no POST
        action = request.args.get("allow_before_end")
        if action == "1":
            set_allow_before_end(True)
            return redirect(url_for(f"{PLUGIN_NAME}_admin.admin_index"))
        elif action == "0":
            set_allow_before_end(False)
            return redirect(url_for(f"{PLUGIN_NAME}_admin.admin_index"))

        status = "READY" if ready else "NOT READY"
        return render_template(
            "certificates_admin.html",
            status=status,
            ready=ready,
            external_url=external_url,
            ttl=ttl,
            aud=aud,
            allow_before_end=get_allow_before_end(),
        )

    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)
