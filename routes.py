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
from CTFd.models import Teams

PLUGIN_NAME = "ctfd_cert_redirector"
ALLOW_BEFORE_END_KEY = "cert_redirector:allow_before_end"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_token(payload: dict, secret: str) -> str:
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
    cfg = current_app.config
    external_url = str(cfg.get("CTFDBRIDGE_EXTERNAL_URL", "")).strip()
    shared_secret = str(cfg.get("CTFDBRIDGE_SHARED_SECRET", "")).strip()
    ttl = int(cfg.get("CTFDBRIDGE_TTL", 600))
    aud = str(cfg.get("CTFDBRIDGE_AUD", "chronos-cert"))
    allow_before_end = get_allow_before_end()
    return external_url, shared_secret, ttl, aud, allow_before_end


def ctf_has_ended() -> bool:
    end = get_config("end")
    if not end:
        return False
    try:
        dt = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
        return datetime.now(timezone.utc) >= dt
    except Exception:
        return False


def compute_team_rank(team: Teams) -> tuple[int | None, int | None]:
    """
    Returns (team_score, team_pos) or (None, None).
    Uses Python-side sorting to avoid touching the Teams.score hybrid
    property inside SQL expressions.
    """
    if team is None:
        return None, None

    try:
        team_score = team.score
    except Exception:
        return None, None

    if team_score is None:
        return None, None

    teams = Teams.query.filter(
        Teams.banned == False,
        Teams.hidden == False,
    ).all()

    sorted_teams = sorted(
        teams,
        key=lambda t: (
            (getattr(t, "score", 0) or 0),
            t.id,
        ),
        reverse=True,
    )

    team_pos = None
    for idx, t in enumerate(sorted_teams, start=1):
        if t.id == team.id:
            team_pos = idx
            break

    return team_score, team_pos


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

        team = None
        if getattr(user, "team_id", None):
            team = Teams.query.filter_by(id=user.team_id).first()

        team_name = team.name if team is not None else None
        team_score, team_pos = compute_team_rank(team)

        payload = {
            "aud": aud,
            "uid": user.id,
            "email": getattr(user, "email", None),
            "name": user.name,
            "team_id": getattr(user, "team_id", None),
            "team_name": team_name,
            "team_score": team_score,
            "team_pos": team_pos,
            "bracket_id": getattr(user, "bracket_id", None),
            "bracket_name": None,
            "ts": int(datetime.now(timezone.utc).timestamp()),
            "ttl": ttl,
        }
        token = make_token(payload, shared_secret)
        dest = f"{external_url}?token={token}"
        return redirect(dest, code=302)

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
