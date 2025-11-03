import os
import logging

from CTFd.plugins import register_admin_plugin_menu_bar

log = logging.getLogger("CTFd")

EXTERNAL_URL_ENV = "CTFDBRIDGE_EXTERNAL_URL"
SECRET_ENV = "CTFDBRIDGE_SHARED_SECRET"
TTL_ENV = "CTFDBRIDGE_TTL"
AUD_ENV = "CTFDBRIDGE_AUD"


def load(app):
    external_url = os.getenv(EXTERNAL_URL_ENV, "").strip()
    shared_secret = os.getenv(SECRET_ENV, "").strip()
    ttl = int(os.getenv(TTL_ENV, "600"))
    aud = os.getenv(AUD_ENV, "chronos-cert")

    app.config.setdefault("CTFDBRIDGE_EXTERNAL_URL", external_url)
    app.config.setdefault("CTFDBRIDGE_SHARED_SECRET", shared_secret)
    app.config.setdefault("CTFDBRIDGE_TTL", ttl)
    app.config.setdefault("CTFDBRIDGE_AUD", aud)

    from .routes import init_blueprints
    init_blueprints(app)

    try:
        register_admin_plugin_menu_bar(
            title="Certificates",
            route="/admin/certificates",
        )
    except Exception:
        app.logger.warning("ctfd_cert_redirector: unable to register admin menu item")

    log.info(
        "[ctfd_cert_redirector] external_url='%s' ttl=%s aud='%s'",
        external_url or "<unset>",
        ttl,
        aud,
    )
