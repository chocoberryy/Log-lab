"""Titik masuk Monitor untuk systemd/uvicorn: `loglab.monitor_main:app`.

Aplikasi dibuat saat pertama kali dipanggil (bukan saat import), dari variabel LOGLAB_* yang
sudah divalidasi kontrak. Paket model dimuat sekali; bila gagal, alasannya terlihat di dashboard
dan hasil ML ditandai failed, tanpa mematikan penerimaan event.
"""
from __future__ import annotations

from .config import Settings
from .model import ModelError, load_model
from .monitor_app import create_app


def build_app():
    settings = Settings.from_env("monitor")
    package, error = None, None
    try:
        package = load_model(settings.model_path)
    except ModelError as exc:
        error = exc.code
    return create_app(settings, model=package, model_error=error, start_analysis=True)


class _LazyApp:
    """ASGI app yang membangun aplikasi sebenarnya pada panggilan pertama (startup uvicorn)."""

    def __init__(self) -> None:
        self._app = None

    async def __call__(self, scope, receive, send) -> None:
        if self._app is None:
            self._app = build_app()
        await self._app(scope, receive, send)


app = _LazyApp()
