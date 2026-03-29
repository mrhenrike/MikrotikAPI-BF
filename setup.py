"""
setup.py — MikrotikAPI-BF
==========================
Post-install hook: copies NSE scripts to Nmap's scripts directory
automatically after `pip install` or `pip install --upgrade`.

This file works alongside pyproject.toml (PEP 517/518).
The post-install hook is the primary reason this file exists.
"""

from setuptools import setup
from setuptools.command.install import install
from setuptools.command.develop import develop


class _PostInstallMixin:
    """Mixin that runs NSE installer after pip install or pip install -e."""

    def _run_nse_install(self) -> None:
        try:
            from mikrotikapi_bf.nse_installer import install_nse
            print("\n  [mikrotikapi-bf] Installing NSE scripts to Nmap...")
            install_nse(verbose=True)
        except Exception as exc:
            print(f"  [mikrotikapi-bf] NSE auto-install skipped: {exc}")
            print("  Run manually: mikrotikapi-install-nse")


class PostInstall(_PostInstallMixin, install):
    """pip install hook."""

    def run(self) -> None:
        install.run(self)
        self._run_nse_install()


class PostDevelop(_PostInstallMixin, develop):
    """pip install -e hook."""

    def run(self) -> None:
        develop.run(self)
        self._run_nse_install()


setup(
    cmdclass={
        "install": PostInstall,
        "develop": PostDevelop,
    },
)
