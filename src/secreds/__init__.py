"""seCreds: a local credential broker for AI agents. Made by henderlabs."""
__version__ = "0.6.4"
PRODUCT = "seCreds"
MAKER = "henderlabs"
REPO = "henderlabs/secreds"
HOMEPAGE = f"https://github.com/{REPO}"
FEEDBACK_URL = f"https://github.com/{REPO}/issues/new/choose"


def signature():
    """The one-line signature used everywhere seCreds puts its name: the app, the command line, files it makes."""
    return f"{PRODUCT} {__version__} by {MAKER}"
