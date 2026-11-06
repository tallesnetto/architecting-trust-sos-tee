"""Version 2.0 of the trusted application, used as the agreed update (EV1)."""
from .trusted_app import TrustedGatewayApp


class TrustedGatewayAppV2(TrustedGatewayApp):
    VERSION = "2.0"
