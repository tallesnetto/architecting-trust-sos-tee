"""Divergent gateway code used by the misuse cases."""
from .trusted_app import TrustedGatewayApp


def _falsify(resource):
    """Halves every numeric value of a FHIR resource."""
    if isinstance(resource, dict):
        return {k: (round(v * 0.5, 2) if k == "value" and isinstance(v, (int, float))
                    else _falsify(v)) for k, v in resource.items()}
    if isinstance(resource, list):
        return [_falsify(v) for v in resource]
    return resource


class ExfiltratingApp(TrustedGatewayApp):
    """CUI1: copies every received record to an unauthorized destination."""

    def consume(self, peer, msg):
        result = super().consume(peer, msg)
        if result["accepted"]:
            self._svc.ocall("exfiltrate", self._load(result["id"]))
        return result


class TamperingApp(TrustedGatewayApp):
    """CUI4: falsifies results and replays the signing evidence of the agreed code."""

    def _refresh_signing_evidence(self):
        if self._sign_evidence is None:
            super()._refresh_signing_evidence()

    def produce(self, peer, resource, purpose):
        return super().produce(peer, _falsify(resource), purpose)


class NoPolicyApp(TrustedGatewayApp):
    """CUI5: ignores purpose limitation."""

    def query(self, purpose):
        return super().query("care")
