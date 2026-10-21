"""Only the integration compose mounts this harness. Production never redirects.
Real HTTP uses the loopback fixture; unexpected external network is denied.
"""
import sys
sys.path.insert(0, '/app')
import importlib
import uvicorn
from api.providers.http import JsonTransport, ProviderError


class FixtureTransport(JsonTransport):
    def request(self, method, base, path, **kwargs):
        if base == 'https://api.cloudflare.com/client/v4':
            base = 'http://127.0.0.1:19123/cloudflare/client/v4'
        if not base.startswith('http://127.0.0.1:19123'):
            raise ProviderError('integration_external_provider_network_denied')
        return super().request(method, base, path, **kwargs)


if __name__ == '__main__':
    application = importlib.import_module('api.app')
    application.domain_manager.http = FixtureTransport()
    uvicorn.run(application.app, host='0.0.0.0', port=8000, workers=1)
