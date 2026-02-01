#!/usr/bin/env python3
"""
HARelay Tunnel Client for Home Assistant Add-on

Features:
- Web UI for device pairing (via ingress)
- WebSocket tunnel to HARelay server
- HTTP and WebSocket proxying to Home Assistant
"""

import asyncio
import base64
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
    from aiohttp import web
except ImportError:
    print("ERROR: aiohttp not installed")
    sys.exit(1)

try:
    import websockets
except ImportError:
    print("ERROR: websockets not installed")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Home Assistant URLs
HA_HTTP_URL = 'http://localhost:8123'
HA_WS_URL = 'ws://localhost:8123'

# Template directory
TEMPLATE_DIR = Path(__file__).parent / 'templates'

# Template cache
_template_cache: dict[str, str] = {}

def load_template(name: str) -> str:
    """Load a template from file. Caches templates for performance."""
    if name not in _template_cache:
        template_path = TEMPLATE_DIR / f'{name}.html'
        try:
            _template_cache[name] = template_path.read_text()
        except Exception as e:
            logger.error(f'Failed to load template {name}: {e}')
            _template_cache[name] = f'<html><body><h1>Error</h1><p>Template {name} not found</p></body></html>'
    return _template_cache[name]


CREDENTIALS_FILE = Path('/data/credentials.json')


class HARelayAddon:
    """Main add-on class handling both web UI and tunnel."""

    def __init__(self, config: dict):
        self.config = config
        self.server_url = 'https://harelay.com'
        self.supervisor_token = os.environ.get('SUPERVISOR_TOKEN')

        # Load credentials from file (not from options - keeps them hidden from UI)
        credentials = self._load_credentials()
        self.subdomain = credentials.get('subdomain', '').strip()
        self.token = credentials.get('connection_token', '').strip()

        # State
        self.status = 'initializing'
        self.status_message = ''
        self.device_code = None
        self.user_code = None
        self.code_expires_at = 0
        self.running = True

        logger.info(f'Server URL: {self.server_url}')
        logger.info(f'Configured: {self.is_configured}')

    def _load_credentials(self) -> dict:
        """Load credentials from file."""
        if CREDENTIALS_FILE.exists():
            try:
                return json.loads(CREDENTIALS_FILE.read_text())
            except Exception as e:
                logger.error(f'Failed to load credentials: {e}')
        return {}

    def _save_credentials(self, subdomain: str, token: str) -> bool:
        """Save credentials to file."""
        try:
            CREDENTIALS_FILE.write_text(json.dumps({
                'subdomain': subdomain,
                'connection_token': token
            }))
            logger.info('Credentials saved')
            return True
        except Exception as e:
            logger.error(f'Failed to save credentials: {e}')
            return False

    @property
    def is_configured(self) -> bool:
        return bool(self.subdomain and self.token)

    # ==================== Web Handlers ====================

    async def handle_index(self, request: web.Request) -> web.Response:
        """Main page - show pairing or status."""
        if not self.is_configured:
            # Don't auto-start pairing if user manually unlinked
            if self.status not in ('pairing', 'error', 'unlinked'):
                asyncio.create_task(self.start_pairing())
            # Show unlinked page if manually unlinked
            if self.status == 'unlinked':
                return await self.handle_unlinked_page(request)
            return await self.handle_pairing_page(request)
        return await self.handle_status_page(request)

    async def handle_pairing_page(self, request: web.Request) -> web.Response:
        """Show pairing page with code."""
        # Wait for code if not ready yet
        for _ in range(50):
            if self.user_code:
                break
            await asyncio.sleep(0.1)

        expires_in = max(0, int(self.code_expires_at - time.time()))

        html = load_template('pairing')
        html = html.replace('{{USER_CODE}}', self.user_code or 'Loading...')
        html = html.replace('{{VERIFICATION_URL}}', f'{self.server_url}/link')
        html = html.replace('{{EXPIRES_IN}}', str(expires_in))

        return web.Response(text=html, content_type='text/html')

    async def handle_unlinked_page(self, request: web.Request) -> web.Response:
        """Show unlinked page with option to start pairing."""
        html = load_template('unlinked')
        return web.Response(text=html, content_type='text/html')

    async def handle_status_page(self, request: web.Request) -> web.Response:
        """Show connection status page."""
        if self.status == 'connected':
            status_class, emoji, title = 'connected', '✓', 'Connected'
            subtitle = 'Your Home Assistant is accessible remotely'
        elif self.status == 'connecting':
            status_class, emoji, title = 'connecting pulse', '⟳', 'Connecting...'
            subtitle = 'Establishing tunnel connection'
        elif self.status == 'initializing':
            status_class, emoji, title = 'initializing spin', '⟳', 'Starting...'
            subtitle = 'Initializing add-on, please wait'
        else:
            status_class, emoji, title = 'disconnected', '✗', 'Disconnected'
            subtitle = self.status_message or 'Tunnel is not connected'

        html = load_template('status')
        html = html.replace('{{STATUS_CLASS}}', status_class)
        html = html.replace('{{STATUS_EMOJI}}', emoji)
        html = html.replace('{{STATUS_TITLE}}', title)
        html = html.replace('{{STATUS_SUBTITLE}}', subtitle)
        html = html.replace('{{SUBDOMAIN}}', self.subdomain)
        html = html.replace('{{SERVER_URL}}', self.server_url)

        return web.Response(text=html, content_type='text/html')

    async def handle_api_status(self, request: web.Request) -> web.Response:
        """API endpoint for status polling."""
        if self.status == 'connected':
            data = {'status': 'connected', 'status_class': 'connected', 'emoji': '✓', 'title': 'Connected', 'subtitle': 'Your Home Assistant is accessible remotely'}
        elif self.status == 'connecting':
            data = {'status': 'connecting', 'status_class': 'connecting pulse', 'emoji': '⟳', 'title': 'Connecting...', 'subtitle': 'Establishing tunnel connection'}
        elif self.status == 'initializing':
            data = {'status': 'initializing', 'status_class': 'initializing spin', 'emoji': '⟳', 'title': 'Starting...', 'subtitle': 'Initializing add-on, please wait'}
        elif self.status == 'pairing':
            data = {'status': 'pairing'}
        elif self.status == 'expired':
            data = {'status': 'expired'}
        elif self.status == 'unlinked':
            data = {'status': 'unlinked'}
        else:
            data = {'status': 'disconnected', 'status_class': 'disconnected', 'emoji': '✗', 'title': 'Disconnected', 'subtitle': self.status_message or 'Tunnel is not connected'}
        return web.json_response(data)

    async def handle_api_unlink(self, request: web.Request) -> web.Response:
        """Clear credentials without starting re-pairing."""
        self._save_credentials('', '')
        self.subdomain = ''
        self.token = ''
        self.status = 'unlinked'
        self.user_code = None
        self.status_message = 'Device unlinked. Restart the add-on or click Relink to pair again.'
        return web.json_response({'ok': True})

    async def handle_api_relink(self, request: web.Request) -> web.Response:
        """Reset credentials and start re-pairing."""
        self._save_credentials('', '')
        self.subdomain = ''
        self.token = ''
        self.status = 'pairing'
        self.user_code = None
        asyncio.create_task(self.start_pairing())
        return web.json_response({'ok': True})

    # ==================== Pairing ====================

    async def start_pairing(self):
        """Request device code and poll until linked."""
        self.status = 'pairing'
        self.user_code = None
        logger.info('Starting device pairing...')

        try:
            async with aiohttp.ClientSession() as session:
                # Request device code with retry for rate limiting
                data = None
                retry_delay = 5  # Start with 5 seconds
                max_retries = 10

                for attempt in range(max_retries):
                    if not self.running:
                        return

                    try:
                        async with session.post(
                            f'{self.server_url}/api/device/code',
                            json={'device_name': 'Home Assistant'},
                            timeout=aiohttp.ClientTimeout(total=15),
                            allow_redirects=True
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                break
                            elif resp.status == 429:
                                # Rate limited - check Retry-After header or use backoff
                                retry_after = resp.headers.get('Retry-After')
                                if retry_after:
                                    try:
                                        retry_delay = int(retry_after)
                                    except ValueError:
                                        pass
                                logger.warning(f'Rate limited, retrying in {retry_delay}s...')
                                await asyncio.sleep(retry_delay)
                                retry_delay = min(retry_delay * 2, 60)  # Exponential backoff, max 60s
                                continue
                            else:
                                logger.error(f'Failed to get device code: HTTP {resp.status}')
                                self.status = 'error'
                                self.status_message = f'Server returned {resp.status}'
                                return
                    except aiohttp.ClientError as e:
                        logger.error(f'Failed to connect: {e}')
                        if attempt < max_retries - 1:
                            logger.info(f'Retrying in {retry_delay}s...')
                            await asyncio.sleep(retry_delay)
                            retry_delay = min(retry_delay * 2, 60)
                            continue
                        self.status = 'error'
                        self.status_message = f'Cannot reach {self.server_url}'
                        return

                if not data:
                    logger.error('Failed to get device code after max retries')
                    self.status = 'error'
                    self.status_message = 'Rate limit exceeded, please try again later'
                    return

                self.device_code = data['device_code']
                self.user_code = data['user_code']
                expires_in = data['expires_in']
                interval = data['interval']
                self.code_expires_at = time.time() + expires_in

                logger.info(f'Pairing code: {self.user_code}')

                # Poll for completion
                max_polls = expires_in // interval
                for _ in range(max_polls):
                    if not self.running or self.status != 'pairing':
                        return

                    await asyncio.sleep(interval)

                    try:
                        async with session.get(
                            f'{self.server_url}/api/device/poll/{self.device_code}',
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            data = await resp.json()

                        if data.get('status') == 'linked':
                            logger.info('Pairing successful!')
                            self.subdomain = data['subdomain']
                            self.token = data['token']
                            self._save_credentials(self.subdomain, self.token)
                            self.status = 'connecting'
                            asyncio.create_task(self.run_tunnel())
                            return

                        if data.get('status') == 'expired':
                            self.status = 'expired'
                            return

                    except Exception:
                        pass

                self.status = 'expired'
        except Exception as e:
            logger.error(f'Pairing error: {e}')
            self.status = 'error'
            self.status_message = str(e)

    # ==================== Tunnel ====================

    async def run_tunnel(self):
        """Main tunnel loop with reconnection."""
        self.status = 'connecting'

        while self.running and self.is_configured:
            tunnel = TunnelClient(
                subdomain=self.subdomain,
                token=self.token,
                supervisor_token=self.supervisor_token
            )

            if await tunnel.connect():
                self.status = 'connected'
                logger.info(f'Connected - https://{self.subdomain}.harelay.com')
                await tunnel.run()
                self.status = 'disconnected'
                self.status_message = 'Connection lost'
            else:
                self.status = 'disconnected'
                self.status_message = tunnel.last_error or 'Connection failed'

            if self.running and self.is_configured:
                logger.info('Reconnecting in 5 seconds...')
                await asyncio.sleep(5)

    # ==================== Main ====================

    async def run(self):
        """Start the add-on."""
        logger.info('Starting web server on port 8099...')

        app = web.Application()
        app.router.add_get('/', self.handle_index)
        app.router.add_get('/api/status', self.handle_api_status)
        app.router.add_post('/api/unlink', self.handle_api_unlink)
        app.router.add_post('/api/relink', self.handle_api_relink)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', 8099)
        await site.start()
        logger.info('Web UI ready on port 8099')

        # Start tunnel if configured, otherwise start pairing
        if self.is_configured:
            self.status = 'connecting'
            asyncio.create_task(self.run_tunnel())
        else:
            asyncio.create_task(self.start_pairing())

        # Keep running
        while self.running:
            await asyncio.sleep(1)

        await runner.cleanup()

    def stop(self):
        logger.info('Shutting down...')
        self.running = False


class TunnelClient:
    """WebSocket tunnel client."""

    def __init__(self, subdomain: str, token: str, supervisor_token: str = None):
        self.subdomain = subdomain
        self.token = token
        self.supervisor_token = supervisor_token
        self.ws = None
        self.running = True
        self.ws_streams = {}
        self.ws_pending = {}
        self.last_error = None

    def get_ws_url(self) -> str:
        """Get WebSocket URL for tunnel connection."""
        return 'wss://harelay.com/tunnel'

    async def connect(self) -> bool:
        ws_url = self.get_ws_url()
        logger.info(f'Connecting to {ws_url}...')

        try:
            self.ws = await websockets.connect(ws_url, ping_interval=20, ping_timeout=10)
            await self.send({'type': 'auth', 'subdomain': self.subdomain, 'token': self.token})
            response = await asyncio.wait_for(self.recv(), timeout=10)

            if response.get('type') == 'auth_result' and response.get('success'):
                return True

            self.last_error = response.get('error', 'Auth failed')
            return False
        except Exception as e:
            self.last_error = str(e)
            return False

    async def send(self, message: dict):
        if self.ws:
            await self.ws.send(json.dumps(message))

    async def recv(self) -> dict:
        data = await self.ws.recv()
        return json.loads(data)

    async def run(self):
        try:
            await asyncio.gather(self.heartbeat_loop(), self.message_loop(), return_exceptions=True)
        finally:
            for ws in self.ws_streams.values():
                try:
                    await ws.close()
                except Exception:
                    pass
            self.ws_streams.clear()
            if self.ws:
                try:
                    await self.ws.close()
                except Exception:
                    pass

    async def heartbeat_loop(self):
        while self.running and self.ws:
            try:
                await self.send({'type': 'heartbeat'})
                await asyncio.sleep(30)  # Heartbeat every 30 seconds
            except Exception:
                break

    async def message_loop(self):
        while self.running and self.ws:
            try:
                message = await asyncio.wait_for(self.recv(), timeout=60)
                msg_type = message.get('type', '')

                if msg_type == 'request':
                    asyncio.create_task(self.handle_request(message))
                elif msg_type == 'ws_open':
                    asyncio.create_task(self.handle_ws_open(message))
                elif msg_type == 'ws_message':
                    asyncio.create_task(self.handle_ws_message(message))
                elif msg_type == 'ws_close':
                    asyncio.create_task(self.handle_ws_close(message))
                elif msg_type == 'error':
                    logger.error(f'Server: {message.get("error")}')

            except asyncio.TimeoutError:
                await self.send({'type': 'heartbeat'})
            except websockets.exceptions.ConnectionClosed:
                break
            except Exception as e:
                logger.error(f'Error: {e}')
                await asyncio.sleep(1)

    async def handle_request(self, message: dict):
        request_id = message.get('request_id')
        method = message.get('method', 'GET')
        uri = message.get('uri', '/')
        headers = message.get('headers', {})
        body = message.get('body')

        if body and message.get('body_encoded'):
            body = base64.b64decode(body)
        elif body:
            body = body.encode()

        try:
            async with aiohttp.ClientSession() as session:
                url = urljoin(HA_HTTP_URL, uri)
                # Filter out headers that shouldn't be forwarded
                skip_headers = {'host', 'content-length', 'transfer-encoding', 'accept-encoding', 'authorization'}
                filtered_headers = {k: v for k, v in headers.items() if k.lower() not in skip_headers}
                filtered_headers['Accept-Encoding'] = 'identity'
                # Use Supervisor token for all requests (except auth endpoints which handle their own auth)
                if self.supervisor_token and not uri.startswith('/auth/'):
                    filtered_headers['Authorization'] = f'Bearer {self.supervisor_token}'

                async with session.request(method=method, url=url, headers=filtered_headers, data=body, timeout=aiohttp.ClientTimeout(total=55), allow_redirects=False) as resp:
                    status_code = resp.status
                    response_bytes = await resp.read()
                    response_headers = dict(resp.headers)
        except asyncio.TimeoutError:
            status_code, response_bytes, response_headers = 504, b'Gateway Timeout', {'Content-Type': 'text/plain'}
        except Exception as e:
            status_code, response_bytes, response_headers = 502, f'Bad Gateway: {e}'.encode(), {'Content-Type': 'text/plain'}

        await self.send({'type': 'response', 'request_id': request_id, 'status_code': status_code, 'headers': response_headers, 'body': base64.b64encode(response_bytes).decode('ascii')})

    async def handle_ws_open(self, message: dict):
        stream_id = message.get('stream_id')
        path = message.get('path', '/api/websocket')
        self.ws_pending[stream_id] = []

        try:
            headers = {'Authorization': f'Bearer {self.supervisor_token}'} if self.supervisor_token else {}
            ha_ws = await websockets.connect(f'{HA_WS_URL}{path}', additional_headers=headers, ping_interval=20, ping_timeout=10)
            self.ws_streams[stream_id] = ha_ws
            for msg in self.ws_pending.pop(stream_id, []):
                await ha_ws.send(msg)
            asyncio.create_task(self.ws_stream_listener(stream_id, ha_ws))
        except Exception as e:
            self.ws_pending.pop(stream_id, None)
            await self.send({'type': 'ws_closed', 'stream_id': stream_id, 'error': str(e)})

    async def ws_stream_listener(self, stream_id: str, ha_ws):
        try:
            async for message in ha_ws:
                if stream_id not in self.ws_streams:
                    break
                await self.send({'type': 'ws_message', 'stream_id': stream_id, 'message': message})
        except Exception:
            pass
        finally:
            self.ws_streams.pop(stream_id, None)
            try:
                await self.send({'type': 'ws_closed', 'stream_id': stream_id})
            except Exception:
                pass

    async def handle_ws_message(self, message: dict):
        stream_id = message.get('stream_id')
        ws_message = message.get('message', '')
        if stream_id in self.ws_streams:
            try:
                await self.ws_streams[stream_id].send(ws_message)
            except Exception:
                pass
        elif stream_id in self.ws_pending:
            self.ws_pending[stream_id].append(ws_message)

    async def handle_ws_close(self, message: dict):
        stream_id = message.get('stream_id')
        self.ws_pending.pop(stream_id, None)
        if stream_id in self.ws_streams:
            try:
                await self.ws_streams.pop(stream_id).close()
            except Exception:
                pass


def load_config() -> dict:
    """Load add-on configuration."""
    options_path = Path('/data/options.json')
    if options_path.exists():
        try:
            return json.loads(options_path.read_text())
        except Exception as e:
            logger.error(f'Config error: {e}')
    return {}


async def main():
    logger.info('HARelay Add-on starting...')
    config = load_config()
    logger.info(f'Config loaded: {list(config.keys())}')

    addon = HARelayAddon(config)

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, addon.stop)

    await addon.run()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f'Fatal error: {e}')
        sys.exit(1)
