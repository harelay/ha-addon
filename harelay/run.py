#!/usr/bin/env python3
"""
HARelay Tunnel Client for Home Assistant Add-on

Features:
- Web UI for device pairing (via ingress)
- WebSocket tunnel to HARelay server
- HTTP and WebSocket proxying to Home Assistant
"""

import asyncio
import json
import logging
import os
import signal
import sys
import time
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urljoin

try:
    import aiohttp
    from aiohttp import web
except ImportError:
    print("ERROR: aiohttp not installed")
    sys.exit(1)

try:
    import websockets
    from websockets.extensions.permessage_deflate import ClientPerMessageDeflateFactory, PerMessageDeflate
except ImportError:
    print("ERROR: websockets not installed")
    sys.exit(1)

# MessagePack for binary protocol
import msgpack

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


class PermissiveDeflateFactory(ClientPerMessageDeflateFactory):
    """
    Permissive permessage-deflate factory for HA ingress WebSockets.
    HA's ingress system has quirks with deflate negotiation - this handles them gracefully.
    """
    def process_response_params(self, params, accepted_extensions):
        if not params:
            return PerMessageDeflate(
                remote_no_context_takeover=False,
                local_no_context_takeover=False,
                remote_max_window_bits=15,
                local_max_window_bits=15,
            )
        return super().process_response_params(params, accepted_extensions)


def extract_response_headers(resp) -> dict:
    """
    Extract headers from aiohttp response, preserving multiple values.
    aiohttp's dict(resp.headers) loses duplicate headers like Set-Cookie.
    """
    headers = {}
    for key, value in resp.headers.items():
        if key in headers:
            if isinstance(headers[key], list):
                headers[key].append(value)
            else:
                headers[key] = [headers[key], value]
        else:
            headers[key] = value
    return headers

# Home Assistant URLs
HA_HTTP_URL = 'http://localhost:8123'
HA_WS_URL = 'ws://localhost:8123'

# Template directory
TEMPLATE_DIR = Path(__file__).parent / 'templates'

# Template cache (loaded once at startup)
_template_cache: dict[str, str] = {}
_template_cache_lock = asyncio.Lock()


async def load_template(name: str) -> str:
    """Load a template from file. Caches templates for performance."""
    async with _template_cache_lock:
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
        self._tunnel_task: asyncio.Task | None = None
        self._pairing_task: asyncio.Task | None = None

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
                self._start_pairing_task()
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

        html = await load_template('pairing')
        html = html.replace('{{USER_CODE}}', self.user_code or 'Loading...')
        html = html.replace('{{VERIFICATION_URL}}', f'{self.server_url}/link')
        html = html.replace('{{EXPIRES_IN}}', str(expires_in))

        return web.Response(text=html, content_type='text/html')

    async def handle_unlinked_page(self, request: web.Request) -> web.Response:
        """Show unlinked page with option to start pairing."""
        html = await load_template('unlinked')
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

        html = await load_template('status')
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
        # Cancel tunnel task if running
        if self._tunnel_task and not self._tunnel_task.done():
            self._tunnel_task.cancel()
            try:
                await self._tunnel_task
            except asyncio.CancelledError:
                pass

        self._save_credentials('', '')
        self.subdomain = ''
        self.token = ''
        self.status = 'unlinked'
        self.user_code = None
        self.status_message = 'Device unlinked. Restart the add-on or click Relink to pair again.'
        return web.json_response({'ok': True})

    async def handle_api_relink(self, request: web.Request) -> web.Response:
        """Reset credentials and start re-pairing."""
        # Cancel tunnel task if running
        if self._tunnel_task and not self._tunnel_task.done():
            self._tunnel_task.cancel()
            try:
                await self._tunnel_task
            except asyncio.CancelledError:
                pass

        self._save_credentials('', '')
        self.subdomain = ''
        self.token = ''
        self.status = 'pairing'
        self.user_code = None
        self._start_pairing_task()
        return web.json_response({'ok': True})

    def _start_pairing_task(self):
        """Start pairing task, cancelling any existing one."""
        if self._pairing_task and not self._pairing_task.done():
            self._pairing_task.cancel()
        self._pairing_task = asyncio.create_task(self.start_pairing())

    def _start_tunnel_task(self):
        """Start tunnel task, cancelling any existing one."""
        if self._tunnel_task and not self._tunnel_task.done():
            self._tunnel_task.cancel()
        self._tunnel_task = asyncio.create_task(self.run_tunnel())

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
                    except asyncio.CancelledError:
                        raise
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
                            self._start_tunnel_task()
                            return

                        if data.get('status') == 'expired':
                            self.status = 'expired'
                            return

                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        pass

                self.status = 'expired'
        except asyncio.CancelledError:
            logger.info('Pairing cancelled')
            raise
        except Exception as e:
            logger.error(f'Pairing error: {e}')
            self.status = 'error'
            self.status_message = str(e)

    # ==================== Tunnel ====================

    def _on_subdomain_changed(self, new_subdomain: str):
        """Called when server notifies us of a subdomain change."""
        self.subdomain = new_subdomain

    async def run_tunnel(self):
        """Main tunnel loop with reconnection."""
        self.status = 'connecting'

        while self.running and self.is_configured:
            tunnel = TunnelClient(
                subdomain=self.subdomain,
                token=self.token,
                supervisor_token=self.supervisor_token,
                on_subdomain_changed=self._on_subdomain_changed
            )

            try:
                if await tunnel.connect():
                    self.status = 'connected'
                    logger.info(f'Connected - https://{self.subdomain}.harelay.com')
                    await tunnel.run()
                    self.status = 'disconnected'
                    self.status_message = 'Connection lost'
                else:
                    self.status = 'disconnected'
                    self.status_message = tunnel.last_error or 'Connection failed'
            except asyncio.CancelledError:
                logger.info('Tunnel cancelled')
                await tunnel.shutdown()
                raise
            finally:
                await tunnel.shutdown()

            # Only reconnect if still running
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
            self._start_tunnel_task()
        else:
            self._start_pairing_task()

        # Keep running
        try:
            while self.running:
                await asyncio.sleep(1)
        finally:
            # Clean shutdown
            if self._tunnel_task and not self._tunnel_task.done():
                self._tunnel_task.cancel()
                try:
                    await self._tunnel_task
                except asyncio.CancelledError:
                    pass
            if self._pairing_task and not self._pairing_task.done():
                self._pairing_task.cancel()
                try:
                    await self._pairing_task
                except asyncio.CancelledError:
                    pass
            await runner.cleanup()

    def stop(self):
        logger.info('Shutting down...')
        self.running = False


class LRUCache:
    """Simple LRU cache with size tracking."""

    def __init__(self, max_size: int):
        self.max_size = max_size
        self.cache: OrderedDict[str, tuple[int, dict, bytes]] = OrderedDict()
        self.current_size = 0
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> tuple[int, dict, bytes] | None:
        async with self._lock:
            if key in self.cache:
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                return self.cache[key]
            return None

    async def put(self, key: str, value: tuple[int, dict, bytes]):
        async with self._lock:
            item_size = len(value[2])

            # Don't cache items larger than max size
            if item_size > self.max_size:
                return

            # Remove existing entry if present
            if key in self.cache:
                old_size = len(self.cache[key][2])
                self.current_size -= old_size
                del self.cache[key]

            # Evict LRU entries until we have space
            while self.current_size + item_size > self.max_size and self.cache:
                oldest_key, oldest_value = self.cache.popitem(last=False)
                self.current_size -= len(oldest_value[2])

            # Add new entry
            self.cache[key] = value
            self.current_size += item_size


class TunnelClient:
    """WebSocket tunnel client."""

    # Health check: force reconnect if no server response within this time
    HEALTH_CHECK_TIMEOUT = 60  # seconds

    # Static file cache settings
    CACHE_MAX_SIZE = 100 * 1024 * 1024  # 100MB max cache size
    CACHE_PATHS = ('/frontend_latest/', '/static/', '/hacsfiles/')

    def __init__(self, subdomain: str, token: str, supervisor_token: str = None, on_subdomain_changed: callable = None):
        self.subdomain = subdomain
        self.token = token
        self.supervisor_token = supervisor_token
        self.on_subdomain_changed = on_subdomain_changed
        self.ws = None
        self.running = True
        self.ws_streams: dict[str, websockets.WebSocketClientProtocol] = {}
        self.ws_pending: dict[str, list[str]] = {}
        self._ws_locks: dict[str, asyncio.Lock] = {}
        self._locks_lock = asyncio.Lock()  # Lock for creating stream locks
        self.last_error = None
        self.http_connector: aiohttp.TCPConnector | None = None
        self.last_server_response = time.time()
        self.static_cache = LRUCache(self.CACHE_MAX_SIZE)
        self._shutdown_event = asyncio.Event()
        self._active_tasks: set[asyncio.Task] = set()

    def get_ws_url(self) -> str:
        """Get WebSocket URL for tunnel connection."""
        return 'wss://harelay.com/tunnel'

    async def connect(self) -> bool:
        ws_url = self.get_ws_url()
        logger.info(f'Connecting to {ws_url}...')

        try:
            self.ws = await websockets.connect(ws_url, ping_interval=20, ping_timeout=10)

            # Send auth (MessagePack binary)
            await self.send({'type': 'auth', 'subdomain': self.subdomain, 'token': self.token})

            # Wait for auth response
            response = await asyncio.wait_for(self.recv(), timeout=10)

            if response.get('type') == 'auth_result' and response.get('success'):
                return True

            self.last_error = response.get('error', 'Auth failed')
            return False
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.last_error = str(e)
            return False

    async def send(self, message: dict):
        if self.ws:
            await self.ws.send(msgpack.packb(message, use_bin_type=True))

    async def recv(self) -> dict:
        data = await self.ws.recv()
        return msgpack.unpackb(data, raw=False)

    async def shutdown(self):
        """Gracefully shutdown all connections."""
        self.running = False
        self._shutdown_event.set()

        # Cancel all active tasks
        for task in list(self._active_tasks):
            task.cancel()

        if self._active_tasks:
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
        self._active_tasks.clear()

        # Close all WebSocket streams
        for stream_id, ws in list(self.ws_streams.items()):
            try:
                await ws.close()
            except Exception:
                pass
        self.ws_streams.clear()
        self.ws_pending.clear()
        self._ws_locks.clear()

        # Close main WebSocket
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
        self.ws = None

        # Close HTTP connector
        if self.http_connector:
            await self.http_connector.close()
            self.http_connector = None

    async def run(self):
        self.http_connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=100,
        )
        self.last_server_response = time.time()
        self._shutdown_event.clear()

        try:
            results = await asyncio.gather(
                self.heartbeat_loop(),
                self.message_loop(),
                self.health_check_loop(),
                return_exceptions=True
            )
            # Log any exceptions that occurred
            loop_names = ['heartbeat_loop', 'message_loop', 'health_check_loop']
            for i, result in enumerate(results):
                if isinstance(result, Exception) and not isinstance(result, asyncio.CancelledError):
                    logger.error(f'{loop_names[i]} exited with error: {result}')
        except asyncio.CancelledError:
            logger.info('Tunnel run cancelled')
            raise

    async def heartbeat_loop(self):
        while self.running and self.ws:
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=30
                )
                break  # Shutdown requested
            except asyncio.TimeoutError:
                pass  # Normal timeout, send heartbeat

            try:
                await self.send({'type': 'heartbeat'})
            except websockets.exceptions.ConnectionClosed as e:
                logger.warning(f'Heartbeat: connection closed (code={e.code}, reason={e.reason})')
                self._shutdown_event.set()  # Wake up other loops
                break
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f'Heartbeat error: {e}')
                self._shutdown_event.set()  # Wake up other loops
                break
        logger.info('Heartbeat loop exited')

    async def health_check_loop(self):
        """Monitor connection health and force reconnect if server stops responding."""
        while self.running and self.ws:
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=10
                )
                break  # Shutdown requested
            except asyncio.TimeoutError:
                pass  # Normal timeout, check health

            time_since_response = time.time() - self.last_server_response
            if time_since_response > self.HEALTH_CHECK_TIMEOUT:
                logger.warning(f'Connection unhealthy: no server response for {time_since_response:.0f}s, forcing reconnect')
                self._shutdown_event.set()  # Wake up other loops
                if self.ws:
                    try:
                        await self.ws.close()
                    except Exception:
                        pass
                break
        logger.info('Health check loop exited')

    async def message_loop(self):
        while self.running and self.ws:
            try:
                message = await asyncio.wait_for(self.recv(), timeout=60)
                self.last_server_response = time.time()
                msg_type = message.get('type', '')

                if msg_type == 'request':
                    task = asyncio.create_task(self.handle_request(message))
                    self._active_tasks.add(task)
                    task.add_done_callback(self._active_tasks.discard)
                elif msg_type == 'ws_open':
                    task = asyncio.create_task(self.handle_ws_open(message))
                    self._active_tasks.add(task)
                    task.add_done_callback(self._active_tasks.discard)
                elif msg_type == 'ws_message':
                    task = asyncio.create_task(self.handle_ws_message(message))
                    self._active_tasks.add(task)
                    task.add_done_callback(self._active_tasks.discard)
                elif msg_type == 'ws_close':
                    task = asyncio.create_task(self.handle_ws_close(message))
                    self._active_tasks.add(task)
                    task.add_done_callback(self._active_tasks.discard)
                elif msg_type == 'subdomain_changed':
                    self.handle_subdomain_changed(message)
                elif msg_type == 'pong':
                    pass  # Heartbeat response, connection is alive
                elif msg_type == 'ping':
                    await self.send({'type': 'pong'})
                elif msg_type == 'error':
                    logger.error(f'Server error: {message.get("error")}')

            except asyncio.TimeoutError:
                try:
                    await self.send({'type': 'heartbeat'})
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.warning(f'Connection dead (heartbeat failed): {e}')
                    self._shutdown_event.set()  # Wake up other loops
                    break
            except asyncio.CancelledError:
                raise
            except websockets.exceptions.ConnectionClosed as e:
                logger.warning(f'Connection closed (code={e.code}, reason={e.reason})')
                self._shutdown_event.set()  # Wake up other loops
                break
            except Exception as e:
                logger.error(f'Message loop error: {e}')
                await asyncio.sleep(1)
        logger.info('Message loop exited')

    async def handle_request(self, message: dict):
        request_id = message.get('request_id')
        method = message.get('method', 'GET')
        uri = message.get('uri', '/')
        headers = message.get('headers', {})
        body = message.get('body')

        # Body arrives as raw bytes from MessagePack
        if body and not isinstance(body, bytes):
            body = body.encode() if isinstance(body, str) else bytes(body)

        url = urljoin(HA_HTTP_URL, uri)
        skip_headers = {'host', 'content-length', 'transfer-encoding', 'accept-encoding'}
        filtered_headers = {k: v for k, v in headers.items() if k.lower() not in skip_headers}

        if not uri.startswith('/auth/'):
            original_auth = headers.get('Authorization') or headers.get('authorization')
            if original_auth:
                filtered_headers['Authorization'] = original_auth
            elif self.supervisor_token:
                filtered_headers['Authorization'] = f'Bearer {self.supervisor_token}'

        is_streaming = '/follow' in uri or headers.get('Accept') == 'text/event-stream'
        is_cacheable = method == 'GET' and any(uri.startswith(p) for p in self.CACHE_PATHS)

        # Check cache first
        if is_cacheable:
            cached = await self.static_cache.get(uri)
            if cached:
                status_code, response_headers, response_bytes = cached
                logger.info(f'REQ CACHE HIT {uri}')
                await self.send({
                    'type': 'response',
                    'request_id': request_id,
                    'status_code': status_code,
                    'headers': response_headers,
                    'body': response_bytes,  # Raw bytes
                })
                return

        logger.info(f'REQ START {uri}')
        status_code = None
        response_bytes = None
        response_headers = None
        last_error = None

        for attempt in range(2):
            try:
                # IMPORTANT: auto_decompress=False keeps responses in original encoding.
                # This ensures Content-Encoding header matches the actual body content.
                # Without this, aiohttp decompresses gzip but headers still say "gzip",
                # causing browsers to fail parsing JS modules.
                async with aiohttp.ClientSession(connector=self.http_connector, connector_owner=False, auto_decompress=False) as session:
                    if is_streaming:
                        timeout = aiohttp.ClientTimeout(total=10, sock_read=3)
                        async with session.request(method=method, url=url, headers=filtered_headers, data=body, timeout=timeout, allow_redirects=False) as resp:
                            status_code = resp.status
                            response_headers = extract_response_headers(resp)
                            chunks = []
                            total_size = 0
                            try:
                                async for chunk in resp.content.iter_chunked(8192):
                                    chunks.append(chunk)
                                    total_size += len(chunk)
                                    if total_size >= 1024 * 1024:
                                        break
                            except asyncio.TimeoutError:
                                pass
                            response_bytes = b''.join(chunks)
                    else:
                        timeout = aiohttp.ClientTimeout(total=None, connect=10, sock_read=55)
                        async with session.request(method=method, url=url, headers=filtered_headers, data=body, timeout=timeout, allow_redirects=False) as resp:
                            status_code = resp.status
                            response_bytes = await resp.read()
                            response_headers = extract_response_headers(resp)
                break

            except (aiohttp.ClientPayloadError, aiohttp.ServerDisconnectedError,
                    aiohttp.ClientOSError, ConnectionResetError) as e:
                last_error = e
                if attempt == 0:
                    logger.warning(f'Request {uri} failed ({type(e).__name__}), retrying...')
                    await asyncio.sleep(0.05)
                    continue
            except asyncio.TimeoutError:
                status_code = 504
                response_bytes = b'Gateway Timeout'
                response_headers = {'Content-Type': 'text/plain'}
                break

            except asyncio.CancelledError:
                raise

            except Exception as e:
                last_error = e
                break

        if last_error:
            logger.error(f'Request {uri} failed: {last_error}')
            status_code = 502
            response_bytes = f'Bad Gateway: {type(last_error).__name__}'.encode()
            response_headers = {'Content-Type': 'text/plain'}

        # Cache successful static file responses
        if is_cacheable and status_code == 200 and response_bytes:
            await self.static_cache.put(uri, (status_code, response_headers, response_bytes))
            logger.info(f'REQ CACHED {uri} ({len(response_bytes)} bytes)')

        logger.info(f'REQ DONE {uri} -> {status_code}')
        await self.send({
            'type': 'response',
            'request_id': request_id,
            'status_code': status_code,
            'headers': response_headers,
            'body': response_bytes,  # Raw bytes
        })

    async def _get_stream_lock(self, stream_id: str) -> asyncio.Lock:
        """Get or create a lock for a stream."""
        async with self._locks_lock:
            if stream_id not in self._ws_locks:
                self._ws_locks[stream_id] = asyncio.Lock()
            return self._ws_locks[stream_id]

    async def handle_ws_open(self, message: dict):
        stream_id = message.get('stream_id')
        path = message.get('path', '/api/websocket')
        ingress_session = message.get('ingress_session')

        lock = await self._get_stream_lock(stream_id)
        async with lock:
            self.ws_pending[stream_id] = []

        try:
            if ingress_session:
                logger.info(f'WS OPEN {path} (ingress, session={ingress_session[:20]}...)')

                ws_headers = [('Cookie', f'ingress_session={ingress_session}')]
                ha_ws = await websockets.connect(
                    f'{HA_WS_URL}{path}',
                    additional_headers=ws_headers,
                    extensions=[PermissiveDeflateFactory()],
                )
                logger.info(f'WS CONNECTED {path} (ingress)')
            else:
                ha_ws = await websockets.connect(
                    f'{HA_WS_URL}{path}',
                    ping_interval=20,
                    ping_timeout=10
                )
                logger.info(f'WS CONNECTED {path}')

            async with lock:
                self.ws_streams[stream_id] = ha_ws
                pending = self.ws_pending.pop(stream_id, [])

            # Start listener
            task = asyncio.create_task(self.ws_stream_listener(stream_id, ha_ws))
            self._active_tasks.add(task)
            task.add_done_callback(self._active_tasks.discard)

            # Send pending messages
            if pending:
                logger.info(f'WS SENDING {len(pending)} pending messages')
                for msg in pending:
                    await ha_ws.send(msg)

        except asyncio.CancelledError:
            # Clean up on cancellation
            async with lock:
                self.ws_pending.pop(stream_id, None)
            async with self._locks_lock:
                self._ws_locks.pop(stream_id, None)
            raise
        except Exception as e:
            logger.error(f'WS OPEN FAILED {path}: {e}')
            async with lock:
                self.ws_pending.pop(stream_id, None)
            async with self._locks_lock:
                self._ws_locks.pop(stream_id, None)
            await self.send({'type': 'ws_closed', 'stream_id': stream_id, 'error': str(e)})

    async def ws_stream_listener(self, stream_id: str, ha_ws):
        try:
            msg_count = 0
            async for message in ha_ws:
                msg_count += 1
                if stream_id not in self.ws_streams:
                    logger.warning(f'WS LISTENER {stream_id[:8]}: stream removed, stopping')
                    break
                await self.send({'type': 'ws_message', 'stream_id': stream_id, 'message': message})
            logger.info(f'WS LISTENER {stream_id[:8]}: closed after {msg_count} msgs, code={ha_ws.close_code}, reason={ha_ws.close_reason}')
        except asyncio.CancelledError:
            logger.info(f'WS LISTENER {stream_id[:8]}: cancelled')
            raise
        except Exception as e:
            logger.error(f'WS LISTENER {stream_id[:8]}: error: {e}')
        finally:
            lock = await self._get_stream_lock(stream_id)
            async with lock:
                self.ws_streams.pop(stream_id, None)
            # Clean up the lock
            async with self._locks_lock:
                self._ws_locks.pop(stream_id, None)
            try:
                await self.send({'type': 'ws_closed', 'stream_id': stream_id})
            except Exception:
                pass

    async def handle_ws_message(self, message: dict):
        stream_id = message.get('stream_id')
        ws_message = message.get('message', '')

        lock = await self._get_stream_lock(stream_id)
        async with lock:
            if stream_id in self.ws_streams:
                try:
                    ws = self.ws_streams[stream_id]
                    await ws.send(ws_message)
                except Exception as e:
                    logger.error(f'WS MSG SEND FAILED {stream_id[:8]}: {e}')
            elif stream_id in self.ws_pending:
                self.ws_pending[stream_id].append(ws_message)
            else:
                logger.warning(f'WS MSG DROPPED {stream_id[:8]}: no stream or pending')

    async def handle_ws_close(self, message: dict):
        stream_id = message.get('stream_id')

        lock = await self._get_stream_lock(stream_id)
        async with lock:
            self.ws_pending.pop(stream_id, None)
            ws = self.ws_streams.pop(stream_id, None)

        if ws:
            try:
                await ws.close()
            except Exception:
                pass

        # Clean up lock (synchronized)
        async with self._locks_lock:
            self._ws_locks.pop(stream_id, None)

    def handle_subdomain_changed(self, message: dict):
        """Handle subdomain change notification from server."""
        old_subdomain = message.get('old_subdomain')
        new_subdomain = message.get('new_subdomain')
        logger.info(f'Subdomain changed: {old_subdomain} -> {new_subdomain}')

        self.subdomain = new_subdomain

        try:
            CREDENTIALS_FILE.write_text(json.dumps({
                'subdomain': new_subdomain,
                'connection_token': self.token
            }))
            logger.info(f'Credentials updated with new subdomain: {new_subdomain}')
        except Exception as e:
            logger.error(f'Failed to save updated credentials: {e}')

        if self.on_subdomain_changed:
            self.on_subdomain_changed(new_subdomain)


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
    logger.info('HARelay Add-on starting')
    config = load_config()
    logger.info(f'Config loaded: {list(config.keys())}')

    addon = HARelayAddon(config)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, addon.stop)

    await addon.run()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f'Fatal error: {e}')
        sys.exit(1)