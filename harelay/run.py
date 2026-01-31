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

# Embedded templates (fallback if files not found)
PAIRING_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HARelay - Device Pairing</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #fff;
        }
        .container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
        }
        h1 { font-size: 24px; margin-bottom: 10px; }
        .subtitle { color: rgba(255,255,255,0.7); margin-bottom: 30px; }
        .code-box {
            background: rgba(0,0,0,0.3);
            border: 2px solid #03dac6;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
        }
        .code-label { font-size: 12px; text-transform: uppercase; letter-spacing: 2px; color: #03dac6; margin-bottom: 10px; }
        .code { font-family: monospace; font-size: 36px; font-weight: bold; letter-spacing: 4px; }
        .steps { text-align: left; margin: 30px 0; }
        .step { display: flex; align-items: flex-start; margin-bottom: 15px; }
        .step-number { background: #03dac6; color: #1a1a2e; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; margin-right: 15px; flex-shrink: 0; }
        .step-text a { color: #03dac6; }
        .status { display: flex; align-items: center; justify-content: center; margin-top: 20px; color: rgba(255,255,255,0.7); }
        .spinner { width: 20px; height: 20px; border: 2px solid rgba(255,255,255,0.3); border-top-color: #03dac6; border-radius: 50%; animation: spin 1s linear infinite; margin-right: 10px; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .timer { color: rgba(255,255,255,0.5); font-size: 14px; margin-top: 20px; }
        .btn { background: #03dac6; color: #1a1a2e; border: none; padding: 12px 24px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; margin-top: 15px; }
        .error { background: rgba(255,82,82,0.2); border: 1px solid #ff5252; border-radius: 8px; padding: 15px; margin-top: 20px; color: #ff8a80; display: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Link Your Home Assistant</h1>
        <p class="subtitle">Connect HARelay to access your home remotely</p>
        <div class="code-box">
            <div class="code-label">Your Pairing Code</div>
            <div class="code" id="code">{{USER_CODE}}</div>
        </div>
        <div class="steps">
            <div class="step"><div class="step-number">1</div><div class="step-text">Visit <a href="{{VERIFICATION_URL}}" target="_blank">{{VERIFICATION_URL}}</a></div></div>
            <div class="step"><div class="step-number">2</div><div class="step-text">Log in or create a free account</div></div>
            <div class="step"><div class="step-number">3</div><div class="step-text">Enter the pairing code above</div></div>
        </div>
        <div class="status"><div class="spinner"></div><span>Waiting for pairing...</span></div>
        <div class="timer">Code expires in <span id="minutes">15</span> minutes</div>
        <div id="error" class="error"><strong>Pairing failed.</strong> The code may have expired.<br><button class="btn" onclick="location.reload()">Get New Code</button></div>
    </div>
    <script>
        let expiresAt = Date.now() + {{EXPIRES_IN}} * 1000;
        function updateTimer() {
            const remaining = Math.max(0, expiresAt - Date.now());
            const minutes = Math.floor(remaining / 60000);
            const seconds = Math.floor((remaining % 60000) / 1000);
            document.getElementById('minutes').textContent = minutes > 0 ? minutes + ':' + seconds.toString().padStart(2, '0') : seconds + 's';
            if (remaining <= 0) { document.getElementById('error').style.display = 'block'; document.querySelector('.status').style.display = 'none'; }
        }
        function checkStatus() {
            fetch('api/status').then(r => r.json()).then(data => {
                if (data.status === 'connected' || data.status === 'connecting') location.reload();
                else if (data.status === 'expired' || data.status === 'error') { document.getElementById('error').style.display = 'block'; document.querySelector('.status').style.display = 'none'; }
            }).catch(() => {});
        }
        setInterval(updateTimer, 1000);
        setInterval(checkStatus, 3000);
        updateTimer();
    </script>
</body>
</html>'''

STATUS_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HARelay - Status</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #fff;
        }
        .container { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); border-radius: 20px; padding: 40px; max-width: 500px; width: 100%; text-align: center; }
        .status-icon { width: 100px; height: 100px; margin: 0 auto 20px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 50px; }
        .status-icon.connected { background: linear-gradient(135deg, #00c853, #00e676); }
        .status-icon.disconnected { background: linear-gradient(135deg, #ff5252, #ff8a80); }
        .status-icon.connecting { background: linear-gradient(135deg, #ffc107, #ffca28); }
        h1 { font-size: 28px; margin-bottom: 10px; }
        .subtitle { color: rgba(255,255,255,0.7); margin-bottom: 30px; }
        .info-box { background: rgba(0,0,0,0.3); border-radius: 12px; padding: 20px; margin: 20px 0; text-align: left; }
        .info-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .info-row:last-child { border-bottom: none; }
        .info-label { color: rgba(255,255,255,0.6); }
        .info-value a { color: #03dac6; text-decoration: none; }
        .btn { background: transparent; color: #ff8a80; border: 1px solid #ff8a80; padding: 12px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; margin-top: 20px; }
        .btn-primary { background: #03dac6; color: #1a1a2e; border: none; margin-left: 10px; }
        .pulse { animation: pulse 2s ease-in-out infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="status-icon {{STATUS_CLASS}}" id="statusIcon"><span id="statusEmoji">{{STATUS_EMOJI}}</span></div>
        <h1 id="statusTitle">{{STATUS_TITLE}}</h1>
        <p class="subtitle" id="statusSubtitle">{{STATUS_SUBTITLE}}</p>
        <div class="info-box">
            <div class="info-row"><span class="info-label">Subdomain</span><span class="info-value">{{SUBDOMAIN}}</span></div>
            <div class="info-row"><span class="info-label">Remote URL</span><span class="info-value"><a href="https://{{SUBDOMAIN}}.harelay.com" target="_blank">{{SUBDOMAIN}}.harelay.com</a></span></div>
            <div class="info-row"><span class="info-label">Server</span><span class="info-value">{{SERVER_URL}}</span></div>
        </div>
        <div>
            <button class="btn" onclick="relink()">Relink Device</button>
            <a href="https://{{SUBDOMAIN}}.harelay.com" target="_blank" class="btn btn-primary">Open Remote Access</a>
        </div>
    </div>
    <script>
        function relink() {
            if (confirm('This will unlink your device. Continue?')) {
                fetch('api/relink', { method: 'POST' }).then(() => setTimeout(() => location.reload(), 1000));
            }
        }
        function updateStatus() {
            fetch('api/status').then(r => r.json()).then(data => {
                document.getElementById('statusIcon').className = 'status-icon ' + data.status_class;
                document.getElementById('statusEmoji').textContent = data.emoji;
                document.getElementById('statusTitle').textContent = data.title;
                document.getElementById('statusSubtitle').textContent = data.subtitle;
                if (data.status === 'pairing') location.reload();
            }).catch(() => {});
        }
        setInterval(updateStatus, 5000);
    </script>
</body>
</html>'''


class HARelayAddon:
    """Main add-on class handling both web UI and tunnel."""

    def __init__(self, config: dict):
        self.config = config
        self.subdomain = config.get('subdomain', '').strip()
        self.token = config.get('connection_token', '').strip()
        self.server_url = 'https://harelay.com'

        self.supervisor_token = os.environ.get('SUPERVISOR_TOKEN')

        # State
        self.status = 'initializing'
        self.status_message = ''
        self.device_code = None
        self.user_code = None
        self.code_expires_at = 0
        self.running = True

        logger.info(f'Server URL: {self.server_url}')
        logger.info(f'Configured: {self.is_configured}')

    @property
    def is_configured(self) -> bool:
        return bool(self.subdomain and self.token)

    # ==================== Web Handlers ====================

    async def handle_index(self, request: web.Request) -> web.Response:
        """Main page - show pairing or status."""
        if not self.is_configured:
            if self.status not in ('pairing', 'error'):
                asyncio.create_task(self.start_pairing())
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

        html = PAIRING_HTML
        html = html.replace('{{USER_CODE}}', self.user_code or 'Loading...')
        html = html.replace('{{VERIFICATION_URL}}', f'{self.server_url}/link')
        html = html.replace('{{EXPIRES_IN}}', str(expires_in))

        return web.Response(text=html, content_type='text/html')

    async def handle_status_page(self, request: web.Request) -> web.Response:
        """Show connection status page."""
        if self.status == 'connected':
            status_class, emoji, title = 'connected', '✓', 'Connected'
            subtitle = 'Your Home Assistant is accessible remotely'
        elif self.status == 'connecting':
            status_class, emoji, title = 'connecting pulse', '⟳', 'Connecting...'
            subtitle = 'Establishing tunnel connection'
        else:
            status_class, emoji, title = 'disconnected', '✗', 'Disconnected'
            subtitle = self.status_message or 'Tunnel is not connected'

        html = STATUS_HTML
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
        elif self.status == 'pairing':
            data = {'status': 'pairing'}
        elif self.status == 'expired':
            data = {'status': 'expired'}
        else:
            data = {'status': 'disconnected', 'status_class': 'disconnected', 'emoji': '✗', 'title': 'Disconnected', 'subtitle': self.status_message or 'Tunnel is not connected'}
        return web.json_response(data)

    async def handle_api_relink(self, request: web.Request) -> web.Response:
        """Reset credentials and start re-pairing."""
        await self.save_credentials('', '')
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
                # Request device code
                try:
                    async with session.post(
                        f'{self.server_url}/api/device/code',
                        json={'device_name': 'Home Assistant'},
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True
                    ) as resp:
                        if resp.status != 200:
                            logger.error(f'Failed to get device code: HTTP {resp.status}')
                            self.status = 'error'
                            self.status_message = f'Server returned {resp.status}'
                            return
                        data = await resp.json()
                except aiohttp.ClientError as e:
                    logger.error(f'Failed to connect: {e}')
                    self.status = 'error'
                    self.status_message = f'Cannot reach {self.server_url}'
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
                            await self.save_credentials(self.subdomain, self.token)
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

    async def save_credentials(self, subdomain: str, token: str) -> bool:
        """Save credentials to Home Assistant add-on config."""
        if not self.supervisor_token:
            logger.warning('No SUPERVISOR_TOKEN')
            return False

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'http://supervisor/addons/self/options/config',
                    headers={'Authorization': f'Bearer {self.supervisor_token}'},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    current = await resp.json() if resp.status == 200 else {}

                options = current.get('data', {})
                options['subdomain'] = subdomain
                options['connection_token'] = token

                async with session.post(
                    'http://supervisor/addons/self/options',
                    json={'options': options},
                    headers={'Authorization': f'Bearer {self.supervisor_token}'},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        logger.info('Credentials saved')
                        return True
                    logger.error(f'Save failed: {resp.status}')
                    return False
        except Exception as e:
            logger.error(f'Save error: {e}')
            return False

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
                # For /api/hassio/* endpoints, forward the user's token (HA validates user permissions)
                # For other endpoints, use the Supervisor token
                is_hassio = uri.startswith('/api/hassio')
                skip_headers = {'host', 'content-length', 'transfer-encoding', 'accept-encoding'}
                if not is_hassio:
                    skip_headers.add('authorization')
                filtered_headers = {k: v for k, v in headers.items() if k.lower() not in skip_headers}
                filtered_headers['Accept-Encoding'] = 'identity'
                if self.supervisor_token and not uri.startswith('/auth/') and not is_hassio:
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
