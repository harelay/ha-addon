# HARelay Home Assistant Add-on

Secure remote access to your Home Assistant via HARelay.

## Features

- **Easy Setup**: Device pairing via web UI - no manual configuration needed
- **Secure Tunnel**: WebSocket-based encrypted connection
- **WebSocket Proxying**: Full support for Home Assistant's real-time features
- **Auto-reconnect**: Automatic reconnection with status display

## Installation

1. Add this repository to Home Assistant:
   - Go to **Settings → Add-ons → Add-on Store**
   - Click the three dots → **Repositories**
   - Add: `https://github.com/harelay/ha-addon`

2. Install **HARelay Tunnel** from the add-on store

3. Start the add-on and open the web UI

4. Follow the pairing instructions:
   - Visit the URL shown (harelay.com/link)
   - Log in or create an account
   - Enter the pairing code

5. The add-on will automatically connect!

## Repository Structure

```
ha-addon/
├── repository.yaml           # Repository metadata
└── harelay/                  # HARelay add-on
    ├── config.yaml
    ├── Dockerfile
    ├── run.py
    └── rootfs/
        ├── run.sh
        └── app/templates/    # Web UI templates
```

## Add-on

| Add-on | Description | Server URL |
|--------|-------------|------------|
| **HARelay Tunnel** | Secure remote access | `https://harelay.com` |

## Configuration

No configuration needed! Just start the add-on and follow the pairing instructions.

**Optional setting:**
| Option | Description | Default |
|--------|-------------|---------|
| `log_level` | Logging verbosity | `info` |

## How It Works

1. **Pairing Mode**: When no credentials are configured, the add-on displays a pairing code
2. **Device Linking**: User visits harelay.com/link and enters the code
3. **Credential Sync**: The add-on automatically receives and saves credentials
4. **Tunnel Connection**: WebSocket connection established to HARelay server
5. **Request Proxying**: HTTP requests and WebSocket messages are relayed to Home Assistant

## Web UI

The add-on provides a web UI accessible from the Home Assistant sidebar:

- **Pairing Page**: Shows pairing code and instructions
- **Status Page**: Shows connection status and remote URL
- **Relink Button**: Reset credentials and start pairing again

## Security

- All communication uses TLS encryption
- Connection tokens are never exposed after initial pairing
- The add-on only makes outbound connections
- Credentials are stored securely in Home Assistant's configuration

## Troubleshooting

### Pairing code expired
Click "Get New Code" or restart the add-on to generate a fresh pairing code.

### Connection keeps disconnecting
Check your network connection and ensure the HARelay server is accessible.

### Relink device
Open the add-on web UI and click "Relink Device" to start fresh.
