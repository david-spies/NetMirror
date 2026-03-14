# ChatterBox Web App

> A modern, tech-noir styled web chat app — rebuilt from the original Python/Tkinter desktop client to a lightweight, browser-based experience.

![Tech-noir chat · solarized green · slate blue · zero dependencies](.github/banner.png)

---

## What is this?

ChatterBox Web replaces the original `chatterbox_client.py` + `chatterbox_server.py` desktop application with:

| Original | Replacement |
|---|---|
| Python/Tkinter GUI | Single-page HTML client (`index.html`) |
| Raw TCP socket server | Async WebSocket server (`server.py`) |
| Desktop-only | Any browser, any OS |
| Requires Python + tkinter | Client needs no install — just double-click |

---

## Features

- **Zero-install client** — open `index.html` in any modern browser, no Node, no npm, no build step
- **Real-time messaging** via WebSocket
- **Live typing indicators** — see who's composing
- **User presence list** — sidebar shows who's online
- **Message history** — server buffers the last 50 messages for late joiners
- **Auto-reconnect** — exponential backoff if the connection drops
- **Tech-noir aesthetic** — solarized green on black, slate blue accents, scanline overlay, mono fonts

---

## Quick Start

See [`quickstart.md`](docs/quickstart.md) for a step-by-step guide to running both the server and client on one machine.

---

## Repository Layout

```
chatterbox-web/
├── client/
│   └── index.html          ← the entire client (double-click to open)
├── server/
│   ├── server.py            ← async WebSocket server
│   └── requirements.txt     ← server Python deps (websockets)
└── docs/
    ├── quickstart.md
    ├── tech-stack.md
    └── requirements.txt     ← full Python environment pin
```

---

## Network

The server listens on **`ws://0.0.0.0:8765`** by default.  
Clients connect by entering the server address in the connect screen.  

For local development: `ws://localhost:8765`  
For LAN play: `ws://<your-local-ip>:8765`

---

## License

MIT — same as the original ChatterBox project.
