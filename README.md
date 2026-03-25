# `tripwire-server`

Official Tripwire Ruby server SDK.

`tripwire-server` exposes the customer-facing server APIs for:

- Sessions API
- Fingerprints API
- Teams API
- Team API key management
- sealed token verification

It does not include collect endpoints or internal scoring APIs.

## Installation

```bash
bundle add tripwire-server
```

## Quick start

```ruby
require "tripwire/server"

client = Tripwire::Server::Client.new(secret_key: "sk_live_...")

page = client.sessions.list(verdict: "bot", limit: 25)
session = client.sessions.get("sid_123")

result = Tripwire::Server.safe_verify_tripwire_token("AQAA...", "sk_live_...")
puts result[:data][:verdict] if result[:ok]
```

Defaults:

- `base_url`: `https://api.tripwirejs.com`
- `secret_key`: `TRIPWIRE_SECRET_KEY`
- `timeout`: `30` seconds

## Development

The canonical cross-language server SDK spec lives in the Tripwire main repo under `sdk-spec/server/`.
This repo carries a synced copy in `spec/` for standalone testing and release workflows.
Official Tripwire Ruby server SDK
