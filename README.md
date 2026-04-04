# Tripwire Ruby Library

![Preview](https://img.shields.io/badge/status-preview-111827)
![Ruby 2.6+](https://img.shields.io/badge/ruby-2.6%2B-CC342D?logo=ruby&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)

The Tripwire Ruby library provides convenient access to the Tripwire API from applications written in Ruby. It includes a client for Sessions, visitor fingerprints, Teams, Team API key management, sealed token verification, Gate, and Gate delivery/webhook helpers.

The library also provides:

- a fast configuration path using `TRIPWIRE_SECRET_KEY`
- lazy helpers for cursor-based pagination
- structured API errors and built-in sealed token verification
- public, bearer-token, and secret-key auth modes for Gate flows
- Gate delivery/webhook helpers

## Documentation

See the [Tripwire docs](https://tripwirejs.com/docs) and [API reference](https://tripwirejs.com/docs/api-reference/introduction).

## Installation

You don't need this source code unless you want to modify the gem. If you just want to use the package, run:

```bash
bundle add tripwire-server
```

## Requirements

- Ruby 2.6+

## Usage

Use `TRIPWIRE_SECRET_KEY` or `secret_key:` for core detect APIs. For public or bearer-auth Gate flows, the client can also be created without a secret key:

```ruby
require "tripwire/server"

client = Tripwire::Server::Client.new(secret_key: "sk_live_...")

page = client.sessions.list(verdict: "bot", limit: 25)
session = client.sessions.get("sid_0123456789abcdefghjkmnpqrs")

puts "#{session[:decision][:automation_status]} #{session[:highlights].first&.fetch(:summary, nil)}"
```

### Sealed token verification

```ruby
result = Tripwire::Server.safe_verify_tripwire_token(sealed_token, "sk_live_...")

if result[:ok]
  puts "#{result[:data][:decision][:verdict]} #{result[:data][:decision][:risk_score]}"
else
  warn result[:error].message
end
```

### Pagination

```ruby
client.sessions.iter(search: "signup").each do |session|
  puts "#{session[:id]} #{session[:latest_decision][:verdict]}"
end
```

### Visitor fingerprints

```ruby
fingerprint = client.fingerprints.get("vid_0123456789abcdefghjkmnpqrs")
puts fingerprint[:id]
```

### Teams

```ruby
team = client.teams.get("team_0123456789abcdefghjkmnpqrs")
updated = client.teams.update("team_0123456789abcdefghjkmnpqrs", name: "New Name")

puts updated[:name]
```

### Team API keys

```ruby
created = client.teams.api_keys.create("team_0123456789abcdefghjkmnpqrs", name: "Production", environment: "live")
client.teams.api_keys.revoke("team_0123456789abcdefghjkmnpqrs", created[:id])
```

### Gate APIs

```ruby
delivery_key_pair = Tripwire::Server::GateDelivery.create_delivery_key_pair

services = client.gate.registry.list
session = client.gate.sessions.create(
  service_id: "tripwire",
  account_name: "my-project",
  delivery: delivery_key_pair[:delivery]
)

puts "#{services.first[:id]} #{session[:consent_url]}"
```

### Gate delivery and webhook helpers

```ruby
key_pair = Tripwire::Server::GateDelivery.create_delivery_key_pair
response = Tripwire::Server::GateDelivery.create_gate_approved_webhook_response(
  delivery: key_pair[:delivery],
  outputs: {
    "TRIPWIRE_PUBLISHABLE_KEY" => "pk_live_...",
    "TRIPWIRE_SECRET_KEY" => "sk_live_..."
  }
)
payload = Tripwire::Server::GateDelivery.decrypt_gate_delivery_envelope(key_pair[:private_key], response[:encrypted_delivery])

puts payload[:outputs]["TRIPWIRE_SECRET_KEY"]
```

### Error handling

```ruby
begin
  client.sessions.list(limit: 999)
rescue Tripwire::Server::ApiError => error
  warn "#{error.status} #{error.code} #{error.message}"
end
```

## Support

If you need help integrating Tripwire, start with [tripwirejs.com/docs](https://tripwirejs.com/docs).
