# Tripwire Ruby Library

![Preview](https://img.shields.io/badge/status-preview-111827)
![Ruby 2.6+](https://img.shields.io/badge/ruby-2.6%2B-CC342D?logo=ruby&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)

The Tripwire Ruby library provides convenient access to the Tripwire API from applications written in Ruby. It includes a client for Sessions, Fingerprints, Teams, Team API key management, and sealed token verification.

The library also provides:

- a fast configuration path using `TRIPWIRE_SECRET_KEY`
- lazy helpers for cursor-based pagination
- structured API errors and built-in sealed token verification

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

The library needs to be configured with your account's secret key. Set `TRIPWIRE_SECRET_KEY` in your environment or pass `secret_key` directly:

```ruby
require "tripwire/server"

client = Tripwire::Server::Client.new(secret_key: "sk_live_...")

page = client.sessions.list(verdict: "bot", limit: 25)
session = client.sessions.get("sid_123")
```

### Sealed token verification

```ruby
result = Tripwire::Server.safe_verify_tripwire_token(sealed_token, "sk_live_...")

if result[:ok]
  puts "#{result[:data][:verdict]} #{result[:data][:score]}"
else
  warn result[:error].message
end
```

### Pagination

```ruby
client.sessions.iter(search: "signup").each do |session|
  puts "#{session[:id]} #{session[:latestResult][:verdict]}"
end
```

### Fingerprints

```ruby
fingerprint = client.fingerprints.get("vis_123")
puts fingerprint[:id]
```

### Teams

```ruby
team = client.teams.get("team_123")
updated = client.teams.update("team_123", name: "New Name")

puts updated[:name]
```

### Team API keys

```ruby
created = client.teams.api_keys.create("team_123", name: "Production")
client.teams.api_keys.revoke("team_123", created[:id])
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
