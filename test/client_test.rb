require_relative "test_helper"

class ClientTest < Minitest::Test
  def test_env_secret_fallback
    original = ENV["TRIPWIRE_SECRET_KEY"]
    ENV["TRIPWIRE_SECRET_KEY"] = "sk_env_default"
    fixture = load_fixture("public-api/sessions/list.json")

    client = Tripwire::Server::Client.new(
      base_url: "https://example.tripwire.dev",
      transport: lambda do |_request|
        [200, { "content-type" => "application/json" }, JSON.dump(fixture)]
      end
    )

    assert_equal 1, client.sessions.list.items.length
  ensure
    ENV["TRIPWIRE_SECRET_KEY"] = original
  end

  def test_missing_secret_raises
    original = ENV.delete("TRIPWIRE_SECRET_KEY")
    assert_raises(Tripwire::Server::ConfigurationError) do
      Tripwire::Server::Client.new
    end
  ensure
    ENV["TRIPWIRE_SECRET_KEY"] = original if original
  end

  def test_base_url_timeout_and_headers_are_applied
    fixture = load_fixture("public-api/sessions/list.json")
    observed = nil

    client = Tripwire::Server::Client.new(
      secret_key: "sk_live_test",
      base_url: "https://example.tripwire.dev",
      timeout: 5,
      user_agent: "custom-tripwire-ruby",
      transport: lambda do |request|
        observed = request
        [200, { "content-type" => "application/json" }, JSON.dump(fixture)]
      end
    )

    client.sessions.list(limit: 5)
    assert_equal "https://example.tripwire.dev/v1/sessions?limit=5", observed[:url]
    assert_equal "Bearer sk_live_test", observed[:headers]["Authorization"]
    assert_equal "tripwire-server-ruby/0.1.0", observed[:headers]["X-Tripwire-Client"]
    assert_equal "custom-tripwire-ruby", observed[:headers]["User-Agent"]
    assert_equal 5, client.timeout
  end

  def test_sessions_fingerprints_teams_and_api_keys
    session_list = load_fixture("public-api/sessions/list.json")
    session_detail = load_fixture("public-api/sessions/detail.json")
    fingerprint_list = load_fixture("public-api/fingerprints/list.json")
    fingerprint_detail = load_fixture("public-api/fingerprints/detail.json")
    team_get = load_fixture("public-api/teams/team.json")
    team_create = load_fixture("public-api/teams/team-create.json")
    team_update = load_fixture("public-api/teams/team-update.json")
    api_key_create = load_fixture("public-api/teams/api-key-create.json")
    api_key_list = load_fixture("public-api/teams/api-key-list.json")
    api_key_rotate = load_fixture("public-api/teams/api-key-rotate.json")

    client = Tripwire::Server::Client.new(
      secret_key: "sk_live_test",
      transport: lambda do |request|
        case [request[:method], request[:url]]
        when ["GET", "https://api.tripwirejs.com/v1/sessions"]
          [200, {}, JSON.dump(session_list)]
        when ["GET", "https://api.tripwirejs.com/v1/sessions?cursor=cur_sessions_page_2"]
          second_page = {
            data: [
              session_list[:data].first.merge(
                id: "sid_example_two",
                latestEventId: "evt_example_two",
                lastScoredAt: "2026-03-24T20:01:05.000Z"
              )
            ],
            pagination: {
              limit: 50,
              hasMore: false
            }
          }
          [200, {}, JSON.dump(second_page)]
        when ["GET", "https://api.tripwirejs.com/v1/sessions/sid_example_one"]
          [200, {}, JSON.dump(session_detail)]
        when ["GET", "https://api.tripwirejs.com/v1/fingerprints"]
          [200, {}, JSON.dump(fingerprint_list)]
        when ["GET", "https://api.tripwirejs.com/v1/fingerprints/vis_example_one"]
          [200, {}, JSON.dump(fingerprint_detail)]
        when ["POST", "https://api.tripwirejs.com/v1/teams"]
          [201, {}, JSON.dump(team_create)]
        when ["GET", "https://api.tripwirejs.com/v1/teams/team_example"]
          [200, {}, JSON.dump(team_get)]
        when ["PATCH", "https://api.tripwirejs.com/v1/teams/team_example"]
          [200, {}, JSON.dump(team_update)]
        when ["POST", "https://api.tripwirejs.com/v1/teams/team_example/api-keys"]
          [201, {}, JSON.dump(api_key_create)]
        when ["GET", "https://api.tripwirejs.com/v1/teams/team_example/api-keys"]
          [200, {}, JSON.dump(api_key_list)]
        when ["DELETE", "https://api.tripwirejs.com/v1/teams/team_example/api-keys/key_example"]
          [204, {}, ""]
        when ["POST", "https://api.tripwirejs.com/v1/teams/team_example/api-keys/key_example/rotations"]
          [201, {}, JSON.dump(api_key_rotate)]
        else
          flunk("Unexpected request #{request[:method]} #{request[:url]}")
        end
      end
    )

    assert_equal "sid_example_one", client.sessions.get("sid_example_one")[:id]
    assert_equal ["sid_example_one", "sid_example_two"], client.sessions.iter.map { |item| item[:id] }
    assert_equal "vis_example_one", client.fingerprints.get("vis_example_one")[:id]
    assert_equal "team_example", client.teams.get("team_example")[:id]
    assert_equal "team_example", client.teams.create(name: "Example Team", slug: "example-team")[:id]
    assert_equal "Updated Example Team", client.teams.update("team_example", name: "Updated Example Team")[:name]
    assert_equal "sk_live_example", client.teams.api_keys.create("team_example", name: "Production")[:secretKey]
    assert_equal "key_example", client.teams.api_keys.list("team_example").items.first[:id]
    assert_nil client.teams.api_keys.revoke("team_example", "key_example")
    assert_equal "sk_live_rotated", client.teams.api_keys.rotate("team_example", "key_example")[:secretKey]
  end

  def test_api_errors_are_parsed
    %w[
      errors/missing-api-key.json
      errors/invalid-api-key.json
      errors/validation-error.json
      errors/not-found.json
    ].each do |fixture_path|
      fixture = load_fixture(fixture_path)
      client = Tripwire::Server::Client.new(
        secret_key: "sk_live_test",
        transport: lambda do |_request|
          [fixture.fetch(:error).fetch(:status), { "x-request-id" => fixture.fetch(:error).fetch(:requestId) }, JSON.dump(fixture)]
        end
      )

      error = assert_raises(Tripwire::Server::ApiError) do
        client.sessions.list(limit: 999)
      end
      assert_equal fixture.fetch(:error).fetch(:code), error.code
      assert_equal fixture.fetch(:error).fetch(:requestId), error.request_id
    end
  end
end
