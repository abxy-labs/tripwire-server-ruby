require_relative "test_helper"

class ContractTest < Minitest::Test
  def strip_examples(value)
    case value
    when Array
      value.map { |item| strip_examples(item) }
    when Hash
      value.each_with_object({}) do |(key, item), result|
        next if key == "example"

        result[key] = strip_examples(item)
      end
    else
      value
    end
  end

  def spec
    @spec ||= JSON.parse(File.read(File.join(__dir__, "..", "spec", "openapi.json")))
  end

  def test_only_supported_public_paths_are_exposed
    expected = [
      "/v1/fingerprints",
      "/v1/fingerprints/{visitorId}",
      "/v1/gate/agent-tokens/revoke",
      "/v1/gate/agent-tokens/verify",
      "/v1/gate/login-sessions",
      "/v1/gate/login-sessions/consume",
      "/v1/gate/registry",
      "/v1/gate/registry/{serviceId}",
      "/v1/gate/services",
      "/v1/gate/services/{serviceId}",
      "/v1/gate/sessions",
      "/v1/gate/sessions/{gateSessionId}",
      "/v1/gate/sessions/{gateSessionId}/ack",
      "/v1/sessions",
      "/v1/sessions/{sessionId}",
      "/v1/teams",
      "/v1/teams/{teamId}",
      "/v1/teams/{teamId}/api-keys",
      "/v1/teams/{teamId}/api-keys/{keyId}",
      "/v1/teams/{teamId}/api-keys/{keyId}/rotations"
    ]

    assert_equal expected.sort, spec.fetch("paths").keys.sort
  end

  def test_expected_success_fixtures_exist
    paths = [
      "api/sessions/list.json",
      "api/sessions/detail.json",
      "api/fingerprints/list.json",
      "api/fingerprints/detail.json",
      "api/gate/registry-list.json",
      "api/gate/registry-detail.json",
      "api/gate/services-list.json",
      "api/gate/service-detail.json",
      "api/gate/service-create.json",
      "api/gate/service-update.json",
      "api/gate/service-disable.json",
      "api/gate/session-create.json",
      "api/gate/session-poll.json",
      "api/gate/session-ack.json",
      "api/gate/login-session-create.json",
      "api/gate/login-session-consume.json",
      "api/gate/agent-token-verify.json",
      "api/gate/agent-token-revoke.json",
      "api/teams/team.json",
      "api/teams/team-create.json",
      "api/teams/team-update.json",
      "api/teams/api-key-create.json",
      "api/teams/api-key-list.json",
      "api/teams/api-key-rotate.json",
      "api/teams/api-key-revoke.json"
    ]

    paths.each do |relative_path|
      assert File.exist?(File.join(__dir__, "..", "spec", "fixtures", relative_path)), "missing fixture #{relative_path}"
    end
  end

  def test_schema_constraints_are_tightened_for_sdk_consumers
    schemas = spec.fetch("components").fetch("schemas")

    assert_equal "^sid_[0123456789abcdefghjkmnpqrstvwxyz]{26}$", schemas.fetch("SessionId").fetch("pattern")
    assert_equal "^vid_[0123456789abcdefghjkmnpqrstvwxyz]{26}$", schemas.fetch("FingerprintId").fetch("pattern")
    assert_equal "^team_[0123456789abcdefghjkmnpqrstvwxyz]{26}$", schemas.fetch("TeamId").fetch("pattern")
    assert_equal "^key_[0123456789abcdefghjkmnpqrstvwxyz]{26}$", schemas.fetch("ApiKeyId").fetch("pattern")

    assert_equal({ "$ref" => "#/components/schemas/SessionId" }, strip_examples(schemas.fetch("SessionSummary").fetch("properties").fetch("id")))
    assert_equal({ "$ref" => "#/components/schemas/TeamStatus" }, strip_examples(schemas.fetch("Team").fetch("properties").fetch("status")))
    assert_equal({ "$ref" => "#/components/schemas/ApiKeyStatus" }, strip_examples(schemas.fetch("ApiKey").fetch("properties").fetch("status")))
    assert_equal "#/components/schemas/KnownPublicErrorCode", schemas.fetch("PublicError").fetch("properties").fetch("code").fetch("x-tripwire-known-values-ref")
    assert_equal ["active", "suspended", "deleted"], schemas.fetch("TeamStatus").fetch("enum")
    assert_equal ["active", "revoked", "rotated"], schemas.fetch("ApiKeyStatus").fetch("enum")
    %w[decision highlights automation web_bot_auth network runtime_integrity visitor_fingerprint connection_fingerprint previous_decisions request browser device analysis_coverage signals_fired client_telemetry].each do |field|
      assert_includes schemas.fetch("SessionDetail").fetch("required"), field
    end
    assert_equal(
      { "$ref" => "#/components/schemas/SessionDetailRequest" },
      strip_examples(schemas.fetch("SessionDetail").fetch("properties").fetch("request"))
    )
    assert_equal(
      { "$ref" => "#/components/schemas/SessionClientTelemetry" },
      strip_examples(schemas.fetch("SessionDetail").fetch("properties").fetch("client_telemetry"))
    )
    assert_equal(
      { "anyOf" => [{ "$ref" => "#/components/schemas/SessionAutomation" }, { "type" => "null" }] },
      strip_examples(schemas.fetch("SessionDetail").fetch("properties").fetch("automation"))
    )
    assert_equal(
      { "type" => "array", "items" => { "$ref" => "#/components/schemas/SessionSignalFired" } },
      strip_examples(schemas.fetch("SessionDetail").fetch("properties").fetch("signals_fired"))
    )
    assert_equal "string", schemas.fetch("SessionSignalFired").fetch("properties").fetch("signal").fetch("type")
    %w[allowed_origins rate_limit rotated_at revoked_at].each do |field|
      assert_includes schemas.fetch("ApiKey").fetch("required"), field
    end
    refute_includes schemas.fetch("GateManagedService").fetch("properties").keys, "team_id"
    refute_includes schemas.fetch("GateManagedService").fetch("properties").keys, "webhook_secret"
    refute_includes schemas.keys, "CollectBatchResponse"
  end

  def test_public_operations_have_stable_ids_and_tags
    assert_equal "listSessions", spec.fetch("paths").fetch("/v1/sessions").fetch("get").fetch("operationId")
    assert_equal ["Sessions"], spec.fetch("paths").fetch("/v1/sessions").fetch("get").fetch("tags")
    assert_equal "getVisitorFingerprint", spec.fetch("paths").fetch("/v1/fingerprints/{visitorId}").fetch("get").fetch("operationId")
    assert_equal ["Visitor fingerprints"], spec.fetch("paths").fetch("/v1/fingerprints/{visitorId}").fetch("get").fetch("tags")
    assert_equal "updateTeam", spec.fetch("paths").fetch("/v1/teams/{teamId}").fetch("patch").fetch("operationId")
    assert_equal ["Teams"], spec.fetch("paths").fetch("/v1/teams/{teamId}").fetch("patch").fetch("tags")
    assert_equal "rotateTeamApiKey", spec.fetch("paths").fetch("/v1/teams/{teamId}/api-keys/{keyId}/rotations").fetch("post").fetch("operationId")
    assert_equal ["API Keys"], spec.fetch("paths").fetch("/v1/teams/{teamId}/api-keys/{keyId}/rotations").fetch("post").fetch("tags")
    assert_equal "createManagedGateService", spec.fetch("paths").fetch("/v1/gate/services").fetch("post").fetch("operationId")
    assert_equal ["Gate"], spec.fetch("paths").fetch("/v1/gate/services").fetch("post").fetch("tags")
    assert_equal "pollGateSession", spec.fetch("paths").fetch("/v1/gate/sessions/{gateSessionId}").fetch("get").fetch("operationId")
    assert_equal ["Gate"], spec.fetch("paths").fetch("/v1/gate/sessions/{gateSessionId}").fetch("get").fetch("tags")
    assert_equal "revokeGateAgentToken", spec.fetch("paths").fetch("/v1/gate/agent-tokens/revoke").fetch("post").fetch("operationId")
    assert_equal ["Gate"], spec.fetch("paths").fetch("/v1/gate/agent-tokens/revoke").fetch("post").fetch("tags")
  end
end
