require_relative "test_helper"

class ContractTest < Minitest::Test
  def test_only_supported_public_paths_are_exposed
    spec = JSON.parse(File.read(File.join(__dir__, "..", "spec", "openapi.json")))
    expected = [
      "/v1/fingerprints",
      "/v1/fingerprints/{visitorId}",
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
      "public-api/sessions/list.json",
      "public-api/sessions/detail.json",
      "public-api/fingerprints/list.json",
      "public-api/fingerprints/detail.json",
      "public-api/teams/team.json",
      "public-api/teams/team-create.json",
      "public-api/teams/team-update.json",
      "public-api/teams/api-key-create.json",
      "public-api/teams/api-key-list.json",
      "public-api/teams/api-key-rotate.json",
      "public-api/teams/api-key-revoke.json"
    ]

    paths.each do |relative_path|
      assert File.exist?(File.join(__dir__, "..", "spec", "fixtures", relative_path)), "missing fixture #{relative_path}"
    end
  end
end
