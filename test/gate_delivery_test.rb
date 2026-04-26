require_relative "test_helper"

class GateDeliveryTest < Minitest::Test
  def setup
    require_gate_crypto_support!
  end

  def load_fixture(relative_path)
    JSON.parse(File.read(File.join(__dir__, "..", "spec", "fixtures", relative_path)))
  end

  def test_delivery_request_and_vector_fixtures
    request_fixture = load_fixture("gate-delivery/delivery-request.json")
    vector_fixture = load_fixture("gate-delivery/vector.v1.json")

    validated = Tripwire::Server::GateDelivery.validate_gate_delivery_request(request_fixture["delivery"])
    assert_equal request_fixture["derived_key_id"], validated[:key_id]

    private_key = Tripwire::Server::GateDelivery.import_delivery_private_key_pkcs8(vector_fixture["private_key_pkcs8"])
    decrypted = Tripwire::Server::GateDelivery.decrypt_gate_delivery_envelope(private_key, vector_fixture["envelope"])
    assert_equal vector_fixture["payload"]["outputs"], decrypted[:outputs].transform_keys(&:to_s)
    assert_equal vector_fixture["payload"]["ack_token"], decrypted[:ack_token]
  end

  def test_webhook_signature_and_env_policy_fixtures
    payload_fixture = load_fixture("gate-delivery/approved-webhook-payload.valid.json")
    signature_fixture = load_fixture("gate-delivery/webhook-signature.json")
    env_policy_fixture = load_fixture("gate-delivery/env-policy.json")

    validated = Tripwire::Server::GateDelivery.validate_gate_approved_webhook_payload(payload_fixture)
    assert_equal payload_fixture["service_id"], validated[:service_id]
    assert_equal payload_fixture["gate_session_id"], validated[:gate_session_id]

    event = Tripwire::Server::GateDelivery.parse_webhook_event(signature_fixture["raw_body"])
    assert_equal "webhook_event", event[:object]
    assert_equal "gate.session.approved", event[:type]
    assert_equal payload_fixture["service_id"], event[:data][:service_id]
    parsed = Tripwire::Server::GateDelivery.verify_and_parse_webhook_event(
      secret: signature_fixture["secret"],
      timestamp: signature_fixture["timestamp"],
      raw_body: signature_fixture["raw_body"],
      signature: signature_fixture["signature"],
      now_seconds: signature_fixture["now_seconds"]
    )
    assert_equal "gate.session.approved", parsed[:type]

    assert Tripwire::Server::GateDelivery.verify_gate_webhook_signature(
      secret: signature_fixture["secret"],
      timestamp: signature_fixture["timestamp"],
      raw_body: signature_fixture["raw_body"],
      signature: signature_fixture["signature"],
      now_seconds: signature_fixture["now_seconds"]
    )
    refute Tripwire::Server::GateDelivery.verify_gate_webhook_signature(
      secret: signature_fixture["secret"],
      timestamp: signature_fixture["timestamp"],
      raw_body: signature_fixture["raw_body"],
      signature: signature_fixture["invalid_signature"],
      now_seconds: signature_fixture["now_seconds"]
    )
    refute Tripwire::Server::GateDelivery.verify_gate_webhook_signature(
      secret: signature_fixture["secret"],
      timestamp: signature_fixture["expired_timestamp"],
      raw_body: signature_fixture["raw_body"],
      signature: signature_fixture["signature"],
      now_seconds: signature_fixture["now_seconds"]
    )

    env_policy_fixture["derive_agent_token_env_key"].each do |entry|
      assert_equal entry["expected"], Tripwire::Server::GateDelivery.derive_gate_agent_token_env_key(entry["service_id"])
    end
    env_policy_fixture["is_gate_managed_env_var_key"].each do |entry|
      assert_equal entry["managed"], Tripwire::Server::GateDelivery.is_gate_managed_env_var_key(entry["key"])
    end
    env_policy_fixture["is_blocked_gate_env_var_key"].each do |entry|
      assert_equal entry["blocked"], Tripwire::Server::GateDelivery.is_blocked_gate_env_var_key(entry["key"])
    end
  end

  def test_created_response_roundtrips
    key_pair = Tripwire::Server::GateDelivery.create_delivery_key_pair
    response = Tripwire::Server::GateDelivery.create_gate_approved_webhook_response(
      delivery: key_pair[:delivery],
      outputs: {
        "TRIPWIRE_PUBLISHABLE_KEY" => "pk_live_bundle",
        "TRIPWIRE_SECRET_KEY" => "sk_live_bundle"
      }
    )
    decrypted = Tripwire::Server::GateDelivery.decrypt_gate_delivery_envelope(key_pair[:private_key], response[:encrypted_delivery])
    assert_equal(
      {
        "TRIPWIRE_PUBLISHABLE_KEY" => "pk_live_bundle",
        "TRIPWIRE_SECRET_KEY" => "sk_live_bundle"
      },
      decrypted[:outputs].transform_keys(&:to_s)
    )
  end
end
