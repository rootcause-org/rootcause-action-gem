# frozen_string_literal: true

require "stringio"

RSpec.describe "per-project reverse secrets" do
  project_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
  project_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
  secret_a = "project-a-reverse-secret"
  secret_b = "project-b-reverse-secret"

  define_method(:project_a) { project_a }
  define_method(:project_b) { project_b }
  define_method(:secret_a) { secret_a }
  define_method(:secret_b) { secret_b }

  def map_config(**overrides)
    Wire.config(secret: nil, secrets: {project_a => secret_a, project_b => secret_b}, **overrides)
  end

  def map_invocation(project_id: project_a, **overrides)
    Wire.invocation(**overrides).tap { |payload| payload["project_id"] = project_id }
  end

  def map_result(project_id: project_a, **overrides)
    Wire.result(**overrides).tap { |payload| payload["project_id"] = project_id }
  end

  def signed_handle(receiver, payload, secret: secret_a)
    raw = JSON.generate(payload)
    receiver.handle(raw_body: raw, signature: Wire.sign(raw, secret: secret))
  end

  def stub_map_fetch(script:, secret: secret_a)
    digest = Wire.digest_of(script)
    body = JSON.generate("action_id" => "devise_send_password_reset", "digest" => digest, "script" => script, "runtime" => "ruby")
    WebMock.stub_request(:get, /rootcause\.test/).to_return(
      status: 200, body: body, headers: {RootCause::Embassy::Signature::HEADER => Wire.sign(body, secret: secret)}
    )
  end

  it "requires exactly one non-blank single secret or a non-empty UUID map" do
    cfg = RootCause::Embassy::Config.new
    cfg.fetch_url = Wire::FETCH_URL
    cfg.secrets = {project_a => secret_a}
    expect { cfg.validate! }.not_to raise_error

    cfg.secret = Wire::SECRET
    expect { cfg.validate! }.to raise_error(ArgumentError, /exactly one/)

    cfg.secret = nil
    cfg.secrets = {"not-a-project" => secret_a}
    expect { cfg.validate! }.to raise_error(ArgumentError, /project UUIDs/)

    cfg.secrets = {project_a => "  "}
    expect { cfg.validate! }.to raise_error(ArgumentError, /non-blank/)
  end

  it "selects the map entry before verification and signs fetches and responses with it" do
    config = map_config
    runner = RootCause::Embassy::Runner.new(config)
    script = "{ project: 'a' }"
    stub_map_fetch(script: script)
    raw = JSON.generate(map_invocation(script: script))

    reply = runner.handle(raw_body: raw, signature: Wire.sign(raw, secret: secret_a))

    expect(reply.status).to eq(200)
    expect(JSON.parse(reply.body).dig("return_value", "project")).to eq("a")
    expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: secret_a)).to be(true)
    query = URI.encode_www_form([["action_id", "devise_send_password_reset"], ["digest", Wire.digest_of(script)], ["project_id", project_a]])
    expect(a_request(:get, /rootcause\.test/).with(headers: {"X-Webhook-Signature" => Wire.sign(query, secret: secret_a)})).to have_been_made
  end

  it "refuses a sibling key with the selected project's signed bad_signature" do
    runner = RootCause::Embassy::Runner.new(map_config)
    fetch = WebMock.stub_request(:get, /rootcause\.test/)
    raw = JSON.generate(map_invocation)

    reply = runner.handle(raw_body: raw, signature: Wire.sign(raw, secret: secret_b))

    expect(reply.status).to eq(401)
    expect(JSON.parse(reply.body).dig("error", "class")).to eq("bad_signature")
    expect(reply.signature).not_to be_nil
    expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: secret_a)).to be(true)
    expect(fetch).not_to have_been_requested
  end

  it "does not reuse another project's cached digest before that project's fetch authorization" do
    config = map_config
    runner = RootCause::Embassy::Runner.new(config)
    script = "{ project: 'authorized-a' }"
    stub_map_fetch(script: script, secret: secret_a)
    a_raw = JSON.generate(map_invocation(script: script))
    expect(runner.handle(raw_body: a_raw, signature: Wire.sign(a_raw, secret: secret_a)).status).to eq(200)

    WebMock.stub_request(:get, /rootcause\.test/).with { |request|
      request.uri.query.include?("project_id=#{project_b}")
    }.to_return(status: 403)
    b_raw = JSON.generate(map_invocation(project_id: project_b, script: script))
    reply = runner.handle(raw_body: b_raw, signature: Wire.sign(b_raw, secret: secret_b))

    expect(reply.status).to eq(502)
    expect(JSON.parse(reply.body).dig("error", "class")).to eq("resolve_failed")
    expect(
      a_request(:get, /rootcause\.test/).with { |request|
        request.uri.query.include?("project_id=#{project_b}")
      }
    ).to have_been_made
  end

  it "keeps missing and unknown action selectors opaque and unsigned" do
    runner = RootCause::Embassy::Runner.new(map_config)
    fetch = WebMock.stub_request(:get, /rootcause\.test/)

    [map_invocation.tap { |payload| payload.delete("project_id") }, map_invocation(project_id: "cccccccc-cccc-cccc-cccc-cccccccccccc")].each do |payload|
      raw = JSON.generate(payload)
      reply = runner.handle(raw_body: raw, signature: Wire.sign(raw, secret: secret_a))
      expect(reply.status).to eq(401)
      expect(JSON.parse(reply.body).dig("error", "class")).to eq("bad_signature")
      expect(reply.signature).to be_nil
    end
    expect(fetch).not_to have_been_requested
  end

  it "uses the selected map key for result callbacks and never dispatches selector failures" do
    handler = Class.new(RootCause::Embassy::ResultHandler) do
      class << self
        attr_accessor :calls
      end
      self.calls = 0
      def process(_) = self.class.calls += 1
    end
    receiver = RootCause::Embassy::ResultReceiver.new(map_config(result_handler: handler))

    reply = signed_handle(receiver, map_result(analysis_id: "map-result"))
    expect(reply.status).to eq(200)
    expect(handler.calls).to eq(1)
    expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: secret_a)).to be(true)

    sibling = signed_handle(receiver, map_result(analysis_id: "sibling-result"), secret: secret_b)
    expect(sibling.status).to eq(401)
    expect(RootCause::Embassy::Signature.valid?(sibling.signature, sibling.body, secret: secret_a)).to be(true)

    missing_payload = map_result(analysis_id: "missing-result").tap { |payload| payload.delete("project_id") }
    missing = signed_handle(receiver, missing_payload)
    unknown = signed_handle(receiver, map_result(project_id: "cccccccc-cccc-cccc-cccc-cccccccccccc", analysis_id: "unknown-result"))
    expect([missing, unknown]).to all(have_attributes(status: 401, signature: nil))
    expect(handler.calls).to eq(1)
  end

  it "serves a map-aware signed health query and preserves the legacy single-secret probe" do
    map_runner = RootCause::Embassy::Runner.new(map_config)
    query = "project_id=#{project_a}"
    map_reply = map_runner.health(raw_query: query, signature: Wire.sign(query, secret: secret_a))
    expect(map_reply.status).to eq(200)
    expect(JSON.parse(map_reply.body).slice("embassy", "protocol")).to eq({"embassy" => "ruby", "protocol" => 1})
    expect(RootCause::Embassy::Signature.valid?(map_reply.signature, map_reply.body, secret: secret_a)).to be(true)

    unknown = map_runner.health(raw_query: "project_id=cccccccc-cccc-cccc-cccc-cccccccccccc", signature: Wire.sign(query, secret: secret_a))
    expect(unknown).to have_attributes(status: 404, signature: nil, body: "")
    bad_signature = map_runner.health(raw_query: query, signature: Wire.sign(query, secret: secret_b))
    expect(bad_signature).to have_attributes(status: 404, signature: nil, body: "")

    single_runner = RootCause::Embassy::Runner.new(Wire.config)
    single_reply = single_runner.health(raw_query: "", signature: Wire.sign(""))
    expect(single_reply.status).to eq(200)
    expect(RootCause::Embassy::Signature.valid?(single_reply.signature, single_reply.body, secret: Wire::SECRET)).to be(true)
  end

  it "selects an outbound analysis secret from the caller-supplied project id" do
    client = RootCause::Embassy::Client.new(map_config)
    Wire.stub_trigger
    Wire.stub_sent_message

    client.start_analysis(subject: "s", body: "b", project_id: project_a)
    client.capture_sent_message(sent_body: "sent", session_id: "session", project_id: project_b)

    expect(
      a_request(:post, Wire::TRIGGER_URL).with { |request|
        RootCause::Embassy::Signature.valid?(request.headers["X-Webhook-Signature"], request.body, secret: secret_a)
      }
    ).to have_been_made
    expect(
      a_request(:post, Wire::SENT_MESSAGE_URL).with { |request|
        RootCause::Embassy::Signature.valid?(request.headers["X-Webhook-Signature"], request.body, secret: secret_b)
      }
    ).to have_been_made
    expect { client.start_analysis(subject: "s", body: "b") }.to raise_error(ArgumentError, /project_id/)
  end
end
