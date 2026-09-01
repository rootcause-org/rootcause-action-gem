# frozen_string_literal: true

require "stringio"

# A recording handler, resolvable by name (Object.const_get) to exercise the
# lazy-load path. Upserts by analysis_id so a redelivery can't duplicate.
class SpecResultHandler < RootCause::Embassy::ResultHandler
  class << self
    def store = (@store ||= {})
    def reset! = (@store = {})
  end

  def process(result)
    self.class.store[result.analysis_id] = result
  end
end

# A handler that always blows up — proves a handler exception is NOT acked.
class SpecBoomHandler < RootCause::Embassy::ResultHandler
  def process(_result) = raise "boom"
end

RSpec.describe RootCause::Embassy::ResultReceiver do
  let(:config) { Wire.config(result_handler: "SpecResultHandler") }
  let(:receiver) { described_class.new(config) }

  before { SpecResultHandler.reset! }

  def handle(payload, secret: Wire::SECRET)
    raw = JSON.generate(payload)
    receiver.handle(raw_body: raw, signature: Wire.sign(raw, secret: secret))
  end

  def body_of(reply) = JSON.parse(reply.body)

  it "verifies, dispatches to the named handler, and returns a signed ack" do
    reply = handle(Wire.result(analysis_id: "run-1"))

    expect(reply.status).to eq(200)
    expect(body_of(reply)).to eq({"ok" => true})
    expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)

    delivered = SpecResultHandler.store.fetch("run-1")
    expect(delivered.metadata).to eq({resource_type: "SupportTicket", resource_id: 42})
    expect(delivered.draft).to eq("Hi there")
    expect(delivered.note).to eq("Summary. [run trace](https://rc/runs/1)")
  end

  it "rejects a forged signature with a signed 401 (and never dispatches)" do
    reply = handle(Wire.result, secret: "wrong")
    expect(reply.status).to eq(401)
    expect(body_of(reply).fetch("error")).to include(
      "class" => "bad_signature",
      "code" => "BAD_SIGNATURE",
      "hint" => a_kind_of(String),
      "docs" => a_string_ending_with("#bad_signature")
    )
    expect(SpecResultHandler.store).to be_empty
    expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
  end

  it "rejects a missing signature with 401" do
    raw = JSON.generate(Wire.result)
    expect(receiver.handle(raw_body: raw, signature: nil).status).to eq(401)
  end

  it "rejects a missing required field with 400" do
    payload = Wire.result
    payload.delete("analysis_id")
    expect(handle(payload).status).to eq(400)
  end

  it "rejects a stale issued_at with 409" do
    expect(handle(Wire.result(issued_at: (Time.now.utc - 3600).iso8601)).status).to eq(409)
  end

  it "acks a duplicate nonce within the window WITHOUT re-dispatching (host nonce = run_id)" do
    payload = Wire.result(analysis_id: "run-dup", nonce: "fixed")
    expect(handle(payload).status).to eq(200)
    SpecResultHandler.reset!

    reply = handle(payload)
    expect(reply.status).to eq(200)
    expect(body_of(reply)).to eq({"ok" => true})
    expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
    # The redelivery never reached the handler — it was deduped, not reprocessed.
    expect(SpecResultHandler.store).to be_empty
  end

  it "redelivery with a FRESH nonce dispatches again → handler upserts, not duplicates" do
    # Same analysis_id, two different nonces (a retry outside the original window).
    handle(Wire.result(analysis_id: "run-7", nonce: "n1"))
    handle(Wire.result(analysis_id: "run-7", nonce: "n2"))
    expect(SpecResultHandler.store.size).to eq(1)
    expect(SpecResultHandler.store).to have_key("run-7")
  end

  it "releases the nonce when dispatch fails so the host's redelivery is processed" do
    config.result_handler = "SpecBoomHandler"
    payload = Wire.result(analysis_id: "run-boom", nonce: "same-run-id")
    expect(handle(payload).status).to eq(500)

    # Same nonce, but the failed delivery was never processed → not a duplicate.
    config.result_handler = "SpecResultHandler"
    expect(handle(payload).status).to eq(200)
    expect(SpecResultHandler.store).to have_key("run-boom")
  end

  it "exposes the host-managed session_id on the dispatched result" do
    handle(Wire.result(analysis_id: "s1", session_id: "sess-xyz"))
    expect(SpecResultHandler.store.fetch("s1").session_id).to eq("sess-xyz")
  end

  it "round-trips: a delivered result's session_id rides a follow-up trigger" do
    # Deliver a result carrying the host's session_id.
    handle(Wire.result(analysis_id: "run-1", session_id: "sess-cont"))
    delivered = SpecResultHandler.store.fetch("run-1")

    # The customer continues the thread with ONLY the new message.
    Wire.stub_trigger
    RootCause::Embassy::Client.new(config).start_analysis(
      subject: "follow up", body: "new turn only", session_id: delivered.session_id
    )

    expect(
      a_request(:post, Wire::TRIGGER_URL).with { |req|
        JSON.parse(req.body)["session_id"] == "sess-cont"
      }
    ).to have_been_made
  end

  it "dispatches a decline result (ok? == false)" do
    handle(Wire.result(analysis_id: "d1", draft: nil, decline: {"reason" => "out of scope"}))
    result = SpecResultHandler.store.fetch("d1")
    expect(result.ok?).to be(false)
    expect(result.decline).to eq({reason: "out of scope"})
  end

  context "when result_handler is unconfigured" do
    let(:config) { Wire.config(result_handler: nil) }

    it "fails closed with a signed structured error (no ack)" do
      reply = handle(Wire.result)
      expect(reply.status).to eq(500)
      expect(body_of(reply).dig("error", "class")).to eq("handler_error")
      expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
    end
  end

  context "when result_handler names an unknown constant" do
    let(:config) { Wire.config(result_handler: "NoSuchHandler") }

    it "fails closed with handler_error" do
      reply = handle(Wire.result)
      expect(reply.status).to eq(500)
      expect(body_of(reply).dig("error", "class")).to eq("handler_error")
    end
  end

  context "when the handler raises" do
    let(:config) { Wire.config(result_handler: "SpecBoomHandler") }

    it "returns a signed 500 and does NOT ack (so rootcause redelivers)" do
      reply = handle(Wire.result)
      expect(reply.status).to eq(500)
      expect(body_of(reply).dig("error", "class")).to eq("internal_error")
      # Message is the class only — never the (possibly input-bearing) message.
      expect(body_of(reply).dig("error", "message")).to eq("RuntimeError")
      expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
    end
  end

  it "accepts a Class (not just a name) as the handler" do
    config.result_handler = SpecResultHandler
    expect(handle(Wire.result(analysis_id: "c1")).status).to eq(200)
    expect(SpecResultHandler.store).to have_key("c1")
  end
end

RSpec.describe RootCause::Embassy::ResultRackApp do
  let(:config) { Wire.config(result_handler: "SpecResultHandler") }
  let(:receiver) { RootCause::Embassy::ResultReceiver.new(config) }
  let(:app) { described_class.new(receiver: receiver) }

  before { SpecResultHandler.reset! }

  def env_for(method:, body: "", signature: nil)
    {
      "REQUEST_METHOD" => method,
      "rack.input" => StringIO.new(body),
      "HTTP_X_WEBHOOK_SIGNATURE" => signature
    }
  end

  it "handles a POSTed result and returns a signed JSON triple" do
    raw = JSON.generate(Wire.result(analysis_id: "rk-1"))
    status, headers, body = app.call(env_for(method: "POST", body: raw, signature: Wire.sign(raw)))

    expect(status).to eq(200)
    joined = body.join
    expect(headers["content-type"]).to eq("application/json")
    expect(headers["X-Webhook-Signature"]).to eq(Wire.sign(joined))
    expect(JSON.parse(joined)).to eq({"ok" => true})
    expect(SpecResultHandler.store).to have_key("rk-1")
  end

  it "returns 405 for a non-POST method" do
    status, headers, = app.call(env_for(method: "GET"))
    expect(status).to eq(405)
    expect(headers["allow"]).to eq("POST")
  end

  it "passes a bad signature through to a signed 401" do
    raw = JSON.generate(Wire.result)
    status, = app.call(env_for(method: "POST", body: raw, signature: "sha256=nope"))
    expect(status).to eq(401)
  end

  it "falls back to the globally-configured receiver when none is injected" do
    RootCause::Embassy.configure { |c|
      c.secret = Wire::SECRET
      c.fetch_url = Wire::FETCH_URL
      c.result_handler = "SpecResultHandler"
      c.logger = nil
    }
    bare = described_class.new
    status, = bare.call(env_for(method: "POST", body: "x", signature: "sha256=nope"))
    expect(status).to eq(401)
  end
end
