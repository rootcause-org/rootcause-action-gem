# frozen_string_literal: true

# The outbound trigger: build → sign → POST → parse {analysis_id}. The host's
# trigger endpoint is stubbed via Wire (202 + analysis_id); no live host.
RSpec.describe RootCause::Embassy::Client do
  let(:config) { Wire.config }
  let(:client) { described_class.new(config) }

  # Strict base64, stdlib only (matches the gem's decode path).
  def b64(str) = [str].pack("m0")

  it "builds the documented body, signs the raw JSON, and returns the analysis_id" do
    Wire.stub_trigger(analysis_id: "run-123")

    analysis = client.start_analysis(
      subject: "Login fails",
      body: "plain text",
      metadata: {resource_type: "SupportTicket", resource_id: 42}
    )

    expect(analysis.analysis_id).to eq("run-123")
    expect(analysis.status).to eq("queued")

    expect(
      a_request(:post, Wire::TRIGGER_URL).with { |req|
        body = JSON.parse(req.body)
        sig_ok = RootCause::Embassy::Signature.valid?(
          req.headers["X-Webhook-Signature"], req.body, secret: Wire::SECRET
        )
        sig_ok &&
          body["subject"] == "Login fails" &&
          body["body"] == "plain text" &&
          body["metadata"] == {"resource_type" => "SupportTicket", "resource_id" => 42} &&
          body["nonce"].is_a?(String) && !body["nonce"].empty? &&
          body["issued_at"].is_a?(String)
      }
    ).to have_been_made
  end

  it "returns the host-minted session_id from the 202" do
    Wire.stub_trigger(analysis_id: "run-1", session_id: "sess-1")
    analysis = client.start_analysis(subject: "s", body: "b")
    expect(analysis.session_id).to eq("sess-1")
  end

  it "forwards session_id in the trigger body on a follow-up" do
    Wire.stub_trigger
    client.start_analysis(subject: "follow up", body: "more", session_id: "sess-99")

    expect(
      a_request(:post, Wire::TRIGGER_URL).with { |req|
        JSON.parse(req.body)["session_id"] == "sess-99"
      }
    ).to have_been_made
  end

  it "forwards tenant in the trigger body for tenant-enabled projects" do
    Wire.stub_trigger
    client.start_analysis(subject: "support ticket", body: "details", tenant: "heyo")

    expect(
      a_request(:post, Wire::TRIGGER_URL).with { |req|
        JSON.parse(req.body)["tenant"] == "heyo"
      }
    ).to have_been_made
  end

  describe "principal" do
    it "sends exactly the host's field names, omitting the nils" do
      Wire.stub_trigger
      client.start_analysis(
        subject: "s", body: "b",
        principal: {kind: "probackup_user", external_id: "u-42", asserted_by: "intercom", tenant_hint: nil}
      )

      expect(
        a_request(:post, Wire::TRIGGER_URL).with { |req|
          JSON.parse(req.body)["principal"] == {
            "kind" => "probackup_user", "external_id" => "u-42", "asserted_by" => "intercom"
          }
        }
      ).to have_been_made
    end

    it "is omitted entirely when nil (the trigger route strict-decodes)" do
      Wire.stub_trigger
      client.start_analysis(subject: "s", body: "b")

      expect(
        a_request(:post, Wire::TRIGGER_URL).with { |req| !JSON.parse(req.body).key?("principal") }
      ).to have_been_made
    end

    it "raises before sending when the identity core is incomplete" do
      Wire.stub_trigger
      expect {
        client.start_analysis(subject: "s", body: "b", principal: {kind: "probackup_user"})
      }.to raise_error(ArgumentError, /external_id/)
      expect(a_request(:post, Wire::TRIGGER_URL)).not_to have_been_made
    end

    it "drops unknown fields rather than letting the host 400 them" do
      Wire.stub_trigger
      client.start_analysis(
        subject: "s", body: "b",
        principal: {"kind" => "probackup_user", "external_id" => "u-1", "role" => "admin"}
      )

      expect(
        a_request(:post, Wire::TRIGGER_URL).with { |req|
          !JSON.parse(req.body)["principal"].key?("role")
        }
      ).to have_been_made
    end
  end

  it "omits session_id from the trigger body on the first turn (absent/blank)" do
    Wire.stub_trigger

    client.start_analysis(subject: "first", body: "turn")                  # default nil
    client.start_analysis(subject: "first", body: "turn", session_id: "")  # blank → omitted

    expect(
      a_request(:post, Wire::TRIGGER_URL).with { |req|
        !JSON.parse(req.body).key?("session_id")
      }
    ).to have_been_made.twice
  end

  it "round-trips: first turn's session_id rides the next trigger" do
    # Turn 1 — host mints a session.
    Wire.stub_trigger(analysis_id: "run-1", session_id: "sess-abc")
    first = client.start_analysis(subject: "Login fails", body: "details")
    expect(first.session_id).to eq("sess-abc")

    # Turn 2 — continue that session with ONLY the new message.
    client.start_analysis(subject: "still failing", body: "after reset", session_id: first.session_id)

    expect(
      a_request(:post, Wire::TRIGGER_URL).with { |req|
        body = JSON.parse(req.body)
        body["session_id"] == "sess-abc" && body["subject"] == "still failing"
      }
    ).to have_been_made
  end

  it "carries a within-cap attachment through verbatim" do
    Wire.stub_trigger
    encoded = b64("an error log")

    client.start_analysis(
      subject: "s", body: "b",
      attachments: [{filename: "error.log", mime_type: "text/plain", content_base64: encoded}]
    )

    expect(
      a_request(:post, Wire::TRIGGER_URL).with { |req|
        att = JSON.parse(req.body)["attachments"].first
        att == {"filename" => "error.log", "mime_type" => "text/plain", "content_base64" => encoded}
      }
    ).to have_been_made
  end

  it "raises ArgumentError BEFORE sending when an attachment is over the cap" do
    config.max_attachment_bytes = 8
    stub = Wire.stub_trigger

    expect {
      client.start_analysis(
        subject: "s", body: "b",
        attachments: [{filename: "big.bin", mime_type: "application/octet-stream", content_base64: b64("x" * 64)}]
      )
    }.to raise_error(ArgumentError, /exceeds max_attachment_bytes/)

    expect(stub).not_to have_been_requested
  end

  it "raises ArgumentError on malformed base64, before sending" do
    stub = Wire.stub_trigger
    expect {
      client.start_analysis(
        subject: "s", body: "b",
        attachments: [{filename: "x", mime_type: "text/plain", content_base64: "not valid base64!!!"}]
      )
    }.to raise_error(ArgumentError, /not valid/)
    expect(stub).not_to have_been_requested
  end

  it "raises TriggerError on a non-2xx response" do
    Wire.stub_trigger(status: 500)
    expect {
      client.start_analysis(subject: "s", body: "b")
    }.to raise_error(RootCause::Embassy::TriggerError, /500/)
  end

  it "raises TriggerError when the response omits analysis_id" do
    WebMock.stub_request(:post, Wire::TRIGGER_URL).to_return(
      status: 202, body: JSON.generate("status" => "queued")
    )
    expect {
      client.start_analysis(subject: "s", body: "b")
    }.to raise_error(RootCause::Embassy::TriggerError, /missing analysis_id/)
  end

  it "raises TriggerError on a transport failure" do
    WebMock.stub_request(:post, Wire::TRIGGER_URL).to_timeout
    expect {
      client.start_analysis(subject: "s", body: "b")
    }.to raise_error(RootCause::Embassy::TriggerError, /trigger failed/)
  end

  it "raises ArgumentError when trigger_url is unconfigured" do
    config.trigger_url = nil
    expect {
      client.start_analysis(subject: "s", body: "b")
    }.to raise_error(ArgumentError, /trigger_url is not configured/)
  end

  describe "logging" do
    let(:logger) { instance_double(Logger, info: nil) }
    let(:config) { Wire.config(logger: logger) }

    it "logs the analysis_id and metadata KEYS — never values" do
      Wire.stub_trigger(analysis_id: "run-9")
      client.start_analysis(
        subject: "s", body: "b",
        metadata: {resource_type: "SupportTicket", resource_id: 42}
      )
      expect(logger).to have_received(:info) do |line|
        expect(line).to include("analysis_id=run-9")
        expect(line).to include("metadata_keys=[\"resource_id\", \"resource_type\"]")
        expect(line).not_to include("SupportTicket")
        expect(line).not_to include("42")
      end
    end
  end

  # Fire-and-forget capture of the reply a human agent actually sent. Same build →
  # sign → POST shape as start_analysis, on the same reverse secret.
  describe "#capture_sent_message" do
    it "builds the documented body, signs the raw JSON, and returns the result struct" do
      Wire.stub_sent_message(id: "sm-7")

      result = client.capture_sent_message(
        sent_body: "Thanks, your reset link is on the way.",
        session_id: "support_ticket-abc",
        proposed_body: "Here is your reset link.",
        sender: "Astrid",
        metadata: {resource_type: "SupportTicket", resource_id: 42}
      )

      expect(result.ok).to be(true)
      expect(result.id).to eq("sm-7")
      expect(result).to be_frozen

      expect(
        a_request(:post, Wire::SENT_MESSAGE_URL).with { |req|
          body = JSON.parse(req.body)
          sig_ok = RootCause::Embassy::Signature.valid?(
            req.headers["X-Webhook-Signature"], req.body, secret: Wire::SECRET
          )
          sig_ok &&
            body["type"] == "sent_message" &&
            body["session_id"] == "support_ticket-abc" &&
            body["sent"] == {"body" => "Thanks, your reset link is on the way.", "sender" => "Astrid"} &&
            body["proposed"] == {"body" => "Here is your reset link."} &&
            body["metadata"] == {"resource_type" => "SupportTicket", "resource_id" => 42} &&
            body["nonce"].is_a?(String) && !body["nonce"].empty? &&
            body["issued_at"].is_a?(String)
        }
      ).to have_been_made
    end

    it "omits proposed and sender when not given" do
      Wire.stub_sent_message

      client.capture_sent_message(sent_body: "reply", session_id: "sess-1")

      expect(
        a_request(:post, Wire::SENT_MESSAGE_URL).with { |req|
          body = JSON.parse(req.body)
          !body.key?("proposed") && body["sent"] == {"body" => "reply"}
        }
      ).to have_been_made
    end

    it "returns ok with a nil id when the host echoes no body" do
      WebMock.stub_request(:post, Wire::SENT_MESSAGE_URL).to_return(status: 204, body: "")
      result = client.capture_sent_message(sent_body: "reply", session_id: "sess-1")
      expect(result.ok).to be(true)
      expect(result.id).to be_nil
    end

    it "raises ArgumentError BEFORE any HTTP when sent_message_url is unconfigured" do
      config.sent_message_url = nil
      stub = Wire.stub_sent_message
      expect {
        client.capture_sent_message(sent_body: "reply", session_id: "sess-1")
      }.to raise_error(ArgumentError, /sent_message_url is not configured/)
      expect(stub).not_to have_been_requested
    end

    it "raises ArgumentError on a blank sent_body, before sending" do
      stub = Wire.stub_sent_message
      expect {
        client.capture_sent_message(sent_body: "", session_id: "sess-1")
      }.to raise_error(ArgumentError, /sent_body is required/)
      expect(stub).not_to have_been_requested
    end

    it "raises ArgumentError on a blank session_id, before sending" do
      stub = Wire.stub_sent_message
      expect {
        client.capture_sent_message(sent_body: "reply", session_id: "")
      }.to raise_error(ArgumentError, /session_id is required/)
      expect(stub).not_to have_been_requested
    end

    it "raises SentMessageError on a non-2xx response" do
      Wire.stub_sent_message(status: 500)
      expect {
        client.capture_sent_message(sent_body: "reply", session_id: "sess-1")
      }.to raise_error(RootCause::Embassy::SentMessageError, /500/)
    end

    it "raises SentMessageError on a transport failure" do
      WebMock.stub_request(:post, Wire::SENT_MESSAGE_URL).to_timeout
      expect {
        client.capture_sent_message(sent_body: "reply", session_id: "sess-1")
      }.to raise_error(RootCause::Embassy::SentMessageError, /capture failed/)
    end

    describe "logging" do
      let(:logger) { instance_double(Logger, info: nil) }
      let(:config) { Wire.config(logger: logger) }

      it "logs session_id, metadata KEYS, and byte sizes — never bodies or values" do
        Wire.stub_sent_message
        client.capture_sent_message(
          sent_body: "secret reply text",
          session_id: "sess-1",
          proposed_body: "proposed text",
          metadata: {resource_type: "SupportTicket", resource_id: 42}
        )
        expect(logger).to have_received(:info) do |line|
          expect(line).to include("session_id=sess-1")
          expect(line).to include("metadata_keys=[\"resource_id\", \"resource_type\"]")
          expect(line).to include("sent_bytes=17")
          expect(line).to include("proposed_bytes=13")
          expect(line).not_to include("secret reply text")
          expect(line).not_to include("SupportTicket")
          expect(line).not_to include("42")
        end
      end
    end
  end
end
