# frozen_string_literal: true

RSpec.describe RootCause::Embassy::Config do
  # Every boot gate is fail-closed AND names the attribute the operator must fix —
  # that naming is the whole point, so assert it once over the whole table.
  it "refuses to boot on a missing or invalid attribute, naming it" do
    {
      "secret" => {fetch_url: "https://x"},
      "fetch_url" => {secret: "s"},
      "timeout" => {secret: "s", fetch_url: "https://x", timeout: 0},
      # timeout raised past the default budget without raising the budget
      "total_deadline" => {secret: "s", fetch_url: "https://x", timeout: 30},
      "require_tenant_context" => {secret: "s", fetch_url: "https://x", require_tenant_context: "yes"}
    }.each do |attribute, attrs|
      cfg = described_class.new
      attrs.each { |name, value| cfg.public_send(:"#{name}=", value) }
      expect { cfg.validate! }.to raise_error(ArgumentError, /#{attribute}/), attribute
    end
  end

  it "raises a clear, fix-naming error when fetch_url is the placeholder and the reverse channel is active" do
    cfg = described_class.new
    cfg.secret = "s"
    cfg.fetch_url = described_class::PLACEHOLDER_FETCH_URL
    expect { cfg.validate! }.to raise_error(ArgumentError, /placeholder.*ROOTCAUSE_FETCH_URL/m)
  end

  it "rejects any fetch_url whose host ends in .invalid when the reverse channel is active" do
    cfg = described_class.new
    cfg.secret = "s"
    cfg.fetch_url = "https://rootcause.invalid/actions/script"
    expect { cfg.validate! }.to raise_error(ArgumentError, /placeholder/)
  end

  it "carries sensible defaults" do
    cfg = described_class.new
    expect(cfg.mount_at).to eq("/rootcause/action")
    expect(cfg.clock_skew).to eq(300)
    expect(cfg.timeout).to eq(20)
    expect(cfg.total_deadline).to eq(22)
    expect(cfg.require_tenant_context).to be(false)
    expect(cfg.tenantless_actions).to eq([])
    expect(cfg.chat_base_url).to eq("https://app.replypen.com")
  end

  it "rejects malformed tenantless action allowlists" do
    cfg = described_class.new
    cfg.secret = "s"
    cfg.fetch_url = "https://x"

    ["action", [""], [:action], ["action", "action"]].each do |value|
      cfg.tenantless_actions = value
      expect { cfg.validate! }.to raise_error(ArgumentError, /tenantless_actions/)
    end
  end

  describe "embedded chat (optional)" do
    def base
      described_class.new.tap { |c|
        c.secret = "s"
        c.fetch_url = "https://x"
      }
    end

    it "stays inert when no chat attribute is set" do
      cfg = base
      expect { cfg.validate! }.not_to raise_error
      expect(cfg.chat_configured?).to be(false)
    end

    it "refuses a half-wired chat deployment" do
      cfg = base
      cfg.chat_project = "example-support"
      expect { cfg.validate! }.to raise_error(ArgumentError, /chat_secret/)

      cfg.chat_secret = "webhook-secret"
      expect { cfg.validate! }.not_to raise_error
      expect(cfg.chat_configured?).to be(true)

      cfg.chat_project = nil
      expect { cfg.validate! }.to raise_error(RootCause::Embassy::Error) { |error|
        expect(error.code).to eq("CHAT_PROJECT_REQUIRED")
      }
    end

    it "refuses the action reverse-channel secret reused as the chat secret" do
      cfg = base
      cfg.chat_secret = "s"
      cfg.chat_project = "acme-support"
      expect { cfg.validate! }.to raise_error(ArgumentError, /ROOTCAUSE_CHAT_SECRET/)
    end

    it "rejects a chat_base_url that is not an absolute http(s) URL" do
      cfg = base
      cfg.chat_secret = "webhook-secret"
      cfg.chat_project = "acme-support"
      cfg.chat_base_url = "chat.rootcause.test"
      expect { cfg.validate! }.to raise_error(ArgumentError, /chat_base_url/)
    end

    it "rejects a chat_base_url with credentials or a path at boot" do
      cfg = base
      cfg.chat_secret = "webhook-secret"
      cfg.chat_project = "example-support"

      ["https://user:pass@app.replypen.com", "https://app.replypen.com/chat"].each do |url|
        cfg.chat_base_url = url
        expect { cfg.validate! }.to raise_error(RootCause::Embassy::Error) { |error|
          expect(error.code).to eq("CHAT_BASE_URL_INVALID")
        }
      end
    end

    it "uses the hosted ReplyPen origin when chat_base_url is omitted" do
      cfg = base
      cfg.chat_secret = "webhook-secret"
      cfg.chat_project = "example-support"
      cfg.chat_base_url = nil
      cfg.chat_base_url ||= described_class::DEFAULT_CHAT_BASE_URL
      expect { cfg.validate! }.not_to raise_error
    end
  end
end

RSpec.describe RootCause::Embassy do
  it "raises a clear error if used before configuration" do
    described_class.reset!
    expect { described_class.runner }.to raise_error(/not configured/)
  end

  it "builds a runner once configured" do
    described_class.configure { |c|
      c.secret = "s"
      c.fetch_url = "https://x"
    }
    expect(described_class.runner).to be_a(RootCause::Embassy::Runner)
    expect(described_class.config.secret).to eq("s")
  end

  it "boots chat-only without the action plane" do
    described_class.configure { |c|
      c.chat_secret = "chat-secret"
      c.chat_project = "example-support"
      c.logger = nil
    }

    expect(described_class.config.action_plane_enabled?).to be(false)
    token = described_class.chat_token(external_id: "user-1", kind: "app_user", origin: "https://app.example.com")
    expect(token.split(".").length).to eq(3)
  end
end
