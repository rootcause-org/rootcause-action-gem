# frozen_string_literal: true

RSpec.describe RootCause::Embassy::Config do
  it "validates fail-closed when the secret is missing" do
    cfg = described_class.new
    cfg.fetch_url = "https://x"
    expect { cfg.validate! }.to raise_error(ArgumentError, /secret/)
  end

  it "validates fail-closed when fetch_url is missing" do
    cfg = described_class.new
    cfg.secret = "s"
    expect { cfg.validate! }.to raise_error(ArgumentError, /fetch_url/)
  end

  it "rejects a non-positive timeout" do
    cfg = described_class.new
    cfg.secret = "s"
    cfg.fetch_url = "https://x"
    cfg.timeout = 0
    expect { cfg.validate! }.to raise_error(ArgumentError, /timeout/)
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

  it "allows the placeholder fetch_url for an inert app (no secret configured)" do
    cfg = described_class.new
    cfg.fetch_url = described_class::PLACEHOLDER_FETCH_URL
    # No secret → the secret-required check fires first; the placeholder itself is fine.
    expect { cfg.validate! }.to raise_error(ArgumentError, /secret/)
  end

  it "accepts a real fetch_url with the reverse channel active" do
    cfg = described_class.new
    cfg.secret = "s"
    cfg.fetch_url = "https://rootcause.example.com/actions/script"
    expect { cfg.validate! }.not_to raise_error
  end

  it "carries sensible defaults" do
    cfg = described_class.new
    expect(cfg.mount_at).to eq("/rootcause/action")
    expect(cfg.clock_skew).to eq(300)
    expect(cfg.timeout).to eq(20)
    expect(cfg.total_deadline).to eq(22)
    expect(cfg.require_tenant_context).to be(false)
  end

  it "rejects a total_deadline that does not exceed the execute timeout" do
    cfg = described_class.new
    cfg.secret = "s"
    cfg.fetch_url = "https://x"
    cfg.timeout = 30 # raised past the default budget without raising the budget
    expect { cfg.validate! }.to raise_error(ArgumentError, /total_deadline/)
  end

  it "rejects a non-boolean tenant-context requirement" do
    cfg = described_class.new
    cfg.secret = "s"
    cfg.fetch_url = "https://x"
    cfg.require_tenant_context = "yes"
    expect { cfg.validate! }.to raise_error(ArgumentError, /require_tenant_context/)
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
      cfg.chat_base_url = "https://chat.rootcause.test"
      expect { cfg.validate! }.to raise_error(ArgumentError, /chat_secret/)

      cfg.chat_secret = "webhook-secret"
      expect { cfg.validate! }.to raise_error(ArgumentError, /chat_project/)

      cfg.chat_project = "kampadmin-support"
      expect { cfg.validate! }.not_to raise_error
      expect(cfg.chat_configured?).to be(true)
    end

    it "refuses the action reverse-channel secret reused as the chat secret" do
      cfg = base
      cfg.chat_secret = "s"
      cfg.chat_project = "kampadmin-support"
      expect { cfg.validate! }.to raise_error(ArgumentError, /ROOTCAUSE_CHAT_SECRET/)
    end

    it "rejects a chat_base_url that is not an absolute http(s) URL" do
      cfg = base
      cfg.chat_secret = "webhook-secret"
      cfg.chat_project = "kampadmin-support"
      cfg.chat_base_url = "chat.rootcause.test"
      expect { cfg.validate! }.to raise_error(ArgumentError, /chat_base_url/)
    end

    it "mints without chat_base_url — the URL is only the widget tag's concern" do
      cfg = base
      cfg.chat_secret = "webhook-secret"
      cfg.chat_project = "kampadmin-support"
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
end
