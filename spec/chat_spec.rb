# frozen_string_literal: true

RSpec.describe RootCause::Embassy::Chat do
  let(:cfg) { Wire.chat_config }

  def mint(**overrides)
    described_class.token(
      external_id: "admin-uuid-1", kind: "kampadmin_admin", origin: Wire::CHAT_ORIGIN, config: cfg, **overrides
    )
  end

  describe ".token" do
    it "signs with the chat secret and carries the host's required claim set" do
      now = Time.at(1_700_000_000)
      header, claims = Wire.decode_jwt(mint(tenant: "heyo", now: now))

      expect(header).to eq("alg" => "HS256", "typ" => "JWT")
      expect(claims).to include(
        "sub" => "admin-uuid-1",
        "aud" => "rootcause:chat:#{Wire::CHAT_PROJECT}",
        "iss" => Wire::CHAT_PROJECT,
        "origin" => Wire::CHAT_ORIGIN,
        "tenant" => "heyo",
        "iat" => now.to_i,
        "nbf" => now.to_i,
        "exp" => now.to_i + 900
      )
      expect(claims["principal"]).to eq(
        "kind" => "kampadmin_admin",
        "external_id" => "admin-uuid-1",
        "asserted_by" => Wire::CHAT_PROJECT,
        "assurance" => "customer_backend_jwt"
      )
    end

    it "does not verify under the action reverse-channel secret" do
      # The two secrets are separate privilege boundaries — neither may sign for the other.
      expect { Wire.decode_jwt(mint, secret: Wire::SECRET) }.to raise_error(/signature/)
    end

    it "omits tenant entirely when none is given" do
      _, claims = Wire.decode_jwt(mint)
      expect(claims).not_to have_key("tenant")

      _, blank = Wire.decode_jwt(mint(tenant: ""))
      expect(blank).not_to have_key("tenant")
    end

    it "carries locale only when given" do
      _, claims = Wire.decode_jwt(mint(locale: "nl-BE"))
      expect(claims["locale"]).to eq("nl-BE")

      expect(Wire.decode_jwt(mint).last).not_to have_key("locale")
      expect(Wire.decode_jwt(mint(locale: "")).last).not_to have_key("locale")
    end

    it "carries color_scheme only when given, unvalidated" do
      _, claims = Wire.decode_jwt(mint(color_scheme: "dark"))
      expect(claims["color_scheme"]).to eq("dark")

      # Pass-through: the host allowlists the value, a bad one only falls back to auto.
      expect(Wire.decode_jwt(mint(color_scheme: :sepia)).last["color_scheme"]).to eq("sepia")

      expect(Wire.decode_jwt(mint).last).not_to have_key("color_scheme")
      expect(Wire.decode_jwt(mint(color_scheme: "")).last).not_to have_key("color_scheme")
    end

    it "honours a custom ttl and keeps nbf/iat at issue time" do
      now = Time.at(1_700_000_000)
      _, claims = Wire.decode_jwt(mint(ttl: 60, now: now))
      expect(claims.values_at("nbf", "iat", "exp")).to eq([now.to_i, now.to_i, now.to_i + 60])
    end

    it "mints a fresh single-use jti every time" do
      jtis = Array.new(5) { Wire.decode_jwt(mint).last["jti"] }
      expect(jtis.uniq.size).to eq(5)
    end

    it "allows overriding the principal's provenance" do
      _, claims = Wire.decode_jwt(mint(asserted_by: "kampadmin", assurance: "sso"))
      expect(claims["principal"]).to include("asserted_by" => "kampadmin", "assurance" => "sso")
    end

    it "canonicalizes the origin the host compares byte-for-byte" do
      _, claims = Wire.decode_jwt(mint(origin: "https://ADMIN.kampadmin.be/"))
      expect(claims["origin"]).to eq("https://admin.kampadmin.be")

      _, with_port = Wire.decode_jwt(mint(origin: "http://localhost:3000"))
      expect(with_port["origin"]).to eq("http://localhost:3000")
    end

    it "refuses an origin that is not a bare scheme://host[:port]" do
      expect { mint(origin: "https://admin.kampadmin.be/t/heyo/admin") }.to raise_error(ArgumentError, /origin/)
      expect { mint(origin: "admin.kampadmin.be") }.to raise_error(ArgumentError, /origin/)
    end

    it "refuses blank identity, a blank origin, and a non-positive ttl" do
      expect { mint(external_id: "") }.to raise_error(ArgumentError, /external_id/)
      expect { mint(kind: nil) }.to raise_error(ArgumentError, /kind/)
      expect { mint(origin: nil) }.to raise_error(ArgumentError, /origin/)
      expect { mint(ttl: 0) }.to raise_error(ArgumentError, /ttl/)
    end

    it "names the missing ENV when chat is not configured" do
      expect { mint(config: Wire.config) }.to raise_error(ArgumentError, /ROOTCAUSE_CHAT_SECRET/)
    end

    it "is reachable as RootCause::Embassy.chat_token on the configured singleton" do
      RootCause::Embassy.configure do |c|
        c.secret = Wire::SECRET
        c.fetch_url = Wire::FETCH_URL
        c.chat_secret = Wire::CHAT_SECRET
        c.chat_project = Wire::CHAT_PROJECT
      end
      token = RootCause::Embassy.chat_token(
        external_id: "admin-uuid-1", kind: "kampadmin_admin", origin: Wire::CHAT_ORIGIN
      )
      expect(Wire.decode_jwt(token).last["iss"]).to eq(Wire::CHAT_PROJECT)
    end
  end

  describe ".widget_tag_html" do
    def tag(**overrides)
      described_class.widget_tag_html(
        external_id: "admin-uuid-1", kind: "kampadmin_admin", origin: Wire::CHAT_ORIGIN, config: cfg, **overrides
      )
    end

    it "emits the loader with the publishable project and a fresh token" do
      html = tag
      expect(html).to start_with(
        %(<script src="#{Wire::CHAT_BASE_URL}/chat/widget/v1/loader.js?v=#{described_class::LOADER_CONTRACT}" )
      )
      expect(html).to include(%(data-rc-project="#{Wire::CHAT_PROJECT}"))
      expect(html).to end_with("></script>")

      token = html[/data-rc-token="([^"]+)"/, 1]
      expect(Wire.decode_jwt(token).last["sub"]).to eq("admin-uuid-1")
    end

    it "adds page-mode attributes only when asked" do
      expect(tag).not_to include("data-rc-mode")
      expect(tag(mode: :page, target: "#rc-chat"))
        .to include(%(data-rc-mode="page"), %(data-rc-target="#rc-chat"))
    end

    it "puts locale on both the claim and the loader attribute, only when asked" do
      expect(tag).not_to include("data-rc-locale")

      html = tag(locale: :nl)
      expect(html).to include(%(data-rc-locale="nl"))
      expect(Wire.decode_jwt(html[/data-rc-token="([^"]+)"/, 1]).last["locale"]).to eq("nl")
    end

    it "puts color_scheme on both the claim and the loader attribute, only when asked" do
      expect(tag).not_to include("data-rc-color-scheme")

      html = tag(color_scheme: :light)
      expect(html).to include(%(data-rc-color-scheme="light"))
      expect(Wire.decode_jwt(html[/data-rc-token="([^"]+)"/, 1]).last["color_scheme"]).to eq("light")
    end

    it "html-escapes every attribute value so no value can break out of the tag" do
      html = tag(config: Wire.chat_config(chat_project: %(evil" onload="x)), mode: %(p"><img src=x))
      expect(html).to include("&quot;", "&lt;img")
      expect(html.scan("<script").size).to eq(1)
      expect(html).not_to include(%(onload="x"))
    end

    it "does not double a slash when chat_base_url has a trailing one" do
      html = tag(config: Wire.chat_config(chat_base_url: "#{Wire::CHAT_BASE_URL}/"))
      expect(html).to include(
        %(src="#{Wire::CHAT_BASE_URL}/chat/widget/v1/loader.js?v=#{described_class::LOADER_CONTRACT}")
      )
    end

    it "names the missing ENV when chat_base_url is unset" do
      expect { tag(config: Wire.chat_config(chat_base_url: nil)) }
        .to raise_error(ArgumentError, /ROOTCAUSE_CHAT_BASE_URL/)
    end
  end

  describe RootCause::Embassy::ChatViewHelper do
    let(:view) { Object.new.extend(described_class) }

    it "returns the escaped core snippet, marked safe when ActiveSupport is present" do
      html = view.chat_widget_tag(
        external_id: "admin-uuid-1", kind: "kampadmin_admin", origin: Wire::CHAT_ORIGIN, config: Wire.chat_config
      )
      expect(html).to include("data-rc-token=")
      expect(html).to eq(html.to_s)
    end
  end
end
