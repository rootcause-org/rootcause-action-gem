# frozen_string_literal: true

require "openssl"
require "json"
require "securerandom"
require "time"
require "uri"
require "cgi"

module RootCause
  module Embassy
    # The MINT side of rootcause's embedded-chat trust boundary. The customer's backend mints a
    # short-lived HS256 token asserting *who is chatting* (and, on tenant-enabled projects, *inside
    # which tenant*); rootcause only ever VERIFIES it. The browser never sees the key, so it cannot
    # mint a token for another user, another tenant, another origin, or a later expiry.
    #
    # The signing key is the project's `webhook_secret` (`chat_secret`) — a DIFFERENT privilege
    # boundary from the action-plane reverse-channel `secret`, and the two never fall back to one
    # another: a leaked chat key must not buy action execution.
    #
    # Hand-rolled HS256 (OpenSSL::HMAC + base64url + JSON) keeps the gem stdlib-only; the claim set
    # mirrors the host's verifier (rootcause `internal/chat/jwt.go`) exactly.
    module Chat
      # Token lifetime the host is tuned for: long enough that a page left open across a working
      # session can still open its chat without a reload, short enough that a leaked token ages out
      # on its own. The `jti` is single-use anyway, so this only bounds the *unopened* window.
      # The host also allows 60s clock skew.
      DEFAULT_TTL = 7200

      # How the identity was established, carried through to rootcause as the principal's assurance
      # level. "customer_backend_jwt" = asserted by the customer's own authenticated server session.
      DEFAULT_ASSURANCE = "customer_backend_jwt"

      # Path of the hosted loader on the rootcause origin (`chat_base_url`).
      LOADER_PATH = "/chat/widget/v1/loader.js"

      # The loader is immutable-cached by the host. Bump this whenever the generated tag starts
      # relying on new loader behavior, so a page cannot pair fresh attributes with stale JavaScript.
      LOADER_CONTRACT = "2"

      module_function

      # Mint an embed token. `external_id` is the opaque, stable user id rootcause anchors a
      # conversation to (never a name/email); `kind` names the identity namespace it lives in
      # (e.g. "kampadmin_admin"). `tenant` is the rootcause tenant SLUG — required by the host on a
      # tenant-enabled project, and it must come from the server-side authorized tenant context, not
      # from client input: everything below is inside the signature, so a swapped tenant is a broken
      # token.
      #
      # @param origin [String] the browser Origin the token is pinned to ("https://host[:port]");
      #   the host re-checks it against the request's Origin header and the project allowlist.
      # @param locale [String, Symbol, nil] UI language for the chat panel ("en", "nl", "fr"; a region
      #   subtag like "nl-BE" is fine). A presentation hint only — it grants nothing, and the panel
      #   falls back to the browser language and then English on anything it does not support.
      # @param color_scheme [String, Symbol, nil] forced panel color scheme ("light" or "dark"). A
      #   presentation hint only — it grants nothing, and anything else falls back to following the
      #   viewer's own light/dark preference.
      # @return [String] compact HS256 JWT
      # @raise [ArgumentError] unconfigured chat, or a blank/malformed argument
      def token(external_id:, origin:, kind:, tenant: nil, locale: nil, color_scheme: nil, ttl: DEFAULT_TTL,
        asserted_by: nil, assurance: DEFAULT_ASSURANCE, config: Embassy.config, now: Time.now)
        secret = presence(config.chat_secret) ||
          raise(ArgumentError, "RootCause::Embassy: chat_secret is not configured (ROOTCAUSE_CHAT_SECRET)")
        project = presence(config.chat_project) ||
          raise(ArgumentError, "RootCause::Embassy: chat_project is not configured (ROOTCAUSE_CHAT_PROJECT)")
        external_id = required(external_id, "external_id")
        kind = required(kind, "kind")
        ttl = Integer(ttl)
        raise ArgumentError, "RootCause::Embassy: chat token ttl must be positive" unless ttl > 0

        issued = now.to_i
        claims = {
          "sub" => external_id,
          "aud" => audience(project),
          "iss" => project,
          # Single-use at the host: the jti is burned when a session opens, so a captured token
          # cannot be replayed into a second session.
          "jti" => SecureRandom.uuid,
          "origin" => normalize_origin(origin),
          "iat" => issued,
          "nbf" => issued,
          "exp" => issued + ttl,
          "principal" => {
            "kind" => kind,
            "external_id" => external_id,
            "asserted_by" => presence(asserted_by) || project,
            "assurance" => presence(assurance) || DEFAULT_ASSURANCE
          }
        }
        # Omitted rather than blank: the host reads a present-but-empty tenant as "no tenant", and an
        # explicit null would be indistinguishable while making the wire noisier.
        claims["tenant"] = tenant.to_s unless blank?(tenant)
        claims["locale"] = locale.to_s unless blank?(locale)
        claims["color_scheme"] = color_scheme.to_s unless blank?(color_scheme)

        encode(claims, secret)
      end

      # The host's required `aud` for a project's embed token.
      def audience(project) = "rootcause:chat:#{project}"

      # The loader <script> snippet, as an HTML-ESCAPED plain String (framework-agnostic core; the
      # Rails view shell is ChatViewHelper). Mints a fresh token per render — tokens are short-lived
      # and single-use, so they are never cached across renders.
      #
      # @param mode [Symbol, String, nil] :page for the full-page surface (default: the floating widget)
      # @param target [String, nil] CSS selector the page-mode surface mounts into, e.g. "#rc-chat"
      # @param locale [String, Symbol, nil] see .token — rides BOTH the claim and data-rc-locale, so the
      #   loader can localize the panel's server-rendered chrome without first decoding the token.
      # @param color_scheme [String, Symbol, nil] see .token — rides BOTH the claim and
      #   data-rc-color-scheme, so the panel paints in the right scheme without a token decode first.
      def widget_tag_html(mode: nil, target: nil, locale: nil, color_scheme: nil, config: Embassy.config,
        **token_options)
        base = presence(config.chat_base_url) ||
          raise(ArgumentError, "RootCause::Embassy: chat_base_url is not configured (ROOTCAUSE_CHAT_BASE_URL)")
        attrs = {
          "src" => base.to_s.chomp("/") + LOADER_PATH + "?v=#{LOADER_CONTRACT}",
          "data-rc-project" => config.chat_project.to_s,
          "data-rc-token" => token(config: config, locale: locale, color_scheme: color_scheme, **token_options)
        }
        attrs["data-rc-mode"] = mode.to_s unless blank?(mode)
        attrs["data-rc-target"] = target.to_s unless blank?(target)
        attrs["data-rc-locale"] = locale.to_s unless blank?(locale)
        attrs["data-rc-color-scheme"] = color_scheme.to_s unless blank?(color_scheme)
        rendered = attrs.map { |k, v| %(#{k}="#{CGI.escapeHTML(v)}") }.join(" ")
        "<script #{rendered}></script>"
      end

      # --- internals ---

      # Compact JWS: base64url(header).base64url(payload).base64url(HMAC-SHA256 over those bytes).
      # The signature covers the EXACT transmitted segments, never a re-encode.
      def encode(claims, secret)
        signing_input = "#{b64(JSON.generate("alg" => "HS256", "typ" => "JWT"))}.#{b64(JSON.generate(claims))}"
        "#{signing_input}.#{b64(OpenSSL::HMAC.digest("SHA256", secret.to_s, signing_input))}"
      end

      # base64url, unpadded — `pack` rather than the base64 stdlib, which is no longer a default gem.
      def b64(bytes) = [bytes].pack("m0").tr("+/", "-_").delete("=")

      # A browser Origin is scheme://host[:port] with nothing after it. We canonicalize (drop a bare
      # trailing slash, lowercase the host) and refuse anything path/query-bearing, because the host
      # compares this claim byte-for-byte with the request's Origin header — a near-miss here reads
      # as a forged token at runtime, far from its cause.
      def normalize_origin(origin)
        raw = required(origin, "origin")
        uri = begin
          URI.parse(raw)
        rescue URI::InvalidURIError
          raise ArgumentError, "RootCause::Embassy: chat origin is not a valid URL: #{raw.inspect}"
        end
        unless %w[http https].include?(uri.scheme) && !blank?(uri.host) &&
            blank?(uri.query) && blank?(uri.fragment) && ["", "/"].include?(uri.path.to_s)
          raise ArgumentError,
            "RootCause::Embassy: chat origin must be scheme://host[:port] with no path, got #{raw.inspect}"
        end
        port = (uri.port == uri.default_port) ? "" : ":#{uri.port}"
        "#{uri.scheme}://#{uri.host.downcase}#{port}"
      end

      def required(value, name)
        presence(value) || raise(ArgumentError, "RootCause::Embassy: chat token #{name} is required")
      end

      def presence(value) = blank?(value) ? nil : value.to_s

      def blank?(value) = value.nil? || value.to_s.empty?
    end
  end
end
