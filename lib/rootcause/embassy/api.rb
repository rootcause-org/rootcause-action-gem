# frozen_string_literal: true

require "net/http"
require "uri"
require "json"

module RootCause
  module Embassy
    # The **API plane**: a generic, authenticated caller for *any* rootcause
    # backend endpoint — the same HTTP surface the `rc` CLI uses. Deliberately
    # NOT a set of per-endpoint wrappers: the gem owns transport + auth, the
    # caller owns the path and the body (see docs/generic-api.md, and the host's
    # API spec/manifest for what endpoints exist).
    #
    #   RootCause::Embassy.api.patch("/api/v1/tenants/#{slug}/profile",
    #     body: {settings: {...}, source: "embassy"})
    #
    # Distinct from Client: that is the signed reverse channel (HMAC, no bearer);
    # this is bearer auth against the public API. Auth — including the `rcor_`
    # refresh-token exchange and its cache — is entirely the gem's (see ApiAuth).
    #
    # **Never raises on a failed call.** Every outcome (transport failure, auth
    # failure, 4xx, 5xx, 2xx) comes back as a frozen Response the caller inspects:
    # a background job decides retry from `retryable?`, and surfaces
    # `field_errors` to ops. Only a misconfiguration or a bad argument raises
    # (ArgumentError) — that is a deploy/caller bug, not a runtime condition.
    class Api
      # The outcome of one API call.
      #
      # `body` is the parsed JSON when the response was JSON (Hash/Array), else
      # the raw String (nil when empty). `field_errors` carries the host's
      # per-field validation rejections from a 4xx `validation_failed` body.
      # `retryable` is true for transport failures, auth failures and 5xx — a 4xx
      # is a permanent caller/validation error and must not be retried.
      Response = Struct.new(:ok, :status, :body, :field_errors, :error, :retryable, keyword_init: true) do
        def ok? = !!ok

        def retryable? = !!retryable
      end

      # A caller bound to ONE project's credential. rootcause refresh tokens are
      # project-pinned, so an app that talks to several projects (e.g. a tenant
      # profile on one, brain edits on two others) holds several credentials and
      # builds one Api each — see Embassy.api_for. Tokens never mix: ApiAuth keys
      # its cache by (base_url, api_key), so each credential exchanges and
      # refreshes on its own.
      #
      # Timeouts and the logger are inherited from `template` (the configured
      # Config) when there is one, so a per-project caller behaves like the
      # singleton in every respect but its credential.
      #
      # @raise [ArgumentError] blank key, blank/relative base url
      def self.for(api_base_url:, api_key:, template: nil)
        config = template ? template.dup : Config.new
        config.api_base_url = api_base_url
        config.api_key = api_key
        # validate_api! passes a pair that is blank on BOTH sides (the opt-out an
        # Embassy without an API plane relies on) — here, both are required.
        raise ArgumentError, "RootCause::Embassy: api_base_url is required" if blank_value?(api_base_url)
        raise ArgumentError, "RootCause::Embassy: api_key is required" if blank_value?(api_key)

        config.validate_api!
        new(config)
      end

      def self.blank_value?(value) = value.nil? || value.to_s.empty?
      private_class_method :blank_value?

      # Verbs the API plane speaks. `body` is JSON-encoded; `params` becomes the
      # query string.
      def initialize(config)
        @config = config
      end

      def get(path, params: nil) = request(:get, path, params: params)

      def post(path, body: nil, params: nil) = request(:post, path, body: body, params: params)

      def patch(path, body: nil, params: nil) = request(:patch, path, body: body, params: params)

      def put(path, body: nil, params: nil) = request(:put, path, body: body, params: params)

      def delete(path, body: nil, params: nil) = request(:delete, path, body: body, params: params)

      # @param method [Symbol] :get/:post/:patch/:put/:delete
      # @param path [String] path on `api_base_url` ("/api/v1/…"), or an absolute
      #   URL on that same origin
      # @return [Response] never raises for an HTTP/transport/auth outcome
      def request(method, path, body: nil, params: nil)
        uri = build_uri(path, params)
        bearer = ApiAuth.bearer(base_url: base_url, api_key: api_key, config: @config)
        response = perform(method, uri, bearer, body)

        # A token we believed live can still be refused (host restart, revoked
        # token, clock drift). Burn it and re-exchange exactly once, then accept
        # the second answer as final.
        if response.is_a?(Net::HTTPUnauthorized) && exchangeable_key?
          ApiAuth.invalidate(base_url: base_url, api_key: api_key)
          bearer = ApiAuth.bearer(base_url: base_url, api_key: api_key, config: @config)
          response = perform(method, uri, bearer, body)
        end

        to_result(response, method, uri)
      rescue ApiAuthError => e
        # Auth failure is retryable: the credential is usually fine and the
        # exchange endpoint was merely unreachable/unhappy.
        failure(error: "auth: #{e.message}", retryable: true)
      rescue ArgumentError
        # Misconfiguration / bad argument is a deploy or caller bug, not a call
        # outcome — it must reach the developer, not hide in a Response.
        raise
      rescue => e
        failure(error: "#{e.class}: #{e.message}", retryable: true)
      end

      private

      def base_url
        url = @config.api_base_url
        raise ArgumentError, "RootCause::Embassy: api_base_url is not configured" if blank?(url)

        url.to_s
      end

      def api_key
        key = @config.api_key
        raise ArgumentError, "RootCause::Embassy: api_key is not configured" if blank?(key)

        key.to_s
      end

      def exchangeable_key? = api_key.start_with?(ApiAuth::REFRESH_PREFIX)

      # Path is joined onto the configured origin; an absolute URL is accepted as
      # long as it points at that same origin (a typo must not leak the bearer to
      # another host).
      def build_uri(path, params)
        raise ArgumentError, "RootCause::Embassy: api path is required" if blank?(path)

        base = URI(base_url.to_s.chomp("/"))
        uri = URI(path.to_s)
        if uri.absolute?
          unless uri.scheme == base.scheme && uri.host == base.host && uri.port == base.port
            raise ArgumentError,
              "RootCause::Embassy: api path #{path.inspect} is not on api_base_url (#{base_url})"
          end
        else
          relative = path.to_s.start_with?("/") ? path.to_s : "/#{path}"
          uri = URI("#{base}#{relative}")
        end

        if params && !params.empty?
          existing = uri.query.to_s
          added = URI.encode_www_form(params)
          uri.query = existing.empty? ? added : "#{existing}&#{added}"
        end
        uri
      end

      REQUESTS = {
        get: Net::HTTP::Get, post: Net::HTTP::Post, patch: Net::HTTP::Patch,
        put: Net::HTTP::Put, delete: Net::HTTP::Delete
      }.freeze

      def perform(method, uri, bearer, body)
        klass = REQUESTS[method.to_s.downcase.to_sym] ||
          raise(ArgumentError, "RootCause::Embassy: unsupported api method #{method.inspect}")
        request = klass.new(uri)
        request["authorization"] = "Bearer #{bearer}"
        request["accept"] = "application/json"
        unless body.nil?
          request["content-type"] = "application/json"
          request.body = body.is_a?(String) ? body : JSON.generate(body)
        end

        Http.perform(uri, request, open_timeout: @config.http_open_timeout, read_timeout: @config.http_read_timeout)
      end

      def to_result(response, method, uri)
        status = response.code.to_i
        parsed = parse_body(response.body)
        log(method, uri, status)

        if response.is_a?(Net::HTTPSuccess)
          return Response.new(ok: true, status: status, body: parsed, retryable: false).freeze
        end

        hash = parsed.is_a?(Hash) ? parsed : {}
        Response.new(
          ok: false,
          status: status,
          body: parsed,
          field_errors: hash["field_errors"],
          error: hash["error"] || hash["message"] || "http_#{status}",
          retryable: retryable_status?(status)
        ).freeze
      end

      # 5xx is the host having a bad time. Two 4xx are transient despite the
      # class: 429 (rate limit — a sweep pushing every tenant at once WILL hit
      # it) and 408 (the host timed the request out). Every other 4xx is a
      # permanent caller/validation error: retrying it just burns quota and
      # buries the real signal.
      def retryable_status?(status) = status >= 500 || status == 429 || status == 408

      # JSON when it parses, raw String otherwise (some endpoints answer plain
      # text; an empty body is nil).
      def parse_body(raw)
        text = raw.to_s
        return nil if text.empty?

        begin
          JSON.parse(text)
        rescue JSON::ParserError
          text
        end
      end

      def failure(error:, retryable:)
        Response.new(ok: false, status: nil, body: nil, error: error, retryable: retryable).freeze
      end

      # Customer-side audit: verb, PATH (never the query — it can carry
      # identifiers) and status. Never the bearer, never the body.
      def log(method, uri, status)
        return unless @config.logger

        @config.logger.info("[rootcause-api] #{method.to_s.upcase} #{uri.path} → #{status}")
      end

      def blank?(value) = value.nil? || value.to_s.empty?
    end
  end
end
