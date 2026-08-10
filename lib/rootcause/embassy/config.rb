# frozen_string_literal: true

require "logger"
require "uri"

module RootCause
  module Embassy
    # Customer-supplied configuration, set once in an initializer. Values are read
    # on every request, so the same Config instance is shared and treated as
    # effectively immutable after boot.
    class Config
      # Reverse-channel HMAC secret (per project). Distinct from the email
      # `webhook_secret`. Held via ENV customer-side. Never logged.
      attr_accessor :secret

      # The single mounted route, e.g. "/rootcause/action".
      attr_accessor :mount_at

      # Script-by-digest endpoint on the rootcause host, hit on a cache miss.
      attr_accessor :fetch_url

      # Hard per-run wall-clock timeout in seconds (Timeout backstop).
      attr_accessor :timeout

      # Tenant-enabled Embassy deployments set this true so even a validly signed invocation without
      # host tenant context is refused before script resolution. Flat deployments leave it false.
      attr_accessor :require_tenant_context

      # Replay window half-width in seconds: an invocation is fresh iff
      # |now - issued_at| <= clock_skew. ±5 min per the spec.
      attr_accessor :clock_skew

      # Where digest-keyed script bodies are cached on disk. Immutable + self-
      # verifying (re-hashed on read); nil disables disk caching (memory only).
      attr_accessor :cache_dir

      # Capture the action's $stdout into the result. See Executor for the
      # documented multi-threaded caveat (global $stdout swap).
      attr_accessor :capture_stdout

      # Truncate captured stdout to this many bytes (inline JSON only, no files).
      attr_accessor :max_stdout_bytes

      # Truncate the rescued backtrace to this many frames.
      attr_accessor :max_backtrace_lines

      # Customer-side logger. Logs action_id/digest/param KEYS/ok/duration_ms only.
      attr_accessor :logger

      # HTTP open/read timeouts for the script fetch (seconds).
      attr_accessor :http_open_timeout, :http_read_timeout

      # --- async analysis (see docs/async-analysis-spec.md) ---

      # Where start_analysis POSTs the signed trigger, e.g.
      # "https://<rootcause>/analyses/<project>". Required only to trigger.
      attr_accessor :trigger_url

      # Where capture_sent_message POSTs the signed sent-message capture, e.g.
      # "https://<rootcause>/analyses/<project>/sent-message". Reuses `secret`
      # (no new crypto). Required only to capture; not part of validate!.
      attr_accessor :sent_message_url

      # Route that receives async results. Mounted like mount_at; firewall it to
      # rootcause's egress IP, same recommendation as the invocation route.
      attr_accessor :result_mount_at

      # Customer's result handler, as a class NAME string (lazy-loaded, reload-safe)
      # so Rails autoload/reload picks up edits. A Class or handler instance is also
      # accepted. Required only to receive results.
      attr_accessor :result_handler

      # Per-attachment inline cap in DECODED bytes; start_analysis raises before
      # sending anything larger. Large files / fetch-URLs are out of scope (v1).
      attr_accessor :max_attachment_bytes

      # --- API plane (see Api, docs/generic-api.md) ---

      # Origin of the rootcause API, e.g. "https://app.replypen.com" — paths are
      # joined onto it ("/api/v1/…"), and it is also where the OAuth token
      # exchange happens. Optional: an Embassy that never calls `.api` leaves it nil.
      attr_accessor :api_base_url

      # Machine credential for the API plane (ENV ROOTCAUSE_API_KEY). An `rcor_`
      # refresh token is exchanged for a short-lived `rcoa_` access token and
      # cached (ApiAuth); anything else is sent verbatim as the bearer. A THIRD,
      # separate privilege boundary — never the action `secret` or `chat_secret`.
      # Never logged.
      attr_accessor :api_key

      # --- embedded chat (see Chat) ---

      # The project's `webhook_secret`, used ONLY to mint embed-chat tokens (ENV
      # ROOTCAUSE_CHAT_SECRET). A deliberately separate privilege boundary from the
      # action-plane `secret`: neither ever falls back to the other, so a leaked
      # chat key cannot buy action execution. Optional — an Embassy without chat
      # leaves all three chat attributes nil.
      attr_accessor :chat_secret

      # The rootcause project name the token is issued for, e.g. "kampadmin-support"
      # (ENV ROOTCAUSE_CHAT_PROJECT). Public — it ships in the widget tag.
      attr_accessor :chat_project

      # Origin serving the hosted chat widget, e.g. "https://app.replypen.com"
      # (ENV ROOTCAUSE_CHAT_BASE_URL). Needed only by the widget tag, not by minting.
      attr_accessor :chat_base_url

      # The placeholder fetch_url shipped as the default when ROOTCAUSE_FETCH_URL
      # is unset. Reaching resolve with this URL fails opaquely; the boot guard
      # catches it eagerly when the reverse channel is active.
      PLACEHOLDER_FETCH_URL = "https://rootcause.invalid/actions/script"

      def initialize
        @mount_at = "/rootcause/action"
        @timeout = 20
        @require_tenant_context = false
        @clock_skew = 300
        @cache_dir = "tmp/rootcause/actions"
        @capture_stdout = true
        @max_stdout_bytes = 64 * 1024
        @max_backtrace_lines = 50
        @logger = Logger.new($stdout)
        @http_open_timeout = 5
        @http_read_timeout = 15
        @result_mount_at = "/rootcause/result"
        @max_attachment_bytes = 256 * 1024
      end

      # Fail closed at boot rather than on the first invocation: a missing secret
      # or fetch_url is a deployment mistake, not a runtime condition.
      def validate!
        raise ArgumentError, "RootCause::Embassy: secret is required" if blank?(secret)
        raise ArgumentError, "RootCause::Embassy: fetch_url is required" if blank?(fetch_url)
        # When the reverse channel is active (secret present), the placeholder
        # fetch_url is a deployment mistake (ROOTCAUSE_FETCH_URL unset) that would
        # otherwise fail opaquely at the first resolve. Name the fix at boot. An
        # inert app (no secret) never fetches a script, so the placeholder is fine.
        if !blank?(secret) && placeholder_fetch_url?
          raise ArgumentError,
            "RootCause::Embassy: fetch_url is the placeholder " \
            "(#{fetch_url}) — set ROOTCAUSE_FETCH_URL to the host's /actions/script endpoint"
        end
        raise ArgumentError, "RootCause::Embassy: timeout must be positive" unless timeout.to_f > 0
        unless [true, false].include?(require_tenant_context)
          raise ArgumentError, "RootCause::Embassy: require_tenant_context must be true or false"
        end
        validate_api!
        validate_chat!
        self
      end

      # True once the API plane is wired far enough to make a call.
      def api_configured? = !blank?(api_base_url) && !blank?(api_key)

      # The API plane is opt-in: an Embassy that sets neither attribute validates exactly as before.
      # Once ONE of them is set the deployment intends API calls, so a half-wired one is a boot-time
      # mistake rather than a first-call surprise in a background job. Public because Api.for
      # validates a per-project credential pair through the very same rules.
      def validate_api!
        return if blank?(api_base_url) && blank?(api_key)

        raise ArgumentError, "RootCause::Embassy: api_base_url is required when api_key is set" if blank?(api_base_url)
        raise ArgumentError, "RootCause::Embassy: api_key is required when api_base_url is set" if blank?(api_key)
        return if %r{\Ahttps?://\S+\z}.match?(api_base_url.to_s)

        raise ArgumentError, "RootCause::Embassy: api_base_url must be an absolute http(s) URL"
      end

      # True once chat is wired far enough to mint a token.
      def chat_configured? = !blank?(chat_secret) && !blank?(chat_project)

      private

      # Chat is opt-in: an Embassy that sets none of the chat attributes validates exactly as before.
      # Once ANY of them is set the deployment intends chat, so a half-wired one is a boot-time
      # mistake, not a runtime surprise.
      def validate_chat!
        return if [chat_secret, chat_project, chat_base_url].all? { |v| blank?(v) }

        raise ArgumentError, "RootCause::Embassy: chat_secret is required when chat is configured" if blank?(chat_secret)
        raise ArgumentError, "RootCause::Embassy: chat_project is required when chat is configured" if blank?(chat_project)
        # The two secrets are different privilege boundaries; the same value in both means one of the
        # two ENV vars is pointed at the wrong secret.
        if !blank?(secret) && chat_secret.to_s == secret.to_s
          raise ArgumentError,
            "RootCause::Embassy: chat_secret must differ from secret — ROOTCAUSE_CHAT_SECRET is the " \
            "project's webhook_secret, not the action reverse-channel secret"
        end
        return if blank?(chat_base_url) || %r{\Ahttps?://\S+\z}.match?(chat_base_url.to_s)

        raise ArgumentError, "RootCause::Embassy: chat_base_url must be an absolute http(s) URL"
      end

      # The placeholder, by exact match OR by a host ending in `.invalid` (the
      # reserved TLD the placeholder uses). A malformed fetch_url can't slip past
      # the boot guard: an unparseable URI counts as a placeholder so it's caught.
      def placeholder_fetch_url?
        return true if fetch_url.to_s == PLACEHOLDER_FETCH_URL

        host = URI(fetch_url.to_s).host
        host.nil? || host.downcase.end_with?(".invalid")
      rescue URI::InvalidURIError
        true
      end

      def blank?(value) = value.nil? || value.to_s.empty?
    end
  end
end
