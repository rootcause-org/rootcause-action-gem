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
        self
      end

      private

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
