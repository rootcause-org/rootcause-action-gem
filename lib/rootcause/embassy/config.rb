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

      # A shared Embassy may instead hold one reverse-channel secret per project.
      # Configure exactly one of `secret` or this UUID => secret map.
      attr_accessor :secrets

      # The single mounted route, e.g. "/rootcause/action".
      attr_accessor :mount_at

      # Script-by-digest endpoint on the rootcause host, hit on a cache miss.
      attr_accessor :fetch_url

      # Hard per-EXECUTION wall-clock timeout in seconds (Timeout backstop around the
      # action body only). Must stay under total_deadline to be the one that fires.
      attr_accessor :timeout

      # Hard wall-clock budget in seconds for the WHOLE invocation — signature,
      # replay, schema, script fetch AND execution. The host waits 25s for the
      # invocation and never retries, so an Embassy that spends its budget on a slow
      # script fetch would leave the host with a bare transport timeout instead of a
      # signed answer. Default 22s: under the host's wait, above the 20s execute
      # backstop, so a slow BODY still reports as an execute timeout and only
      # fetch+execute overrun trips this.
      attr_accessor :total_deadline

      # Tenant-enabled Embassy deployments set this true so even a validly signed invocation without
      # host tenant context is refused before script resolution. Flat deployments leave it false.
      attr_accessor :require_tenant_context

      # Signed action ids allowed to omit tenant context even when strict tenant context is enabled.
      # Keep this narrow: the reviewed action must derive and enforce its own tenant boundary.
      attr_accessor :tenantless_actions

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

      # AGGREGATE inline cap in DECODED bytes across one trigger's attachments.
      # The host enforces 6 MiB total regardless of the per-attachment cap, so
      # many small files still add up to a rejected request; raise before sending.
      attr_accessor :max_total_attachment_bytes

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

      # The rootcause project name the token is issued for, e.g. "acme-support"
      # (ENV ROOTCAUSE_CHAT_PROJECT). Public — it ships in the widget tag.
      attr_accessor :chat_project

      # Origin serving the hosted chat widget, e.g. "https://app.replypen.com"
      # (ENV ROOTCAUSE_CHAT_BASE_URL). Needed only by the widget tag, not by minting.
      attr_accessor :chat_base_url

      # The placeholder fetch_url shipped as the default when ROOTCAUSE_FETCH_URL
      # is unset. Reaching resolve with this URL fails opaquely; the boot guard
      # catches it eagerly when the reverse channel is active.
      PLACEHOLDER_FETCH_URL = "https://rootcause.invalid/actions/script"
      DEFAULT_CHAT_BASE_URL = "https://app.replypen.com"

      def initialize
        @mount_at = "/rootcause/action"
        @timeout = 20
        @total_deadline = 22
        @require_tenant_context = false
        @tenantless_actions = [].freeze
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
        @max_total_attachment_bytes = 6 * 1024 * 1024
        @chat_base_url = DEFAULT_CHAT_BASE_URL
      end

      # Each plane is optional, but a partially configured plane fails at boot.
      # Chat-only deployments therefore need no action secret or fetch endpoint.
      def validate!
        validate_action! if action_plane_requested?
        validate_api!
        validate_chat!
        self
      end

      def action_plane_enabled? = reverse_channel_configured?

      def action_plane_requested?
        reverse_channel_configured? || !blank?(fetch_url) || !blank?(trigger_url) ||
          !blank?(sent_message_url) || !result_handler.nil? || require_tenant_context ||
          (tenantless_actions.respond_to?(:empty?) && !tenantless_actions.empty?)
      end

      # True once the API plane is wired far enough to make a call.
      def api_configured? = !blank?(api_base_url) && !blank?(api_key)

      def map_mode? = !secrets.nil?

      # Selects a configured candidate only; callers must still verify the raw
      # request bytes before trusting the project id that chose it.
      def secret_for(project_id)
        return secret unless map_mode?
        return nil unless project_id.is_a?(String) && project_uuid?(project_id)

        secrets[project_id] || secrets[project_id.downcase]
      end

      def outbound_secret_for(project_id)
        unless action_plane_enabled?
          raise Error.public(
            "ACTION_PLANE_DISABLED",
            "Configure ROOTCAUSE_ACTION_SECRET and ROOTCAUSE_FETCH_URL before using actions or analysis."
          )
        end

        selected = secret_for(project_id)
        return selected unless blank?(selected)

        raise Error.public("ACTION_PROJECT_UNKNOWN", "Set project_id to a UUID present in the configured secrets map.")
      end

      private

      def validate_action!
        validate_reverse_secrets!
        if blank?(fetch_url)
          raise Error.public("ACTION_FETCH_URL_REQUIRED", "Set ROOTCAUSE_FETCH_URL before enabling actions or analysis.")
        end
        # When the reverse channel is active (secret present), the placeholder
        # fetch_url is a deployment mistake (ROOTCAUSE_FETCH_URL unset) that would
        # otherwise fail opaquely at the first resolve. Name the fix at boot. An
        # inert app (no secret) never fetches a script, so the placeholder is fine.
        if reverse_channel_configured? && placeholder_fetch_url?
          raise Error.public(
            "ACTION_FETCH_URL_REQUIRED",
            "Set ROOTCAUSE_FETCH_URL to the host's absolute script endpoint before enabling actions.",
            "fetch_url is the placeholder #{fetch_url}"
          )
        end
        unless timeout.to_f > 0
          raise Error.public("ACTION_TIMEOUT_INVALID", "Set timeout to a positive duration shorter than total_deadline.")
        end
        unless total_deadline.to_f > timeout.to_f
          raise Error.public(
            "ACTION_DEADLINE_INVALID",
            "Set total_deadline greater than timeout so the Embassy can refuse before the host cutoff.",
            "total_deadline #{total_deadline} must exceed timeout #{timeout}"
          )
        end
        unless clock_skew.to_f > 0
          raise Error.public("ACTION_CLOCK_SKEW_INVALID", "Set clock_skew to a positive duration.")
        end
        unless [true, false].include?(require_tenant_context)
          raise Error.public(
            "ACTION_TENANT_CONTEXT_INVALID",
            "Set require_tenant_context to true or false.",
            "require_tenant_context must be true or false"
          )
        end
        unless tenantless_actions.is_a?(Array) &&
            tenantless_actions.all? { |action_id| action_id.is_a?(String) && !action_id.empty? } &&
            tenantless_actions.uniq.length == tenantless_actions.length
          raise Error.public(
            "ACTION_TENANTLESS_ACTIONS_INVALID",
            "Set tenantless_actions to unique non-empty action ids, or leave it empty.",
            "tenantless_actions must be an array of unique, non-empty action ids"
          )
        end
      end

      public

      # The API plane is opt-in: an Embassy that sets neither attribute validates exactly as before.
      # Once ONE of them is set the deployment intends API calls, so a half-wired one is a boot-time
      # mistake rather than a first-call surprise in a background job. Public because Api.for
      # validates a per-project credential pair through the very same rules.
      def validate_api!
        return if blank?(api_base_url) && blank?(api_key)

        if blank?(api_base_url)
          raise Error.public(
            "API_BASE_URL_REQUIRED",
            "Set ROOTCAUSE_API_BASE_URL when ROOTCAUSE_API_KEY is configured.",
            "api_base_url is required when api_key is set"
          )
        end
        if blank?(api_key)
          raise Error.public(
            "API_KEY_REQUIRED",
            "Set ROOTCAUSE_API_KEY when ROOTCAUSE_API_BASE_URL is configured.",
            "api_key is required when api_base_url is set"
          )
        end
        return if %r{\Ahttps?://\S+\z}.match?(api_base_url.to_s)

        raise Error.public(
          "API_BASE_URL_INVALID",
          "Set ROOTCAUSE_API_BASE_URL to an absolute http or https URL.",
          "api_base_url must be an absolute http(s) URL"
        )
      end

      # True once chat is wired far enough to mint a token.
      def chat_configured? = !blank?(chat_secret) && !blank?(chat_project)

      private

      # Chat is opt-in: an Embassy that sets none of the chat attributes validates exactly as before.
      # Once ANY of them is set the deployment intends chat, so a half-wired one is a boot-time
      # mistake, not a runtime surprise.
      def validate_chat!
        return if blank?(chat_secret) && blank?(chat_project)

        if blank?(chat_secret)
          raise Error.public("CHAT_SECRET_REQUIRED", "Set ROOTCAUSE_CHAT_SECRET to the project's chat signing secret.")
        end
        if blank?(chat_project)
          raise Error.public("CHAT_PROJECT_REQUIRED", "Set ROOTCAUSE_CHAT_PROJECT to the public ReplyPen project slug.")
        end
        # The two secrets are different privilege boundaries; the same value in both means one of the
        # two ENV vars is pointed at the wrong secret.
        if reverse_secrets.include?(chat_secret.to_s)
          raise Error.public(
            "CHAT_SECRET_REUSED",
            "Use different values for ROOTCAUSE_CHAT_SECRET and ROOTCAUSE_ACTION_SECRET."
          )
        end
        Chat.normalize_base_url(chat_base_url)
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

      def blank?(value) = value.nil? || value.to_s.strip.empty?

      def validate_reverse_secrets!
        if map_mode?
          unless blank?(secret)
            raise Error.public("ACTION_SECRETS_INVALID", "Configure exactly one of secret or secrets, never both.")
          end
          unless secrets.is_a?(Hash) && !secrets.empty? &&
              secrets.all? { |project_id, value| project_uuid?(project_id) && value.is_a?(String) && !blank?(value) }
            raise Error.public(
              "ACTION_SECRETS_INVALID",
              "Set secrets to a non-empty map of project UUIDs to non-blank action reverse secrets."
            )
          end
          normalized = secrets.each_with_object({}) do |(project_id, value), map|
            canonical = project_id.downcase
            if map.key?(canonical)
              raise Error.public("ACTION_SECRETS_INVALID", "Use unique project UUID keys in secrets.")
            end

            map[canonical] = value
          end
          self.secrets = normalized
        elsif blank?(secret)
          raise Error.public(
            "ACTION_SECRET_REQUIRED",
            "Set ROOTCAUSE_ACTION_SECRET, or a secrets map, before enabling actions or analysis."
          )
        end
      end

      def reverse_channel_configured? = !blank?(secret) || (secrets.is_a?(Hash) && !secrets.empty?)
      def reverse_secrets = map_mode? ? secrets.values : [secret]
      def project_uuid?(value) = value.is_a?(String) && /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i.match?(value)
    end
  end
end
