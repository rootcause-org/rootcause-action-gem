# frozen_string_literal: true

require_relative "embassy/version"
require_relative "embassy/util"
require_relative "embassy/errors"
require_relative "embassy/config"
require_relative "embassy/signature"
require_relative "embassy/reply"
require_relative "embassy/rack_shell"
require_relative "embassy/signed_endpoint"
require_relative "embassy/secret_selector"
require_relative "embassy/http"
require_relative "embassy/schema"
require_relative "embassy/replay"
require_relative "embassy/resolver"
require_relative "embassy/executor"
require_relative "embassy/runner"
require_relative "embassy/rack"
require_relative "embassy/result"
require_relative "embassy/result_handler"
require_relative "embassy/client"
require_relative "embassy/api_auth"
require_relative "embassy/api"
require_relative "embassy/result_rack"
require_relative "embassy/chat"
require_relative "embassy/chat_view_helper"

module RootCause
  # The Embassy — rootcause's trusted in-app presence in the customer's runtime.
  # Configure once at boot; the mounted RackApp then turns each signed,
  # digest-pinned invocation into a signed result, and the result channel receives
  # async-analysis results.
  module Embassy
    class << self
      # Configure once in an initializer; validates fail-closed at boot and builds
      # the singleton Runner (with its nonce store and script/compile caches).
      #
      #   RootCause::Embassy.configure do |c|
      #     c.secret    = ENV.fetch("ROOTCAUSE_ACTION_SECRET")
      #     c.fetch_url = "https://<rootcause>/actions/script"
      #     c.timeout   = 20
      #     c.logger    = Rails.logger
      #   end
      def configure
        config = Config.new
        yield config if block_given?
        config.validate!
        @config = config
        @runner = Runner.new(config)
        @client = Client.new(config)
        @api = Api.new(config)
        @result_receiver = ResultReceiver.new(config)
        config
      end

      def config
        @config || raise("RootCause::Embassy is not configured — call .configure first")
      end

      def runner
        @runner || raise("RootCause::Embassy is not configured — call .configure first")
      end

      def client
        @client || raise("RootCause::Embassy is not configured — call .configure first")
      end

      def result_receiver
        @result_receiver || raise("RootCause::Embassy is not configured — call .configure first")
      end

      # The API plane: call ANY rootcause backend endpoint, bearer-authed by the
      # gem. `api.get/post/patch/put/delete(path, body:, params:)` return an
      # Api::Response instead of raising. See docs/generic-api.md.
      def api
        @api || raise("RootCause::Embassy is not configured — call .configure first")
      end

      # A caller for ANOTHER rootcause project: refresh tokens are project-pinned,
      # so an app spanning several projects holds one credential each. The returned
      # Api is independent of the configured singleton (which stays on
      # `config.api_key`) and caches its access token separately, keyed by
      # (api_base_url, api_key). Cheap to build per call; also works before
      # `.configure` (timeouts/logger then fall back to Config defaults).
      def api_for(api_base_url:, api_key:)
        Api.for(api_base_url: api_base_url, api_key: api_key, template: @config)
      end

      # Outbound trigger: ask rootcause to analyze something and get an analysis_id
      # back to persist alongside your resource. See Client#start_analysis.
      def start_analysis(...)
        client.start_analysis(...)
      end

      # Fire-and-forget: hand rootcause the reply a human agent actually sent (after
      # editing the proposed draft), keyed to the analysis `session_id`. See
      # Client#capture_sent_message.
      def capture_sent_message(...)
        client.capture_sent_message(...)
      end

      # Mint a short-lived HS256 embed-chat token for one user (+ tenant). See Chat#token — the
      # browser never holds the key, so it cannot mint for another user, tenant, origin, or expiry.
      def chat_token(...)
        Chat.token(...)
      end

      # Test/boot-order seam: drop the configured singletons.
      def reset!
        @config = nil
        @runner = nil
        @client = nil
        @api = nil
        @result_receiver = nil
        ApiAuth.reset!
      end
    end
  end
end
