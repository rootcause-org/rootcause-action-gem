# frozen_string_literal: true

require "net/http"
require "uri"
require "json"

module RootCause
  module Embassy
    # Resolves the `Authorization: Bearer` value for the rootcause **API plane**
    # (Api) — a different channel from the action reverse channel, which is HMAC
    # signed and holds no bearer at all.
    #
    # rootcause's API authenticates with a short-lived (1h) OAuth **access token**
    # (`rcoa_…`). An Embassy deployment is provisioned a long-lived, non-rotating
    # **refresh token** (`rcor_…`, the machine credential in `api_key`) and
    # exchanges it at the OAuth token endpoint:
    #
    #     POST {api_base_url}/oauth/token          (form-encoded)
    #       grant_type=refresh_token
    #       refresh_token=<rcor_…>
    #       client_id=rcocl_cli
    #     → { "access_token": "rcoa_…", "expires_in": 3600, "token_type": "Bearer" }
    #
    # The refresh token does not rotate, so we keep the same `rcor_` and just
    # re-exchange as the access token nears expiry. A key that is already a bearer
    # (`rcoa_…`) — or anything that is not an `rcor_` — is used **verbatim**, so a
    # static-bearer deployment keeps working with no code change.
    #
    # Cache: in-process (the app process is long-lived), one access token per
    # (base_url, refresh token), refreshed EXPIRY_SKEW seconds early so an
    # in-flight call never carries a token that dies mid-request. Guarded by a
    # mutex — Puma/Sidekiq run this from many threads.
    module ApiAuth
      # The OAuth client the machine credential is issued for (same as the rc CLI).
      OAUTH_CLIENT_ID = "rcocl_cli"

      # Refresh this early so a request that starts just before expiry still lands
      # with a live token.
      EXPIRY_SKEW = 60

      # Fallback lifetime when the host omits `expires_in`.
      DEFAULT_EXPIRES_IN = 3600

      # Machine-credential prefix: only these are exchanged.
      REFRESH_PREFIX = "rcor_"

      @mutex = Mutex.new
      # [base_url, api_key] => [access_token, expires_at_monotonic]
      @cache = {}

      class << self
        # @return [String] a usable bearer value
        # @raise [ApiAuthError] the exchange failed (transport or non-2xx)
        def bearer(base_url:, api_key:, config: nil)
          return api_key.to_s unless api_key.to_s.start_with?(REFRESH_PREFIX)

          key = [base_url.to_s, api_key.to_s]
          cached = live_token(key)
          return cached if cached

          @mutex.synchronize do
            # Re-check inside the lock — another thread may have just refreshed.
            cached = live_token(key)
            next cached if cached

            token, expires_in = exchange(base_url, api_key, config)
            @cache[key] = [token, now + expires_in]
            token
          end
        end

        # Drop a cached token so the next call re-exchanges. Used after the API
        # answers 401 with a token we believed was live (host restart, revocation),
        # and by the test seam below.
        def invalidate(base_url:, api_key:)
          @mutex.synchronize { @cache.delete([base_url.to_s, api_key.to_s]) }
        end

        # Test/boot-order seam: drop every cached token.
        def reset!
          @mutex.synchronize { @cache.clear }
        end

        private

        def live_token(key)
          token, expires_at = @cache[key]
          return nil if token.nil?

          (expires_at - EXPIRY_SKEW > now) ? token : nil
        end

        # Monotonic: immune to wall-clock jumps (NTP, suspend).
        def now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

        def exchange(base_url, refresh_token, config)
          uri = URI.join(base_url.to_s.chomp("/") + "/", "oauth/token")
          request = Net::HTTP::Post.new(uri)
          request.set_form_data(
            "grant_type" => "refresh_token",
            "refresh_token" => refresh_token.to_s,
            "client_id" => OAUTH_CLIENT_ID
          )

          response = begin
            Http.perform(
              uri, request,
              open_timeout: config&.http_open_timeout || 5,
              read_timeout: config&.http_read_timeout || 15
            )
          rescue => e
            raise ApiAuthError, "token exchange transport error: #{e.class}: #{e.message}"
          end

          unless response.is_a?(Net::HTTPSuccess)
            raise ApiAuthError, "token exchange failed: http_#{response.code}"
          end

          payload = begin
            JSON.parse(response.body.to_s)
          rescue JSON::ParserError
            raise ApiAuthError, "token exchange response was not valid JSON"
          end
          token = payload.is_a?(Hash) ? payload["access_token"] : nil
          raise ApiAuthError, "token exchange response missing access_token" if token.nil? || token.to_s.empty?

          [token.to_s, (payload["expires_in"] || DEFAULT_EXPIRES_IN).to_f]
        end
      end
    end
  end
end
