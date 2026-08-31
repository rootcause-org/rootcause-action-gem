# frozen_string_literal: true

require "json"
require "uri"

module RootCause
  module Embassy
    # Selects a map-mode candidate from untrusted transport data. This never
    # authenticates a project id; the caller verifies the exact raw bytes next.
    module SecretSelector
      module_function

      def for_body(config, raw_body)
        return config.secret unless config.map_mode?

        payload = JSON.parse(raw_body.to_s)
        return nil unless payload.is_a?(Hash)

        config.secret_for(payload["project_id"])
      rescue JSON::ParserError
        nil
      end

      def for_query(config, raw_query)
        return config.secret unless config.map_mode?

        pairs = URI.decode_www_form(raw_query.to_s)
        return nil unless pairs.length == 1 && pairs.first.first == "project_id"

        config.secret_for(pairs.first.last)
      rescue ArgumentError
        nil
      end
    end
  end
end
