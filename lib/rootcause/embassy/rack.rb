# frozen_string_literal: true

module RootCause
  module Embassy
    # The mounted HTTP handler for the invocation route — RackShell over Runner.
    # Mount it in Rails routes (least magic, easy to restrict at the edge):
    #
    #   mount RootCause::Embassy::RackApp.new => RootCause::Embassy.config.mount_at
    #
    # Named RackApp (not Rack) to avoid shadowing the Rack gem's top-level module.
    class RackApp
      include RackShell

      def initialize(runner: nil)
        @runner = runner
      end

      private

      # Resolve lazily so the app can be constructed at require-time (before the
      # initializer runs) yet still bind to the configured runner per request.
      def core = @runner || RootCause::Embassy.runner

      # Plane check first (Go-port parity): a chat-only deployment that mounts the
      # action routes gets a diagnostic 503 on the health child too, instead of a
      # bare 404 that reads as "wrong path".
      def route(env)
        return plane_disabled unless core.config.action_plane_enabled?

        health(env) if env["PATH_INFO"] == "/health"
      end

      def health(env)
        respond(core.health(raw_query: env["QUERY_STRING"].to_s, signature: env[SIG_HEADER_ENV]))
      end
    end
  end
end
