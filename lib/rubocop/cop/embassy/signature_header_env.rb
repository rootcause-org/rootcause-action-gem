# frozen_string_literal: true

require_relative "line_cop"

module RuboCop
  module Cop
    module Embassy
      # The Rack env spelling of X-Webhook-Signature is transport detail. It belongs
      # to the one Rack shell; a second copy is how a route ends up reading a header
      # the verifier never checked.
      class SignatureHeaderEnv < LineCop
        MSG = "Read the signature header through the shared Rack shell, not a second HTTP_X_WEBHOOK_SIGNATURE literal."
        PATTERN = /HTTP_X_WEBHOOK_SIGNATURE/

        def offense_for(line)
          MSG if PATTERN.match?(line)
        end
      end
    end
  end
end
