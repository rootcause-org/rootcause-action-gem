# frozen_string_literal: true

require_relative "line_cop"

module RuboCop
  module Cop
    module Embassy
      # A spec that sleeps for whole seconds is a spec everyone eventually skips.
      # Timeouts are configurable (Config#timeout / #total_deadline take floats),
      # so an example that must outlive a deadline scopes a sub-second one instead.
      class LongSpecSleep < LineCop
        MSG = "Scope a sub-second timeout instead of sleeping for seconds in a spec."
        PATTERN = /\bsleep[\s(]+([2-9]|\d{2,})\b/

        def offense_for(line)
          MSG if PATTERN.match?(line)
        end
      end
    end
  end
end
