# frozen_string_literal: true

require_relative "line_cop"

module RuboCop
  module Cop
    module Embassy
      # `blank?` / `present?` are defined once, in the shared Util helper. Every
      # other copy is a place where the definition can silently drift apart from
      # the one the wire code fails closed on.
      class SharedBlankHelper < LineCop
        MSG = "Define blank?/present? once in the shared Util helper, not per class."
        PATTERN = /\bdef\s+(?:self\.)?(?:blank|present)\?/

        def offense_for(line)
          MSG if PATTERN.match?(line)
        end
      end
    end
  end
end
