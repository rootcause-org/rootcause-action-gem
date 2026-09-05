# frozen_string_literal: true

require_relative "line_cop"

module RuboCop
  module Cop
    module Embassy
      # CONTRACT.md pins the whole action/result refusal vocabulary: "an
      # implementation invents no others". A new snake_case class here is a wire
      # change, and a wire change starts in the contract hub, not in this repo.
      class WireClassVocabulary < LineCop
        PATTERN = /wire_class:\s*"([a-z_]+)"/

        def offense_for(line)
          match = PATTERN.match(line)
          return nil unless match
          return nil if cop_config.fetch("AllowedClasses", []).include?(match[1])

          "#{match[1].inspect} is not in the contract's refusal vocabulary — change the contract first."
        end
      end
    end
  end
end
