# frozen_string_literal: true

module RootCause
  module Embassy
    # The two-line predicates every file used to redefine for itself. One home, so
    # "blank" means one thing on the wire path and the monotonic clock is read the
    # same way everywhere.
    module Util
      module_function

      # Wire/runtime semantics: nil or the empty string. Whitespace is a VALUE here
      # — a signed field of " " is present, and refusing it is the schema's job, not
      # this predicate's. Config gates want the stricter reading below.
      def blank?(value) = value.to_s.empty?

      def present?(value) = !value.to_s.empty?

      # Boot-gate semantics: a whitespace-only secret or URL is an unset ENV var
      # that picked up a stray space, never a credential.
      def unset?(value) = value.to_s.strip.empty?

      # Monotonic — immune to wall-clock jumps, so a duration or a TTL can never go
      # negative because NTP stepped the clock.
      def monotonic_now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      def monotonic_ms = Process.clock_gettime(Process::CLOCK_MONOTONIC, :float_millisecond)
    end
  end
end
