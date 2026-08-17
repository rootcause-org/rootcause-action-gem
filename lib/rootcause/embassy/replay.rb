# frozen_string_literal: true

require "time"

module RootCause
  module Embassy
    # Replay guard: an invocation is accepted at most once, and only inside a
    # bounded freshness window. Two independent checks, both fail-closed:
    #
    #   1. Window — |now - issued_at| <= clock_skew (±5 min default).
    #   2. Nonce  — the nonce has not been seen before.
    #
    # The window bounds how long a captured invocation stays replayable, which in
    # turn bounds how long a nonce must be remembered: a nonce older than the full
    # window (2 * clock_skew) is already rejected by the window check, so the
    # store only needs to retain nonces that briefly.
    #
    # Both checks are enforced by `guard!` (the invocation route). The result route
    # calls `fresh?` instead: same window enforcement, but a seen nonce comes back
    # as `false` so the caller can ack a redelivery instead of erroring.
    module Replay
      module_function

      # @param store [#add?] nonce store; `add?(nonce, ttl:)` returns true iff the
      #   nonce was newly recorded (i.e. unseen).
      def guard!(issued_at:, nonce:, clock_skew:, store:, now: Time.now.utc)
        raise ReplayError, "nonce already seen" unless fresh?(
          issued_at: issued_at, nonce: nonce, clock_skew: clock_skew, store: store, now: now
        )
      end

      # Window check as usual (stale → ReplayError), but a duplicate nonce is
      # REPORTED, not raised: false means "authentic and in-window, already seen".
      # The result route needs that distinction — the host deliberately sends a
      # stable `nonce = run_id` across redeliveries of the SAME result, so a
      # duplicate there is a redelivery to ack idempotently, not an attack. The
      # invocation route wants the raise, and gets it via guard!.
      def fresh?(issued_at:, nonce:, clock_skew:, store:, now: Time.now.utc)
        check_window!(issued_at, clock_skew, now)
        record_nonce(nonce, store, clock_skew)
      end

      def check_window!(issued_at, clock_skew, now)
        issued = parse_time(issued_at)
        skew = (now - issued).abs
        if skew > clock_skew
          raise ReplayError, "issued_at outside ±#{clock_skew}s window (skew=#{skew.round}s)"
        end
      end

      # @return [Boolean] true iff the nonce was unseen (and is now recorded).
      def record_nonce(nonce, store, clock_skew)
        raise ReplayError, "nonce missing" if nonce.nil? || nonce.to_s.empty?

        # Retain for the full window; after that the window check alone refuses.
        store.add?(nonce.to_s, ttl: (clock_skew * 2) + 1)
      end

      def parse_time(value)
        Time.iso8601(value.to_s).utc
      rescue ArgumentError, TypeError
        raise ReplayError, "issued_at is not a valid ISO8601 timestamp"
      end

      # Default nonce store: a thread-safe, TTL-pruned set held in process memory.
      # Correct for a single process; multi-worker deployments must inject a shared
      # store (e.g. a Rails.cache-backed adapter using `write(unless_exist: true)`)
      # so a replay can't slip through on a second worker. See README.
      class MemoryStore
        def initialize
          @expiries = {} # nonce => monotonic deadline
          @mutex = Mutex.new
        end

        # Record `nonce` if unseen; return true iff newly recorded.
        def add?(nonce, ttl:)
          now = clock
          @mutex.synchronize do
            prune(now)
            return false if @expiries.key?(nonce)

            @expiries[nonce] = now + ttl
            true
          end
        end

        # Forget `nonce` so it can be accepted again. Only the result route uses
        # this, to un-consume a nonce whose dispatch failed (see ResultReceiver).
        def delete(nonce)
          @mutex.synchronize { @expiries.delete(nonce) }
          nil
        end

        private

        def prune(now)
          @expiries.delete_if { |_, deadline| deadline <= now }
        end

        def clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end
  end
end
