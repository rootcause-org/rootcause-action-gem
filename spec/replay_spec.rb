# frozen_string_literal: true

ReplayError = RootCause::Embassy::ReplayError

RSpec.describe RootCause::Embassy::Replay do
  let(:store) { described_class::MemoryStore.new }
  let(:now) { Time.utc(2026, 6, 3, 10, 0, 0) }

  def guard(issued_at:, nonce: "n-#{rand(1_000_000)}", skew: 300)
    described_class.guard!(issued_at: issued_at, nonce: nonce, clock_skew: skew, store: store, now: now)
  end

  it "accepts issued_at anywhere inside the window, including both edges" do
    expect { guard(issued_at: now.iso8601) }.not_to raise_error
    expect { guard(issued_at: (now - 300).iso8601) }.not_to raise_error
    expect { guard(issued_at: (now + 300).iso8601) }.not_to raise_error
  end

  it "rejects issued_at outside the window in either direction" do
    expect { guard(issued_at: (now - 301).iso8601) }.to raise_error(ReplayError, /window/)
    expect { guard(issued_at: (now + 600).iso8601) }.to raise_error(ReplayError, /window/)
  end

  it "rejects a malformed issued_at" do
    expect { guard(issued_at: "not-a-time") }.to raise_error(ReplayError, /ISO8601/)
  end

  it "rejects a repeated nonce but accepts a fresh one" do
    guard(issued_at: now.iso8601, nonce: "dup")
    expect { guard(issued_at: now.iso8601, nonce: "dup") }.to raise_error(ReplayError, /already seen/)
    expect { guard(issued_at: now.iso8601, nonce: "other") }.not_to raise_error
  end

  it "rejects a missing nonce" do
    expect { guard(issued_at: now.iso8601, nonce: "") }.to raise_error(ReplayError, /nonce missing/)
  end

  describe described_class::MemoryStore do
    it "forgets a nonce after its ttl elapses" do
      subject.add?("a", ttl: 0)
      # ttl 0 → deadline already reached on the next call's prune
      expect(subject.add?("a", ttl: 60)).to be(true)
    end
  end
end
