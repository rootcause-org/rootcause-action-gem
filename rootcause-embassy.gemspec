# frozen_string_literal: true

require_relative "lib/rootcause/embassy/version"

Gem::Specification.new do |spec|
  spec.name = "rootcause-embassy"
  spec.version = RootCause::Embassy::VERSION
  spec.authors = ["PJ Muller"]
  spec.email = ["info@probackup.io"]

  spec.summary = "rootcause Embassy — rootcause's trusted in-app presence in the customer's Ruby runtime."
  spec.description = <<~DESC
    The Embassy is rootcause's trusted, in-app presence inside the customer's own
    Rails/Rack runtime — the far end of the reverse channel. It executes actions
    (receives a signed, digest-pinned invocation from the rootcause host, resolves
    the action's script by digest, runs it inline with a hard timeout, returns a
    signed structured result) and receives async-analysis results, all using the
    customer's own env, code, and tooling. No executable code ever travels on the
    wire. This Ruby gem is the first manifestation; PHP/Node/.NET Embassies ship as
    their own per-language repos.
  DESC
  spec.homepage = "https://github.com/rootcause-org/rootcause-embassy-ruby"
  spec.license = "MIT"

  spec.required_ruby_version = ">= 3.2"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  # lib/rubocop holds this repo's house cops — dev tooling, not gem surface.
  spec.files = Dir["lib/**/*.rb"].grep_v(%r{\Alib/rubocop/}) + Dir["examples/**/*", "SPEC.md", "README.md"]
  spec.require_paths = ["lib"]

  # Runtime: stdlib only (Net::HTTP, OpenSSL, Digest, Timeout, JSON). No new deps
  # without a recorded reason — see .claude/CLAUDE.md.

  spec.add_development_dependency "rack", "~> 3.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.13"
  spec.add_development_dependency "standard", "~> 1.40"
  # Dev only: stub the rootcause origin (script fetch) so the suite needs no live
  # host. Not a runtime dependency — the gem fetches with stdlib Net::HTTP.
  spec.add_development_dependency "webmock", "~> 3.23"
end
