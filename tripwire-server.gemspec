require_relative "lib/tripwire/server/version"

Gem::Specification.new do |spec|
  spec.name = "tripwire-server"
  spec.version = Tripwire::Server::VERSION
  spec.authors = ["ABXY Labs"]
  spec.email = ["support@tripwire.com"]

  spec.summary = "Official Tripwire Ruby server SDK"
  spec.description = "Customer-facing Ruby SDK for Tripwire Sessions, Fingerprints, Teams, and sealed token verification."
  spec.homepage = "https://github.com/abxy-labs/tripwire-server-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.6.0"

  spec.files = Dir[
    "lib/**/*.rb",
    "LICENSE",
    "README.md",
    "spec/**/*"
  ]
  spec.require_paths = ["lib"]
end
