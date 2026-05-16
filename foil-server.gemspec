require_relative "lib/foil/server/version"

Gem::Specification.new do |spec|
  spec.name = "foil-server"
  spec.version = Foil::Server::VERSION
  spec.authors = ["ABXY Labs"]
  spec.email = ["support@usefoil.com"]

  spec.summary = "Official Foil Ruby server SDK"
  spec.description = "Customer-facing Ruby SDK for Foil Sessions, Fingerprints, Organizations, and sealed token verification."
  spec.homepage = "https://github.com/abxy-labs/foil-server-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3.0"

  spec.files = Dir[
    "lib/**/*.rb",
    "LICENSE",
    "README.md",
    "spec/**/*"
  ]
  spec.require_paths = ["lib"]
end
