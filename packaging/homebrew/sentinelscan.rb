class Sentinelscan < Formula
  desc "Interactive CLI website security self-audit tool"
  homepage "https://github.com/ChAbdulWahhab/sentinelscan"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ChAbdulWahhab/sentinelscan/releases/download/v#{version}/sscan-darwin-arm64.tar.gz"
      sha256 "PUT_DARWIN_ARM64_SHA256_HERE"
    else
      url "https://github.com/ChAbdulWahhab/sentinelscan/releases/download/v#{version}/sscan-darwin-amd64.tar.gz"
      sha256 "PUT_DARWIN_AMD64_SHA256_HERE"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/ChAbdulWahhab/sentinelscan/releases/download/v#{version}/sscan-linux-arm64.tar.gz"
      sha256 "PUT_LINUX_ARM64_SHA256_HERE"
    else
      url "https://github.com/ChAbdulWahhab/sentinelscan/releases/download/v#{version}/sscan-linux-amd64.tar.gz"
      sha256 "PUT_LINUX_AMD64_SHA256_HERE"
    end
  end

  def install
    bin.install "sscan"
    # Create alias for sentinelscan -> sscan
    bin.install_symlink "sscan" => "sentinelscan"
  end

  test do
    output = shell_output("#{bin}/sscan --version")
    assert_match "SentinelScan", output
  end
end
