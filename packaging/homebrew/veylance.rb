class Veylance < Formula
  desc "Interactive CLI website security self-audit tool"
  homepage "https://github.com/ChAbdulWahhab/veylance"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ChAbdulWahhab/veylance/releases/download/v#{version}/veyl-darwin-arm64.tar.gz"
      sha256 "PUT_DARWIN_ARM64_SHA256_HERE"
    else
      url "https://github.com/ChAbdulWahhab/veylance/releases/download/v#{version}/veyl-darwin-amd64.tar.gz"
      sha256 "PUT_DARWIN_AMD64_SHA256_HERE"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/ChAbdulWahhab/veylance/releases/download/v#{version}/veyl-linux-arm64.tar.gz"
      sha256 "PUT_LINUX_ARM64_SHA256_HERE"
    else
      url "https://github.com/ChAbdulWahhab/veylance/releases/download/v#{version}/veyl-linux-amd64.tar.gz"
      sha256 "PUT_LINUX_AMD64_SHA256_HERE"
    end
  end

  def install
    bin.install "veyl"
    # Create alias for veylance -> veyl
    bin.install_symlink "veyl" => "veylance"
  end

  test do
    output = shell_output("#{bin}/veyl --version")
    assert_match "Veylance", output
  end
end
