# Homebrew formula, published in the tap repository stlk0/homebrew-tap as
# Formula/rndis-tether.rb. At every release: update url and sha256 (see CONTRIBUTING.md).
class RndisTether < Formula
  desc "Use an Android phone's USB tethering as a normal network connection"
  homepage "https://github.com/stlk0/rndis-tether"
  url "https://github.com/stlk0/rndis-tether/archive/refs/tags/v1.1.1.tar.gz"
  sha256 "a6b84cb51ec019b17a40359fbd813984113f30d35e537a3fecbe8290c42d9120"
  license "MIT"
  head "https://github.com/stlk0/rndis-tether.git", branch: "main"

  depends_on macos: :ventura

  def install
    system "make", "rndis-tether", "WERROR="
    bin.install "rndis-tether"
  end

  def caveats
    <<~EOS
      rndis-tether works as a background service. Install (or, after
      `brew upgrade`, update) the service with:
        sudo rndis-tether install
      Then connect the phone and turn on USB tethering. Check with:
        rndis-tether status
      Before `brew uninstall rndis-tether`, remove the service:
        sudo rndis-tether uninstall
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/rndis-tether version")
    assert_match "sudo rndis-tether install", shell_output("#{bin}/rndis-tether help")
  end
end
