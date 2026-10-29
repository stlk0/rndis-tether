# Homebrew formula, published in the tap repository stlk0/homebrew-tap as
# Formula/rndis-tether.rb. At every release: update url and sha256 (see CONTRIBUTING.md).
class RndisTether < Formula
  desc "Use an Android phone's USB tethering as a normal network connection"
  homepage "https://github.com/stlk0/rndis-tether"
  url "https://github.com/stlk0/rndis-tether/archive/refs/tags/v1.1.0.tar.gz"
  sha256 "8f995585836a9f7eada8918f1001d63c746a30fc3a1e5efb9e7916970f148603"
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
