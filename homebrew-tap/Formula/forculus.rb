class Forculus < Formula
  desc "Open-source governance layer for AI agents"
  homepage "https://github.com/bpolania/forculus"
  version "0.2.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/bpolania/forculus/releases/download/v0.2.0/forculus-aarch64-apple-darwin.tar.gz"
      sha256 "bb0c8f6c526c3d0f00cebeb7e12aca7fc1c12d5a32eac5e0880e0827ae8fc2b4"
    end
    on_intel do
      url "https://github.com/bpolania/forculus/releases/download/v0.2.0/forculus-x86_64-apple-darwin.tar.gz"
      sha256 "5bdfb3801fa894485e291289c1dd41a1d3a6faf3b6f6b101f14965bbfb4c2e1f"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/bpolania/forculus/releases/download/v0.2.0/forculus-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "c568811fec7fad8da16343c109eddb9db1f293b16c9953a3f980c9ac0a60a394"
    end
    on_intel do
      url "https://github.com/bpolania/forculus/releases/download/v0.2.0/forculus-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "5125198a0ca12aa45a803ea3b502f627eef253d632115a42bd920e55b5a899ba"
    end
  end

  def install
    bin.install "forculus"
  end

  test do
    assert_match "forculus", shell_output("#{bin}/forculus --version")
  end
end
