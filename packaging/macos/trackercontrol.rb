cask "trackercontrol" do
  version "1.0.0"
  sha256 :no_check

  url "https://github.com/mayankreseracher/PrivacyEnhancer/raw/main/dist/macos/TrackerControl-v#{version}-macOS-universal.tar.gz"
  name "TrackerControl PC"
  desc "Sovereign Desktop Privacy & Telemetry Guard with BSD Packet Filter"
  homepage "https://github.com/mayankreseracher/PrivacyEnhancer"

  app "TrackerControl.app"

  zap trash: [
    "~/Library/Application Support/TrackerControl",
    "~/Library/Preferences/org.trackercontrol.pc.plist",
    "~/Library/Saved Application State/org.trackercontrol.pc.savedState",
  ]
end
