Name:           trackercontrol
Version:        1.0.0
Release:        1%{?dist}
Summary:        Sovereign Desktop Privacy Guard, Multi-Tunnel WireGuard & Orbot Tor Firewall
License:        MIT
URL:            https://github.com/TrackerControl/trackercontrol-pc
Source0:        trackercontrol-v%{version}-linux-x86_64.tar.gz

Requires:       wireguard-tools, iptables
Suggests:       tor

%description
TrackerControl PC is a specialized, high-performance desktop privacy suite
providing process-level network attribution, DNS sinkholing, multi-tunnel
WireGuard concurrency, Proton VPN server integration, Tor/Orbot routing,
and OS telemetry suppression.

%prep
%setup -q -n trackercontrol-%{version}

%install
rm -rf $RPM_BUILD_ROOT
install -d -m 755 $RPM_BUILD_ROOT%{_bindir}
install -d -m 755 $RPM_BUILD_ROOT%{_datadir}/applications
install -d -m 755 $RPM_BUILD_ROOT%{_datadir}/icons/hicolor/scalable/apps
install -d -m 755 $RPM_BUILD_ROOT%{_unitdir}

install -m 755 trackercontrol $RPM_BUILD_ROOT%{_bindir}/trackercontrol
install -m 644 trackercontrol.desktop $RPM_BUILD_ROOT%{_datadir}/applications/trackercontrol.desktop
install -m 644 trackercontrol.svg $RPM_BUILD_ROOT%{_datadir}/icons/hicolor/scalable/apps/trackercontrol.svg
install -m 644 trackercontrol.service $RPM_BUILD_ROOT%{_unitdir}/trackercontrol.service

%post
%systemd_post trackercontrol.service

%preun
%systemd_preun trackercontrol.service

%postun
%systemd_postun_with_restart trackercontrol.service

%files
%{_bindir}/trackercontrol
%{_datadir}/applications/trackercontrol.desktop
%{_datadir}/icons/hicolor/scalable/apps/trackercontrol.svg
%{_unitdir}/trackercontrol.service

%changelog
* Sun Oct 11 2026 TrackerControl Contributors - 1.0.0-1
- Initial PC & Linux Sovereign Edition Release
