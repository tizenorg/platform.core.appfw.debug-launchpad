Name:       debug-launchpad
Summary:    Debug Launchpad
Version:    0.0.12
Release:    1
Group:      System Environment/Daemons
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    debug-launchpad.service
Source2:    debug-launchpad.socket
BuildRoot:  %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires(post): /sbin/ldconfig
Requires(post): /usr/bin/systemctl
Requires(postun): /sbin/ldconfig
Requires(postun): /usr/bin/systemctl
Requires(preun): /usr/bin/systemctl

BuildRequires:  cmake
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(x11)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(libprivilege-control)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(libsmack)
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(ail)
BuildRequires:  libcap-devel
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(libsystemd-daemon)

%if "%{?tizen_profile_name}" == "wearable"
%define appfw_feature_socket_activation 1
%else
%if "%{?tizen_profile_name}" == "mobile"
%define appfw_feature_socket_activation 1
%else
%if "%{?tizen_profile_name}" == "tv"
%define appfw_feature_socket_activation 0
%endif
%endif
%endif


%description
Debug launchpad

%prep
%setup -q

%build
%if 0%{?appfw_feature_socket_activation}
_APPFW_FEATURE_SOCKET_ACTIVATION=ON
%endif

%ifarch %{ix86}
cmake	-DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-DARCH=x86 \
	-D_APPFW_FEATURE_SOCKET_ACTIVATION:BOOL=${_APPFW_FEATURE_SOCKET_ACTIVATION} \
	.
%else
cmake	-DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-DARCH=arm \
	-D_APPFW_FEATURE_SOCKET_ACTIVATION:BOOL=${_APPFW_FEATURE_SOCKET_ACTIVATION} \
	.
%endif
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE  %{buildroot}/usr/share/license/%{name}
%make_install

%if 0%{?appfw_feature_socket_activation}
mkdir -p %{buildroot}/usr/lib/systemd/system/sockets.target.wants
install -m 0644 %{SOURCE1} %{buildroot}/usr/lib/systemd/system/debug-launchpad.service
install -m 0644 %{SOURCE2} %{buildroot}/usr/lib/systemd/system/debug-launchpad.socket
ln -s ../debug-launchpad.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/debug-launchpad.socket
%endif

%clean
rm -rf %{buildroot}

%post

%files
/usr/share/license/%{name}
%manifest debug-launchpad.manifest
%attr(0750, root, root) %{_bindir}/debug_launchpad_preloading_preinitializing_daemon
%attr(0750, developer, developer) %{_bindir}/appid2pid
%attr(0750, developer, developer) %{_bindir}/launch_debug
%if 0%{?appfw_feature_socket_activation}
/usr/lib/systemd/system/debug-launchpad.service
/usr/lib/systemd/system/debug-launchpad.socket
/usr/lib/systemd/system/sockets.target.wants/debug-launchpad.socket
%endif
