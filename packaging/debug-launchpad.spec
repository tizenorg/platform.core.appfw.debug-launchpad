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
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(libprivilege-control)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(libsmack)
BuildRequires:  libcap-devel
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(security-manager)

%if "%{?profile}" == "wearable"
BuildRequires:  pkgconfig(libsystemd-daemon)
%define appfw_feature_socket_activation 1
%else
%if "%{?profile}" == "mobile"
BuildRequires:  pkgconfig(libsystemd-daemon)
%define appfw_feature_socket_activation 1
%else
%if "%{?profile}" == "tv"
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

%ifarch aarch64
_ARCH=aarch64
%else
%ifarch armv7l
_ARCH=armv7l
%else
%ifarch x86_64
_ARCH=x86_64
%else
_ARCH=x86
%endif
%endif
%endif

cmake	-DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-DARCH=${_ARCH} \
	-D_APPFW_FEATURE_SOCKET_ACTIVATION:BOOL=${_APPFW_FEATURE_SOCKET_ACTIVATION} \
	.

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

%if 0%{?appfw_feature_socket_activation}
mkdir -p %{buildroot}%{_unitdir_user}/sockets.target.wants
install -m 0644 %{SOURCE1} %{buildroot}%{_unitdir_user}/debug-launchpad.service
install -m 0644 %{SOURCE2} %{buildroot}%{_unitdir_user}/debug-launchpad.socket
ln -s ../debug-launchpad.socket %{buildroot}%{_unitdir_user}/sockets.target.wants/debug-launchpad.socket
%endif

%clean
rm -rf %{buildroot}

%post

%files
%license LICENSE
%manifest debug-launchpad.manifest
%{_bindir}/debug_launchpad_preloading_preinitializing_daemon
%if 0%{?appfw_feature_socket_activation}
%{_unitdir_user}/debug-launchpad.service
%{_unitdir_user}/debug-launchpad.socket
%{_unitdir_user}/sockets.target.wants/debug-launchpad.socket
%endif
