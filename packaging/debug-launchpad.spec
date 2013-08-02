Name:       debug-launchpad
Summary:    Debug Launchpad
Version:    0.0.9
Release:    1
Group:      System Environment/Daemons
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz
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
BuildRequires:  libcap-devel


%description
Debug launchpad

%prep
%setup -q

%build
%ifarch %{ix86}
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DARCH=x86
%else
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DARCH=arm
%endif
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

%clean
rm -rf %{buildroot}

%post

%files
%attr(0755, root, root) %{_bindir}/debug_launchpad_preloading_preinitializing_daemon
