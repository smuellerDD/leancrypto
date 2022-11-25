#
# spec file for package leancrypto
#
# Copyright (c) 2022 Stephan Mueller <smueller@chronox.de
#

Name:           leancrypto
Version:        0.5.0
Release:        1.1
Summary:        Cryptographic library with stack-only support and PQC-safe algorithms
License:        GPL-2.0 OR BSD-2-Clause
URL:            https://www.chronox.de/leancrypto.html
Source0:        https://www.chronox.de/%{name}-%{version}.tar.xz
#Source1:        https://www.chronox.de/leancrypto-%%{version}.tar.xz.asc
BuildRequires:  meson
BuildRequires:  gcc
BuildRequires:	%kernel_module_package_buildreqs

%description
Leancrypto provides a general-purpose cryptographic library with PQC-safe
algorithms. Further it only has POSIX dependencies, and allows all algorithms
to be used on stack as well as on heap. Accelerated algorithms are transparently
enabled if possible.

%package -n lib%{name}0
Summary:        Cryptographic library with stack-only support and PQC-safe algorithms
Provides:       %{name} = %{version}-%{release}
Obsoletes:      %{name} < %{version}-%{release}

%description -n lib%{name}0
Leancrypto provides a general-purpose cryptographic library with PQC-safe
algorithms. Further it only has POSIX dependencies, and allows all algorithms
to be used on stack as well as on heap. Accelerated algorithms are transparently
enabled if possible.

%package devel
Summary:        Development files for leancrypto, a PQC-safe cryptographic library with stack-only support
Requires:       glibc-devel
Requires:       %{name} = %{version}
#BuildArchitectures: noarch

%description devel
Leancrypto provides a general-purpose cryptographic library with PQC-safe
algorithms. Further it only has POSIX dependencies, and allows all algorithms
to be used on stack as well as on heap. Accelerated algorithms are transparently
enabled if possible.

This subpackage holds the development headers for the library.

%package devel-static
Summary:        Static library for leancrypto
Requires:       %{name}-devel = %{version}
Provides:       %{name}-devel:%{_libdir}/lib%{name}.a

%description devel-static
Leancrypto provides a general-purpose cryptographic library with PQC-safe
algorithms. Further it only has POSIX dependencies, and allows all algorithms
to be used on stack as well as on heap. Accelerated algorithms are transparently
enabled if possible.

This subpackage contains the static version of the library
used for development.

%kernel_module_package

%package -n lib%{name}0-kernel
Summary:	Cryptographic library with stack-only support and PQC-safe algorithms Kernel Module Package

%description -n lib%{name}0-kernel
Leancrypto provides a general-purpose cryptographic library with PQC-safe
algorithms. Further it only has POSIX dependencies, and allows all algorithms
to be used on stack as well as on heap. Accelerated algorithms are transparently
enabled if possible.

This package contains the Linux kernel module version.


%prep
%setup -q
set -- *
mkdir source
cp -ar "$@" source/
mkdir obj

%build
%meson
%meson_build
for flavor in %flavors_to_build; do
       rm -rf obj/$flavor
       cp -r source obj/$flavor
       make -C obj/$flavor/linux_kernel modules M=$PWD/obj/$flavor
done

%check
%meson_test

%install
%meson_install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=updates
for flavor in %flavors_to_build; do
       make -C obj/$flavor/linux_kernel modules_install M=$PWD/obj/$flavor
done

%post -n lib%{name}0 -p /sbin/ldconfig
%postun -n lib%{name}0 -p /sbin/ldconfig

%files -n lib%{name}0
%license LICENSE LICENSE.bsd LICENSE.gplv2
%{_libdir}/lib%{name}.so.*

%files devel
%doc README.md CHANGES.md
%{_includedir}/%{name}.h
%{_includedir}/%{name}
%{_libdir}/lib%{name}.so

%files devel-static
%{_libdir}/lib%{name}.a
