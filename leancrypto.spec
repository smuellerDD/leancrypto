#
# spec file for package leancrypto
#
# Copyright (c) 2022 - 2025 Stephan Mueller <smueller@chronox.de
#

Name:           leancrypto
Version:        1.5.1
Release:        1.1
Summary:        Cryptographic library with stack-only support and PQC-safe algorithms
License:        GPL-2.0 OR BSD-2-Clause
URL:            https://www.leancrypto.org
Source0:        https://www.leancrypto.org/%{name}/releases/%{name}-%{version}/%{name}-%{version}.tar.xz
#Source1:        https://www.leancrypto.org/%{name}/releases/%{name}-%{version}/%{name}-%{version}.tar.xz.asc
BuildRequires:  meson
BuildRequires:  clang
BuildRequires:	%kernel_module_package_buildreqs

%description
Leancrypto provides a general-purpose cryptographic library with PQC-safe
algorithms. Further it only has POSIX dependencies, and allows all algorithms
to be used on stack as well as on heap. Accelerated algorithms are transparently
enabled if possible.

%package -n lib%{name}1
Summary:        Cryptographic library with stack-only support and PQC-safe algorithms
Provides:       %{name} = %{version}-%{release}
Obsoletes:      %{name} < %{version}-%{release}

%description -n lib%{name}1
Leancrypto provides a general-purpose cryptographic library with PQC-safe
algorithms. Further it only has POSIX dependencies, and allows all algorithms
to be used on stack as well as on heap. Accelerated algorithms are transparently
enabled if possible.

%package devel
Summary:        Development files for leancrypto, a cryptographic library
Requires:       glibc-devel
Requires:       lib%{name}1 = %{version}
# Cannot be noarch due to leancrypto.so symlink
#BuildArch:      noarch
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

%package -n lib%{name}-fips1
Summary:        Cryptographic library with stack-only support and PQC-safe algorithms
Provides:       %{name} = %{version}-%{release}
Obsoletes:      %{name} < %{version}-%{release}

%description -n lib%{name}-fips1
Leancrypto provides a general-purpose cryptographic library with PQC-safe
algorithms. Further it only has POSIX dependencies, and allows all algorithms
to be used on stack as well as on heap. Accelerated algorithms are transparently
enabled if possible.

This subpackage contains the FIPS 140 compliant version of the library.

%package -n %{name}-tools
Summary:        Applications provided by leancrypto
Requires:       glibc-devel
Requires:       lib%{name}1 = %{version}

%description -n %{name}-tools
Leancrypto provides a general-purpose cryptographic library with PQC-safe
algorithms. Further it only has POSIX dependencies, and allows all algorithms
to be used on stack as well as on heap. Accelerated algorithms are transparently
enabled if possible.

This subpackage holds the tools provided by the library, such as sha*sum.

%kernel_module_package

%package -n lib%{name}1-kernel
Summary:	Cryptographic library with PQC-safe algorithms Kernel Module Package

%description -n lib%{name}1-kernel
Leancrypto provides a general-purpose cryptographic library with PQC-safe
algorithms. Further it only has POSIX dependencies, and allows all algorithms
to be used on stack as well as on heap. Accelerated algorithms are transparently
enabled if possible.

This package contains the Linux kernel module version of leancrypto. This
kernel module offers the same APIs and functions in kernel space that are
available in user space.


%prep
%setup -q
set -- *
mkdir source
cp -ar "$@" source/
mkdir obj

%build
%meson -Dseedsource=esdm
%meson_build
for flavor in %flavors_to_build; do
	KERNELRELEASE=`make -s -C /%{_prefix}/src/linux-obj/%{_target_cpu}/$flavor kernelrelease`
	rm -rf obj/$flavor
	cp -r source obj/$flavor
	make -C $PWD/obj/$flavor/linux_kernel KERNELRELEASE=$KERNELRELEASE
done

%check
%meson_test --suite regression

%install
%meson_install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=updates
for flavor in %flavors_to_build; do
	KERNELRELEASE=`make -s -C /%{_prefix}/src/linux-obj/%{_target_cpu}/$flavor kernelrelease`
	make -C obj/$flavor/linux_kernel modules_install M=$PWD/obj/$flavor KERNELRELEASE=$KERNELRELEASE
done

%post -n lib%{name}1 -p /sbin/ldconfig
%postun -n lib%{name}1 -p /sbin/ldconfig

%files -n lib%{name}1
%license LICENSE LICENSE.bsd LICENSE.gplv2
%{_libdir}/lib%{name}.so.*
%{_libdir}/pkgconfig/%{name}.pc

%files devel
%doc README.md CHANGES.md
%{_includedir}/%{name}.h
%{_includedir}/%{name}
%{_libdir}/lib%{name}.so
%{_libdir}/lib%{name}-fips.so

%files devel-static
%{_libdir}/lib%{name}.a
%{_libdir}/lib%{name}-fips.a

%files -n lib%{name}-fips1
%{_libdir}/lib%{name}-fips.so.*
%{_libdir}/pkgconfig/%{name}-fips.pc

%files -n %{name}-tools
%{_libexecdir}/%{name}
%{_libexecdir}/%{name}/sha256sum
%{_libexecdir}/%{name}/sha384sum
%{_libexecdir}/%{name}/sha512sum
%{_libexecdir}/%{name}/sha3-256sum
%{_libexecdir}/%{name}/sha3-384sum
%{_libexecdir}/%{name}/sha3-512sum
%{_libexecdir}/%{name}/ascon256-sum
