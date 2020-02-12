%define _helper_root /opt/spiffe-helper
%define _examples    %{_helper_root}/examples
%define debug_package %{nil}			# Do not build debuginfo RPM


Name:    spiffe-helper
Version: %{version}
Release: %{build_number}%{?dist}
Summary: Utility for fetching X.509 SVID certificates from the SPIFFE Workload API
License: Apache License 2.0
URL:     https://github.com/spiffe/spiffe-helper
Vendor:  SPIFFE
Source:  spiffe-helper.tar.gz

%description
The SPIFFE Helper is a simple utility for fetching X.509 SVID certificates from the SPIFFE Workload API,
launch a process that makes use of the certificates and continuously get new certificates before they expire.
The launched process is signaled to reload the certificates when is needed.

%prep
%setup -q -n spiffe-helper

%build
# Move to spiffe-helper root directory
cd /root/spiffe-helper

# Check required golang version
GO_VERSION_FILE_EXPECTED=/root/spiffe-helper/.go-version
if test -f "$GO_VERSION_FILE_EXPECTED"; then
  GO_VERSION_EXPECTED=go$(cat "$GO_VERSION_FILE_EXPECTED")
else
  echo "Go version file not found at $GO_VERSION_FILE_EXPECTED"
  exit
fi

# Check current golang version
GO_VERSION_FILE_CURRENT=/usr/local/go/VERSION
if test -f "$GO_VERSION_FILE_CURRENT"; then
    GO_VERSION_CURRENT=$(cat "$GO_VERSION_FILE_CURRENT")
fi

# If current != required, install golang
if [ "$GO_VERSION_EXPECTED" != "$GO_VERSION_CURRENT" ]; then
    wget https://dl.google.com/go/$GO_VERSION_EXPECTED.linux-amd64.tar.gz
    tar -xzf $GO_VERSION_EXPECTED.linux-amd64.tar.gz
    mv go /usr/local
fi

# Test & build
export GOROOT=/usr/local/go
export GOPATH=/root
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
make all

%install
%{__install} -p -d -m 0750 %{buildroot}/%{_helper_root}
%{__install} -p -d -m 0755 %{buildroot}/%{_examples}

cp -p /root/spiffe-helper/spiffe-helper %{buildroot}/%{_helper_root}/
cp -p /root/spiffe-helper/helper.conf %{buildroot}/%{_helper_root}/

cp -p /root/spiffe-helper/helper_envoy.conf %{buildroot}/%{_examples}/
cp -p /root/spiffe-helper/helper_ghostunnel.conf %{buildroot}/%{_examples}/
cp -p /root/spiffe-helper/examples/mysql/helper.conf %{buildroot}/%{_examples}/helper_mysql.conf
cp -p /root/spiffe-helper/examples/postgresql/helper.conf %{buildroot}/%{_examples}/helper_postgresql.conf


%files
%dir %{_helper_root}
%dir %{_examples}
%attr(750, -, -) %{_helper_root}/spiffe-helper
%attr(644, -, -) %{_helper_root}/helper.conf
%attr(644, -, -) %{_examples}/*

%doc

%clean

%changelog
