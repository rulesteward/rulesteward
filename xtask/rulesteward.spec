# The RPM around the musl binary. Built only through xtask/release.sh: `ver` and
# `srcroot` arrive as --define, so a hand `rpmbuild -bb xtask/rulesteward.spec`
# fails on an undefined macro rather than packaging whatever is in the tree.
#
# No %prep, %build or Source: the binary is already built by xtask/musl.sh and
# the spec only installs it. No %changelog either -- git log is the changelog,
# and a second one would drift.

# brp-strip would rewrite the binary rpmbuild is packaging, and the release
# promise is that the file inside the RPM is byte-identical to the one in the
# tarball, so the whole post-install brp chain is off.
%global __os_install_post %{nil}
# musl.sh builds with `strip = true`; there is no debuginfo left to extract, and
# on an EL host redhat-rpm-config would otherwise fail the build looking for it.
%global debug_package %{nil}
# rpmbuild 4.19 defaults to w19.zstdio. gzip is the one payload format every rpm
# from EL8 up reads, and this package targets EL8, 9 and 10 from one x86_64 file.
%define _binary_payload w9.gzdio
# rpmbuild generates /usr/lib/.build-id symlinks for every ELF file it packages
# and owns them in %%files. They are only useful beside a debuginfo package,
# which this has none of, and they would put three directories and a link into a
# package whose whole content is one binary and its licence.
%define _build_id_links none
# BUILDTIME, and every file mtime, come from SOURCE_DATE_EPOCH, which release.sh
# exports from the commit being built. from_changelog is off because there is no
# %%changelog (see above) and it is the source of rpmbuild's "set but %%changelog
# is missing" warning. _buildhost pins the last header field that took a value
# from the host.
%global use_source_date_epoch_as_buildtime 1
%global clamp_mtime_to_source_date_epoch 1
%global source_date_epoch_from_changelog 0
%global _buildhost rulesteward

Name:           rulesteward
Version:        %{ver}
Release:        1
# Summary and %description are here because rpmbuild refuses a spec without them.
Summary:        audit2why/audit2allow for host policy systems
License:        GPL-3.0-or-later
URL:            https://github.com/rulesteward/rulesteward
# The binary is static musl and the package owns no scripts, so there is nothing
# for rpm to discover; a found dependency would be a bug, and release.sh fails
# the build if one appears.
AutoReqProv:    no

%description
Reads fapolicyd denial records on stdin and writes the rules that would allow them on stdout.

%install
install -Dm755 %{srcroot}/target/x86_64-unknown-linux-musl/release/rulesteward %{buildroot}/usr/bin/rulesteward
install -Dm644 %{srcroot}/LICENSE %{buildroot}/usr/share/licenses/rulesteward/LICENSE

%files
/usr/bin/rulesteward
# %%{_licensedir} is undefined on a host without redhat-rpm-config, so the path is
# literal and matches what EL macros expand to anyway.
%license /usr/share/licenses/rulesteward/LICENSE
