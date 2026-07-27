# rs-oracle9: Rocky Linux 9 carrying all three session-9k-1 differential oracles,
# for the auditd / sysctld / sudoers capture tiers.
#
# ONE image set serves all three lanes rather than three sets of three. The lanes
# are crate-disjoint but their oracles are not mutually exclusive, the packages
# are small, and a single set means one `docker build` loop in each drift
# workflow instead of three.
#
#   audit         -> auditctl, the Lane A rule-line parse oracle
#   systemd-udev  -> /usr/lib/systemd/systemd-sysctl, the Lane B oracle. It ships
#                    in systemd-udev, NOT in systemd, and it is NOT on PATH.
#   sudo          -> visudo + cvtsudoers, the Lane C stdin oracles
#
# Unlike the fapolicyd8/9/10 images (prebuilt, dev-machine-only, no committed
# Dockerfile), these are built from this directory so CI can rebuild them, which
# is what lets each lane have a scheduled drift workflow at all.
FROM rockylinux/rockylinux:9
RUN dnf install -y audit systemd-udev sudo && dnf clean all
