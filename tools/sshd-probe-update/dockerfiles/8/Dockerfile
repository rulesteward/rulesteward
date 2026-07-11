# sshd-probe8: Rocky Linux 8 with a real sshd binary, for the sshd-probe-update
# drift tool (#372). openssh-server is ABSENT from the fapolicyd differential
# images, so it is installed here; ssh-keygen -A generates host keys so `sshd -t`
# does not fail on a missing /etc/ssh/ssh_host_*_key. man-db/man-pages back the
# tool's advisory (never-failing) man-page keyword-discovery pass (#471); the
# image's default dnf tsflags=nodocs would otherwise strip openssh-server's own
# sshd_config(5) man page, so --setopt=tsflags= overrides it for this install.
FROM rockylinux/rockylinux:8
RUN dnf install -y --setopt=tsflags= openssh-server man-db man-pages && ssh-keygen -A
