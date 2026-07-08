# sshd-probe9: Rocky Linux 9 with a real sshd binary, for the sshd-probe-update
# drift tool (#372). openssh-server is ABSENT from the fapolicyd differential
# images, so it is installed here; ssh-keygen -A generates host keys so `sshd -t`
# does not fail on a missing /etc/ssh/ssh_host_*_key. man-db/man-pages back the
# tool's advisory (never-failing) man-page keyword-discovery pass.
FROM rockylinux/rockylinux:9
RUN dnf install -y openssh-server man-db man-pages && ssh-keygen -A
