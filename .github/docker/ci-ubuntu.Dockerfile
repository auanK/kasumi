FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then \
      sed -i 's|http://archive.ubuntu.com/ubuntu/|http://mirrors.edge.kernel.org/ubuntu/|g' /etc/apt/sources.list.d/ubuntu.sources; \
    fi; \
    printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\nAcquire::ForceIPv4 "true";\n' > /etc/apt/apt.conf.d/80-retries; \
    apt_install() { \
      for attempt in 1 2 3; do \
        if apt-get update && apt-get install -y --no-install-recommends --fix-missing "$@"; then \
          return 0; \
        fi; \
        echo "apt-get install failed (attempt ${attempt}/3), retrying in 10s..." >&2; \
        sleep 10; \
      done; \
      return 1; \
    }; \
    apt_install \
      ca-certificates \
      sudo \
      ccache \
      cmake \
      ninja-build \
      gcc-14 \
      g++-14 \
      clang-19 \
      clang-tools-19 \
      libclang-rt-19-dev \
      lld-19 \
      libstdc++-14-dev \
      git \
      unzip \
      python3 \
      python3-dbus \
      gnome-keyring \
      libsecret-1-0 \
      libsecret-tools \
      dbus-x11 \
      dpkg-dev \
      rpm \
      file \
      zstd; \
    apt_install kwallet6 || apt_install libkf5wallet-bin; \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100 --slave /usr/bin/g++ g++ /usr/bin/g++-14; \
    update-alternatives --set gcc /usr/bin/gcc-14; \
    useradd -m -u 1001 -s /bin/bash runner; \
    echo 'runner ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/runner; \
    chmod 0440 /etc/sudoers.d/runner; \
    rm -rf /var/lib/apt/lists/*

USER runner
