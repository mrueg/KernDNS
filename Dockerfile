# syntax=docker/dockerfile:1
#
# KernDNS as a drop-in for the CoreDNS image: the binary is /coredns (with
# /kerndns as an alias), it runs as uid/gid 65532 with cap_net_bind_service
# on the file, and the entrypoint takes CoreDNS's flags, so kubeadm's
# Deployment (`args: [-conf, /etc/coredns/Corefile]`) works by changing only
# the image. glibc rather than static musl, so `-bridge` can still dlopen a
# Go plugin library.
#
#   docker build -t kerndns .

ARG RUST_IMAGE=rust:1-trixie
ARG BASE=gcr.io/distroless/cc-debian13:nonroot

FROM ${RUST_IMAGE} AS build
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -qq update \
    && apt-get -qq --no-install-recommends install libcap2-bin
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release --package kerndns \
    && mkdir /out \
    && cp target/release/kerndns /out/kerndns \
    && ln -s kerndns /out/coredns \
    && setcap cap_net_bind_service=+ep /out/kerndns

FROM ${BASE}
COPY --from=build /out/ /
# numeric uid/gid (distroless "nonroot"), so runAsNonRoot can verify it
USER 65532:65532
WORKDIR /
EXPOSE 53 53/udp
ENTRYPOINT ["/coredns"]
