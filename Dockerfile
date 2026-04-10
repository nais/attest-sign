FROM alpine:3.21

ARG COSIGN_VERSION=v3.0.5
ARG TRIVY_VERSION=0.69.3
ARG ORAS_VERSION=1.3.1

RUN apk add --no-cache \
    bash \
    curl \
    jq \
    ca-certificates

# Install cosign
# Checksum from https://github.com/sigstore/cosign/releases/download/v3.0.5/cosign_checksums.txt
RUN curl -fsSL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" \
    -o /usr/local/bin/cosign \
    && echo "db15cc99e6e4837daabab023742aaddc3841ce57f193d11b7c3e06c8003642b2  /usr/local/bin/cosign" | sha256sum -c - \
    && chmod +x /usr/local/bin/cosign

# Install trivy
# Checksum from https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_checksums.txt
RUN curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    -o /tmp/trivy.tar.gz \
    && echo "1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75  /tmp/trivy.tar.gz" | sha256sum -c - \
    && tar -xz -f /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz

# Install oras
# Checksum from https://github.com/oras-project/oras/releases/download/v1.3.1/oras_1.3.1_checksums.txt
RUN curl -fsSL "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz" \
    -o /tmp/oras.tar.gz \
    && echo "d52c4af76ce6a3ceb8579e51fb751a43ac051cca67f965f973a0b0e897a2bb86  /tmp/oras.tar.gz" | sha256sum -c - \
    && tar -xz -f /tmp/oras.tar.gz -C /usr/local/bin oras \
    && rm /tmp/oras.tar.gz

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
