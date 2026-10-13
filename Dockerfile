# syntax=docker/dockerfile:1
FROM scratch
ARG TARGETARCH
ENV OFC_DATA_DIR=/data
ENV OFC_ADDR=:8080

VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/bin/ofc"]

COPY bin/ofc-linux-${TARGETARCH} /bin/ofc

