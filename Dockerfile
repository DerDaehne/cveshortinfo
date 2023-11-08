FROM scratch

COPY ./cveshortinfo ./cveshortinfo
COPY ./templates ./templates

ENTRYPOINT ["./cveshortinfo"]
