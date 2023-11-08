FROM scratch

ADD ./cveshortinfo
ADD ./templates

ENTRYPOINT ["./cveshortinfo"]
