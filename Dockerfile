FROM scratch

COPY terrarium /usr/local/bin/

ENTRYPOINT ["terrarium"]
