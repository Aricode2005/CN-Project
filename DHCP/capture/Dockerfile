FROM alpine:3.19
RUN apk add --no-cache tcpdump
COPY capture.sh /capture.sh
RUN sed -i 's/\r$//' /capture.sh && chmod +x /capture.sh
ENTRYPOINT ["/capture.sh"]
