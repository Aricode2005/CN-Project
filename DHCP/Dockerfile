FROM eclipse-temurin:11-jdk-alpine
WORKDIR /app
COPY src ./src
RUN mkdir -p out data && \
    javac -d out src/dhcp/protocol/*.java src/dhcp/model/*.java src/dhcp/cluster/*.java src/dhcp/lb/*.java src/dhcp/client/*.java src/dhcp/dashboard/*.java src/dhcp/Main.java
EXPOSE 67/udp 6700/udp 6701/udp 6702/udp 6703/udp 8080/tcp
ENTRYPOINT ["java", "-cp", "out", "dhcp.Main"]
