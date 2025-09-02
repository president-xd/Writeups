FROM azul/zulu-openjdk-debian:21-latest AS builder

RUN useradd -m -u 1001 -s /bin/bash builder
USER builder

WORKDIR /usr/src/agebarrier
COPY --chown=builder:builder . .
RUN ./gradlew --no-daemon bootJar

FROM azul/zulu-openjdk-debian:21-jre-latest

RUN useradd -m -u 1001 -s /bin/bash app
USER app

WORKDIR /usr/share/agebarrier
COPY --from=builder "/usr/src/agebarrier/build/libs/agebarrier-0.0.1-SNAPSHOT.jar" app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAM=30M", "-XX:+UseSerialGC", "-Dserver.tomcat.max-threads=2", "-jar", "app.jar"]
