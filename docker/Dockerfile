FROM arm32v7/debian:10

ENV KEYCLOAK_VERSION 11.0.3

ENV JDBC_POSTGRES_VERSION 42.2.5
ENV JDBC_MYSQL_VERSION 8.0.19
ENV JDBC_MARIADB_VERSION 2.5.4
ENV JDBC_MSSQL_VERSION 7.4.1.jre11

ENV LAUNCH_JBOSS_IN_BACKGROUND 1
ENV PROXY_ADDRESS_FORWARDING false
ENV JBOSS_HOME /opt/jboss/keycloak

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8
ENV LC_ALL en_US.UTF-8

ARG GIT_REPO
ARG GIT_BRANCH
ARG KEYCLOAK_DIST=https://downloads.jboss.org/keycloak/$KEYCLOAK_VERSION/keycloak-$KEYCLOAK_VERSION.tar.gz

USER root

RUN apt-get update -y && \
  apt-get install -y locales && \
  sed -i -e "s/# *$LANG.*/$LANG UTF-8/" /etc/locale.gen && \
  dpkg-reconfigure --frontend=noninteractive locales && \
  update-locale LANG=$LANG && \
  apt-get install -y \
  unzip \
  curl \
  gzip \
  hostname \
  openjdk-11-jdk-headless \
  openssl \
  tar \
  debianutils && \
  apt-get clean

RUN mkdir -p /opt/jboss && \
  cd /tmp && \
  curl -s -L -o keycloak.zip https://github.com/keycloak/keycloak-containers/archive/${KEYCLOAK_VERSION}.zip && \
  unzip keycloak.zip "keycloak-containers-${KEYCLOAK_VERSION}/server/*" && \
  mv keycloak-containers-${KEYCLOAK_VERSION}/server/tools/ /opt/jboss && \
  rm -rf keycloak* && \
  sed -i 's/microdnf/apt-get/g' /opt/jboss/tools/build-keycloak.sh && \
  chmod 755 /opt/jboss/tools/build-keycloak.sh && \
  /opt/jboss/tools/build-keycloak.sh

USER 1000

EXPOSE 8080
EXPOSE 8443

ENTRYPOINT [ "/opt/jboss/tools/docker-entrypoint.sh" ]

CMD ["-b", "0.0.0.0"]
