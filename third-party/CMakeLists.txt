cmake_minimum_required(VERSION 3.16)
project(third-party-code NONE)

#set(OpenSSL_URL "https://www.openssl.org/source/openssl-1.1.1k.tar.gz")
#set(OpenSSL_SHA256 "892a0875b9872acd04a9fde79b1f943075d5ea162415de3047c327df33fbaee5")

set(cURL_URL "https://github.com/curl/curl/releases/download/curl-7_77_0/curl-7.77.0.tar.gz")
set(cURL_SHA256 "b0a3428acb60fa59044c4d0baae4e4fc09ae9af1d8a3aa84b2e3fbcd99841f77")

set(Boost_URL "https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.bz2")
set(Boost_SHA256 "f0397ba6e982c4450f27bf32a2a83292aba035b827a5623a14636ea583318c41")

set(BUNDLED_DEP_PREFIX "${CMAKE_BINARY_DIR}/output")

include(ExternalProject)

# TODO: Add ZNC ExternalProject ?

# We get OpenSSL from znc-dev(el) anyhow and I don't
# plan on dealing with potentially numerous ZNC releases.
#ExternalProject_Add(OpenSSL
#    PREFIX ${BUNDLED_DEP_PREFIX}
#    URL "${OpenSSL_URL}"
#    URL_HASH SHA256=${OpenSSL_SHA256}
#    TLS_VERIFY ON
#    BUILD_IN_SOURCE ON
#    CONFIGURE_COMMAND ./config -Os -fPIC --prefix=${BUNDLED_DEP_PREFIX}
#    BUILD_COMMAND $(MAKE)
#    INSTALL_COMMAND $(MAKE) install_sw
#)

ExternalProject_Add(cURL
    PREFIX ${BUNDLED_DEP_PREFIX}
    URL ${cURL_URL}
    URL_HASH SHA256=${cURL_SHA256}
    TLS_VERIFY ON
    BUILD_IN_SOURCE ON
    # We only need SMTP SMTPS
    CONFIGURE_COMMAND ./configure
        --prefix ${BUNDLED_DEP_PREFIX}
        --with-openssl
        --with-pic --disable-shared
        --disable-proxy
        --disable-manual
        --disable-cookies
        --without-zlib
        --disable-crypto-auth
        --disable-DICT
        --disable-FILE
        --disable-FTP
        --disable-FTPS
        --disable-GOPHER
        --disable-GOPHERS
        --disable-HTTP
        --disable-HTTPS
        --disable-IMAP
        --disable-IMAPS
        --disable-MQTT
        --disable-POP3
        --disable-POP3S
        --disable-RTSP
        --disable-SMB
        --disable-SMBS
        --disable-TELNET
        --disable-TFTP
    BUILD_COMMAND $(MAKE)
    INSTALL_COMMAND $(MAKE) install
    #DEPENDS OpenSSL
)

# TODO: I really only need the headers, but maybe I'll use Boost::chrono.
ExternalProject_Add(Boost
    PREFIX ${BUNDLED_DEP_PREFIX}
    URL ${Boost_URL}
    URL_HASH SHA256=${Boost_SHA256}
    TLS_VERIFY ON
    BUILD_IN_SOURCE ON
    CONFIGURE_COMMAND ./bootstrap.sh --prefix=${BUNDLED_DEP_PREFIX}
    BUILD_COMMAND ./b2 -d+2 link=static --without-python --without-iostreams
    INSTALL_COMMAND ./b2 install --prefix=${BUNDLED_DEP_PREFIX}
)
