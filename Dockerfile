FROM php:latest

# Really my email ends with zighinetto "organization", but for antispam reasons I am masking
# And no offense for the real Greeks, there is a long story why it is pronunciated ECHELON
LABEL maintainer="/usr/local/ΕΨΗΕΛΩΝ <djechelon@github.com>"

RUN pear channel-discover phpseclib.sourceforge.net && \
    pear install phpseclib/Crypt_AES phpseclib/Crypt_RSA

WORKDIR /usr/local/php
COPY TitaniumBackupDecrypt.php /usr/local/php

ENTRYPOINT ["php", "/usr/local/php/TitaniumBackupDecrypt.php"]