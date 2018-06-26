#!/bin/bash
# a shell script to write all the static text data content in .go files

writeConst() {
   printf "const $1=\`" >> $3
   cat $2 >> $3
   printf "\`\n\n" >> $3
}

writeHtml() {
  targetFile="net/static_html.go"
  printf "package net\n\n" > $targetFile
  writeConst "login_html" "templates/login.html" $targetFile
  writeConst "consent_html" "templates/consent.html" $targetFile
  writeConst "saml_response_html" "templates/saml_response.html" $targetFile
  writeConst "totp_register_html" "templates/totp-register.html" $targetFile
  writeConst "totp_send_html" "templates/totp-send.html" $targetFile
  writeConst "changepassword_html" "templates/changepassword.html" $targetFile
}

writeSchemas() {
  targetFile="net/static_schemas.go"
  printf "package net\n\n" > $targetFile
  writeConst "device_schema" "resources/schemas/device.json" $targetFile
  writeConst "enterprise_user_schema" "resources/schemas/enterprise-user.json" $targetFile
  writeConst "group_schema" "resources/schemas/group.json" $targetFile
  writeConst "user_schema" "resources/schemas/user.json" $targetFile
  writeConst "application_schema" "resources/schemas/application.json" $targetFile
  writeConst "authentication_schema" "resources/schemas/authentication.json" $targetFile
}

writeResourceTypes() {
  targetFile="net/static_resourcetypes.go"
  printf "package net\n\n" > $targetFile
  writeConst "device_type" "resources/types/device.json" $targetFile
  writeConst "group_type" "resources/types/group.json" $targetFile
  writeConst "user_type" "resources/types/user.json" $targetFile
  writeConst "application_type" "resources/types/application.json" $targetFile
}

copyVersionFile() {
    cp resources/version.txt net/version.go
}

copyVersionFile() {
    cp resources/version.txt net/version.go
    ver="1.0-alpha"
    rev=`git log --format=%h | head -n 1`
    time=`date`
    sed -e "s/\$version/$ver/g" -i '' net/version.go
    sed -e "s/\$revision/$rev/g" -i '' net/version.go
    sed -e "s/\$time/$time/g" -i '' net/version.go
}

printf "Writing HTML templates\n"
writeHtml

printf "Writing schemas\n"
writeSchemas

printf "Writing resourcetype\n"
writeResourceTypes

printf "Copying version file\n"
copyVersionFile
printf "Copying version file\n"
copyVersionFile