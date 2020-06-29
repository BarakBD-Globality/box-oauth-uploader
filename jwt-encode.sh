#!/usr/bin/env bash

# https://willhaley.com/blog/generate-jwt-with-bash/
# JWT Encoder Bash Script
# Other resources
# https://stackoverflow.com/questions/58313106/create-rs256-jwt-in-bash
# https://willhaley.com/blog/generate-jwt-with-bash/
# https://github.com/rooty0/box-oauth-uploader.git
# https://developer.box.com/guides/authentication/jwt/without-sdk/
# https://stackoverflow.com/questions/34328759/how-to-get-a-random-string-of-32-hexadecimal-digits-through-command-line


source box-config.sh

# ----- FUNCTIONS -----
base64_encode()
{
	declare input=${1:-$(</dev/stdin)}
	# Use `tr` to URL encode the output from base64.
	printf '%s' "${input}" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n'
}

json() {
	declare input=${1:-$(</dev/stdin)}
	printf '%s' "${input}" | jq -c .
}

sha512_sign()
{
	declare input=${1:-$(</dev/stdin)}
	printf '%s' "${input}" | openssl dgst  -binary -sha512 -sign private-key-encrypted -passin pass:$PASSPHRASE
}

# ----- HEADER -----
# Static header field
header='{
  "algorithm": "RS512",
  "keyid" : ""
}'

# Use jq to set the dynamic `keyid` field
header=$(
	echo "${header}" | jq --arg key_id $PUBLIC_KEY_ID \
	'.keyid=$key_id'
)
echo
echo ----- HEADER -----
echo $header | json
header_base64=$(echo "${header}" | json | base64_encode)
echo header_base64 - $header_base64
echo

# -----  CLAIMS -----
# Static claims fields
claims='{
  "iss": "",
  "sub": "",
  "box_sub_type": "enterprise",
  "aud": "",
  "jti": "",
  "exp": ""
}'

claims=$(
	echo "${claims}" | jq \
    --arg client_id $CLIENT_ID \
    --arg enterprise_id $ENTERPRISE_ID \
    --arg box_request_token_url $BOX_REQUEST_TOKEN_URL \
    --arg random_hex $(hexdump -n 16 -e '4/4 "%08X" 1 "\n"' /dev/random) \
    --arg time_str "$(date +%s)" \
    '
    ($time_str | tonumber) as $time_num
    | .iss=$client_id
    | .sub=$enterprise_id
    | .aud=$box_request_token_url
    | .jti=$random_hex
  	| .exp=($time_num + 45)
    '
)
echo ----- CLAIMS -----
echo $claims | json
claims_base64=$(echo "${claims}" | json | base64_encode)
echo claims_base64 - $claims_base64
echo


# ----- SIGN -----
echo ----- SIGN -----
header_claims=$(echo "${header_base64}.${claims_base64}")
echo header_claims - $header_claims
echo

signature=$(echo "${header_claims}" | sha512_sign | base64_encode)
echo signature - $signature
echo

assertion="${header_claims}.${signature}"
echo assertion - $assertion
echo

# ----- REQUEST -----

echo ----- REQUEST -----

curl --request POST $BOX_REQUEST_TOKEN_URL \
          --location \
          --silent \
          --header 'Content-Type: application/x-www-form-urlencoded' \
          --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
          --data-urlencode "assertion=${assertion}" \
          --data-urlencode "client_id=${CLIENT_ID}" \
          --data-urlencode "client_secret=${CLIENT_SECRET}" \
          --dump-header -
          # --output "jwt-long" \
