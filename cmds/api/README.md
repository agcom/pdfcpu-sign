# Go Sign Server

The Go Sign Server service's functionality is **adding digital signatures to PDF documents**.

## Configuration

Configuration of the service is done through setting the following environment variables before starting the service; we repeatedly refer to a key pair and its corresponding certificate as a kert.

| Environment Variable            | Default Value                         | Description                                                                                                            |
|---------------------------------|---------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| SIGN_SERVER_HTTP_PORT           | 4648                                  | The port that this service's HTTP server listens on.                                                                   |
| SIGN_SERVER_PKCS11_LIB_PATH     | /usr/local/lib/softhsm/libsofthsm2.so | The path to the PKCS#11 library.                                                                                       |
| SIGN_SERVER_PKCS11_TOKEN_SLOT   |                                       | *Required; select the token with this slot identifier to look into for the kert; has preference over serial and label. |
| SIGN_SERVER_PKCS11_TOKEN_SERIAL |                                       | *Required; select the token with this serial identifier to look into for the kert; has preference over label.          |
| SIGN_SERVER_PKCS11_TOKEN_LABEL  |                                       | *Required; select the token with this label to look into for kert.                                                     |
| SIGN_SERVER_PKCS11_TOKEN_PIN    |                                       | Optional; the token pin for login.                                                                                     |
| SIGN_SERVER_PKCS11_KERT_ID_HEX  |                                       | Optional; the id of the kert to get from the PKCS#11.                                                                  |
| SIGN_SERVER_PKCS11_KERT_LABEL   |                                       | Optional; the label of kert to get from the PKCS#11.                                                                   |

> *Required: at least one way to select a token must be provided; in other words, at least one of the `SIGN_SERVER_PKCS11_TOKEN_SLOT`, `SIGN_SERVER_PKCS11_TOKEN_SERIAL`, and `SIGN_SERVER_PKCS11_TOKEN_LABEL` environment variables must be set.

> Do not forget to load your HSM's specific configuration if there are any (the HSM behind the PKCS#11 interface implemented by the provided library); it is usually done through setting a specific environment variable, for example `SOFTHSM2_CONF=/home/user/config.file` when using SoftHSMv2 with a custom configuration.

## API

There is only one HTTP API endpoint.

### POST /v1/sign

Receives a signature information JSON object beside a PDF document, both bundled in a `multipart/form-data` request (`sign-info` and `pdf-file` fields); returns the signed PDF document.

The signature information model:
```json
{
	"type": "certification", // Required; possible values are certification and approval.
	"docMdp": "no-changes", // Required if type=certification; possible values are no-changes, form-sign, and form-sign-annot.
	"signerInfo": { // Optional
		"name": "Alireza", // Optional
		"location": "Earth", // Optional
		"reason": "Test", // Optional
		"contactInfo": "example@example.com", // Optional
		"time": "2023-12-28T21:30:00.000Z" // Optional; ISO-8601 representation of a date-time.
	}
}
```

Example request:

```text
POST /v1/sign HTTP/2
Content-Type: multipart/form-data; boundary=------------------------2lllWzF6kb9cgoKNL2ZEJY
Content-Length: ...
Accept: application/pdf

--------------------------2lllWzF6kb9cgoKNL2ZEJY
Content-Disposition: form-data; name=sign-info
Content-Type: application/json

{
	"type": "certification",
	"docMdp": "no-changes",
	"signerInfo": {
		"name": "Alireza",
		"location": "Earth",
		"reason": "Test",
		"contactInfo": "example@example.com",
		"time": "2023-12-28T21:30:00.000Z"
	}
}

--------------------------2lllWzF6kb9cgoKNL2ZEJY
Content-Disposition: form-data; name=pdf-file; filename=sample.pdf
Content-Type: application/pdf

%PDF-1.7...
...
...%%EOF
--------------------------2lllWzF6kb9cgoKNL2ZEJY--
```

Example response:

```text
HTTP/2 200
content-type: application/pdf

%PDF-1.7...
...
...%%EOF
```