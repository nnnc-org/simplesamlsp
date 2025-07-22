# SimpleSamlSp

A simple SAML Service Provider (SP) implementation in golang. This is a test app designed just to print all the attributes for a user. Useful for debugging IDP attributes being sent to an SP.

## Usage

### Docker Compose (recommended)

```yaml
version: '3.8'

services:
  simplesamlsp:
    image: ghcr.io/nnnc-org/simplesamlsp:latest
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - ./certs:/cert
    environment:
      - SAML_CERT_FILE=/cert/myservice.cert
      - SAML_KEY_FILE=/cert/myservice.key
      - SAML_IDP_METADATA_URL=https://idp.example.org/simplesaml/saml2/idp/metadata.php
      - APP_URL=http://localhost:8080/
      - APP_NAME=Nebraska Cloud Testing Page
```

### Running Directly

To run the application directly, ensure you have Go installed and set up. Then, you can run the following command in your terminal:

```bash
$ go build -o simplesamlsp main.go
$ SAML_CERT_FILE=myservice.cert SAML_KEY_FILE=myservice.key SAML_IDP_METADATA_URL=https://idp.example.org/simplesaml/saml2/idp/metadata.php APP_URL=http://localhost:8080/ simplesamlsp
```

## Environment Variables

| Variable                | Default | Description                                      |
|-------------------------|---------|--------------------------------------------------|
| `SAML_CERT_FILE`        | -       | Path to the SAML certificate file                |
| `SAML_KEY_FILE`         | -       | Path to the SAML private key file                |
| `SAML_IDP_METADATA_URL` | -       | URL to the SAML Identity Provider metadata       |
| `APP_URL`               | -       | URL of the application (used for SAML responses) |
| `APP_NAME`              | -       | Name for application page                        |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
