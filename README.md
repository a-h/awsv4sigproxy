# AWS V4 Signature Proxy

Proxies unsigned requests to API Gateway, signing them along the way to make it easier to test IAM authenticated APIs.

## Usage

```sh
awsv4sigproxy -remote=https://xxxxx.execute-api.eu-west-1.amazonaws.com
```

```sh
curl http://localhost:6666/prod/test/1234
```

## Tasks

### build

```sh
go build
```

