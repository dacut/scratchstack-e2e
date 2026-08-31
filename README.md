# scratchstack-e2e

Scratchstack end-to-end testing utility

# generate boto3 services

```
uvx mypy_boto3_builder ./vendored --download-static-stubs --product types-boto3-custom --output-type wheel --services iam sts
```

# install with uv

```
uv add --dev vendored/types_boto3_custom-1.43.81-py3-none-any.whl
```
