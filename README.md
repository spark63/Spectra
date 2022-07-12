# Spectra

This action allows you to scan your solidity smart contract code.

## How to use

* Create .github/workflows/spectra.yml:

```yml
name: Spectra Analysis
on: [push]

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      actions: read
      contents: read
    name: Spectra
    steps:
      - uses: actions/checkout@v3
      - name: Run Spectra
        id: spectra
        uses: spark63/Spectra@v1.0.4
```
* Basically, it works when a push event occurs.
* If you want to change the triggering event, you can change the `on` section of the yml.


## Outputs
* This action supports the Github Code Scanning integration, which will push Spectra's alerts to the Security tab of the your Github project.



