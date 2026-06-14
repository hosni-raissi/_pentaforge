import sys, os
sys.path.append(os.getcwd())
from server.utils.cvss import calculate_cvss, _DEFAULT_VERSION

vectors = [
    f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
    f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", # unauthenticated idor
    f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", # authenticated idor
    f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", # ssrf
    f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", # sqli
    f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", # xss
    f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N", # medium
    f"{_DEFAULT_VERSION}/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", # low
]

for v in vectors:
    print(v, calculate_cvss(v)["score"])
