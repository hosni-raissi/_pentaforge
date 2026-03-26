# ── manual test ──────────────────────────────────────────────────────────────
from server.layers.safety.target_validation import UrlNormalizer, IPValidator
import asyncio
async def _main() -> None:
    print("\n=== URL normalizer test ===")
    test_cases = [
        "https://google.com",        
        "http://google.com",         
        "google.com",                
        "http://example.com",       
        "https://dead-host.xyz",     
        "notahost.invalid",          
        "",                          
    ]

    for url in test_cases:
        result = await UrlNormalizer(url).normalize()
        label = f'"{url}"' if url else "(empty)"
        print(f"{label:<30} → {result}")

    print("\n=== IP validator test ===")
    ip_test_cases = [
        "192.168.1.10",
        "8.8.8.8",
        "127.0.0.1",
        "2001:4860:4860::8888",
        "10.0.0.0/24",
        "10.0.0.5/24",
        "999.1.1.1",
        "abc.def.ghi.jkl",
        "",
    ]

    for ip_value in ip_test_cases:
        result = IPValidator(ip_value).validate()
        label = f'"{ip_value}"' if ip_value else "(empty)"
        print(f"{label:<30} → {result}")


if __name__ == "__main__":
    asyncio.run(_main())
