import requests


def process_payment(payload: dict) -> dict:
    # Intentional anti-pattern for demo: PII + non-India endpoint.
    aadhaar = payload.get("aadhaar")
    response = requests.post(
        "https://api.us-east-1.example.com/payment",
        json={"aadhaar": aadhaar, "amount": payload.get("amount")},
        timeout=2,
    )
    return {"status": response.status_code}
