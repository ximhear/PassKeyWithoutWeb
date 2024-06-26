from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64

# RSA 키 생성 (개인 키와 공개 키)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()
print("private_key: ", private_key)

# 개인 키를 PEM 형식으로 변환
pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# 공개 키를 PEM 형식으로 변환
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
# print(pem_private_key.decode('utf-8'))
#
# # PEM 형식의 키를 Base64로 인코딩
# b64_private_key = base64.b64encode(pem_private_key).decode('utf-8')
# b64_public_key = base64.b64encode(pem_public_key).decode('utf-8')
#
# # 로그 출력
# print("DER 형식의 개인 키:")
# # print(pem_private_key)
# print("\nBase64로 인코딩된 개인 키:")
# print(b64_private_key)
#
# print("\DER 형식의 공개 키:")
# # print(pem_public_key)
# print("\nBase64로 인코딩된 공개 키:")
# print(b64_public_key)

b64_private_key = "MIIEowIBAAKCAQEAu1L39WJ4bmQ09vwViDrg+/PwGpJO/WzZQcW52R4APvT7JNcfb8ht3s/OFq3GkipawI3N7BxuWrLmmWz8ueWKMSNXhhfJ1qW8Y609wNdgib/YY/nJLg0JwWoWE992sWYYy3fxGX7iBut7Kd6CzOqLeYrAUFA/f+Tg+NiJoJqVcQNfc2bAxmT/W6ktGR8rZcpADLOBpr94ZYZUqGpCY/LNikZU8tzeVHmXutAdGrq6ghiRJUIveVBrq+E8loMWXgZF6g7C4Xpzq5WHO4HDP9YoLgQnpyoiTWPQM+ZfF3ves9idBLQSl1URinxTVXiYQa7rn0KLkm6S+dwe2ByngOXPkQIDAQABAoIBAB4DGP8Tm7/0BhhcIwcEh+9WEe3v6v/nZJeJGlGS4O81SNeKL9s0/YVpPdecV+grKQcYsRlXJMcbSp7iO0t9XzqoMumk/g2J2DkQFIjE+Q6Y0g6Sgo0CQcHfQVJFxzp85RQUT2iKT6RULhNzNvmlylraxB0Z/lJ7VSAJcWNt4OuOHJXpieox+UWMAhUb+MV+Kd+9Zq70jBF8IAz8ftROxpFMt81/d4qd0Nll9jzDOazv2MWLS/Z+ZSgrh76DNmDZpPEEDj2KE58FVGJuTeS1A46aSy0r8l8cGui15kaV2hmqufmSq84ebySjoIwd8zQBU1j0OL2UMLR4XWnN4gee4NECgYEA4UpeWKF/5JNCA5qK9IoGBofyUh6Kid9M4/wpb3tTu2Ad3rxLBVB3gjsLANsJkRT4Alc3v6radmiZICyh1gJfxmF4Ssn/C/PaUlgKN/KqTV1hHBxTmEXkBtJkpUHAGjTnFcOaC5gI/3kOH6SMKlGNDfdqgmdvwld2CsjSSgQyhQsCgYEA1Nu+ABe7YJ8ehBEbbxgP6ykZlKfSv8LILXOtFGzTFB0Cf4V7+h96DSGXSHVLYpI/I36nm77+mPFYTVIcCVphzDhNJjr5FcVchoWVYOcXLFqvfBkMlBjlQnxOWwepnIXY9gi3l5sV6gImM06n+/uHmVVZaJmQjrEyP06yuD7AJ1MCgYBY0+m/KG40wZsVsKl5IbKegJuapVAabGD0w0fTHN020/7zA2rQ/ZkhUAZWoAZ1nb7rrVfdyo+4gCVf+jkVGHqKzYOQeXSGUe+S6AOfa56aQmc3njOXpnbx+aKVRgdoTdOPUUA7sgZaNHDNKSPay6zCBPuJzx7RkYqJVgUUCfOhYQKBgQCAq1RvOelKvuTzcGPlA+abgHy2H7yFrnjTANnfPulZfy/DZi1LRTvCNEv+wOiQ7Va9XhJzU0ETstBt7PSFstzrVh1MvtlTD7qelqF1sjuP1EHAAmRYIbR0PDAhVsBwnXhJQXu5aUYV7raozSM+bw3I4o7pa+q2VubI3gmq1kPRgQKBgA1S6TxBwC7xzAKt4Cyzo9ySez5RVrwP1p47k+7vSU7mfIqtJxDmUdWmd7H9PLrQsEIszH2RMawB5vsqqdTFZV3R+qlVPpCe4pUKGRxwU74HDdIuNMB21DWQ5KI0WThrX1jY9q/XnqZuL9703X4OAJN215KiqBR2G1RYMPH5T7ao"
aaa = base64.b64decode(b64_private_key)
# print(aaa)
b64_public_key = "MIIBCgKCAQEAu1L39WJ4bmQ09vwViDrg+/PwGpJO/WzZQcW52R4APvT7JNcfb8ht3s/OFq3GkipawI3N7BxuWrLmmWz8ueWKMSNXhhfJ1qW8Y609wNdgib/YY/nJLg0JwWoWE992sWYYy3fxGX7iBut7Kd6CzOqLeYrAUFA/f+Tg+NiJoJqVcQNfc2bAxmT/W6ktGR8rZcpADLOBpr94ZYZUqGpCY/LNikZU8tzeVHmXutAdGrq6ghiRJUIveVBrq+E8loMWXgZF6g7C4Xpzq5WHO4HDP9YoLgQnpyoiTWPQM+ZfF3ves9idBLQSl1URinxTVXiYQa7rn0KLkm6S+dwe2ByngOXPkQIDAQAB"

private_key = serialization.load_der_private_key(base64.b64decode(b64_private_key), password=None, backend=default_backend())

# b64_public_key to public_key
public_key = serialization.load_der_public_key(base64.b64decode(b64_public_key), backend=default_backend())
# public_key to b64_public_key
# b64_public_key = base64.b64encode(public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )).decode('utf-8')
# print(b64_public_key)

# 원본 데이터
data = b"AAA"
# data to base64
aaa = base64.b64encode(data).decode('utf-8')
bbb = base64.b64decode(aaa)
print("aaa: ", aaa)
print("bbb: ", bbb)

# 데이터 해시
digest = hashes.Hash(hashes.SHA256())
digest.update(data)
hash_value = digest.finalize()
print("hash_value: ", hash_value)

# 서명 생성
signature = private_key.sign(
    hash_value,
    padding.PKCS1v15(),
    hashes.SHA256()
)

print("signature: ", signature)
print("signature len", len(signature))

# 서명 검증
try:
    public_key.verify(
        signature,
        hash_value,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("서명 검증 성공")
except InvalidSignature as e:
    print(f"서명 검증 실패: 유효하지 않은 서명 - {e}")
    import traceback
    traceback.print_exc()
except Exception as e:
    print(f"서명 검증 실패: 다른 오류 - {e}")
    import traceback
    traceback.print_exc()
