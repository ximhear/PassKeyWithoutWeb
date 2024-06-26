from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import uuid
import os

app = Flask(__name__)

# 데이터베이스 대용
user_db = {}

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    public_key_base64 = data['public_key']
    print(public_key_base64)

    # 고유한 userID 생성
    user_id = str(uuid.uuid4())

    # 공개 키를 DER 형식으로 디코딩
    try:
        public_key_der = base64.b64decode(public_key_base64)
        public_key = serialization.load_der_public_key(public_key_der)
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Unable to load public key: {str(e)}"}), 400

    # 사용자 정보 저장
    user_db[user_id] = {
        "username": username,
        "public_key": public_key_base64  # 저장은 base64 형식으로 저장
    }

    return jsonify({"message": "User registered successfully", "userID": user_id}), 200


@app.route('/login-challenge', methods=['POST'])
def login_challenge():
    data = request.json
    username = data['username']
    userid = data['userid']

    print("user_db: ", user_db)
    print('userid: ', userid)
    user_info = user_db.get(userid)
    if not user_info:
        return jsonify({"error": "User not found"}), 404

    # 임의의 챌린지 생성
    challenge = base64.b64encode(os.urandom(32)).decode('utf-8')
    # data = b"AAA"
    # challenge = base64.b64encode(data).decode('utf-8')

    # 챌린지를 클라이언트로 전송
    print(f"Generated Challenge: {challenge}")
    return jsonify({"challenge": challenge}), 200


@app.route('/verify1', methods=['POST'])
def verify1():
    data = request.json
    username = data['username']
    signed_challenge = data['signed_challenge']
    challenge = data['challenge']
    userid = data['userid']

    user_info = user_db.get(userid)
    if not user_info:
        return jsonify({"error": "User not found"}), 404

    try:
        print("user info public_key: ", user_info['public_key'])
        public_key_der = base64.b64decode(user_info['public_key'])
        public_key = serialization.load_der_public_key(public_key_der)
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Unable to load public key: {str(e)}"}), 400

    # print("public_key: ", public_key_der)
    # print("public_key: ", public_key)
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print(pem_public_key.decode('utf-8'))
    # 디버깅을 위한 데이터 출력
    print(f"Received Challenge: {challenge}")
    print(f"Signed Challenge: {signed_challenge}")
    print(f"Public Key (DER): {user_info['public_key']}")
    print(f"Signed Challenge (decoded): {base64.b64decode(signed_challenge)}")

    # print(challenge)
    # print(challenge.encode('utf-8'))
    data = base64.b64decode(challenge)
    # print(data)

    # 서명 검증
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    digest = h.finalize()
    signature = base64.b64decode(signed_challenge)
    print("data: ", base64.b64encode(data).decode('utf-8'))
    print("digest: ", base64.b64encode(digest).decode('utf-8'))
    # print("signature: ", signature)
    # print("signature: ", len(signature))
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return jsonify({"message": "Login successful"}), 200
    except Exception as e:
        print(f"서명 검증 실패: {e}")
        print(f"Verification error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Invalid signature: {str(e)}"}), 400


@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    client_data_json = base64.b64decode(data['clientDataJSON'])
    authenticator_data = base64.b64decode(data['authenticatorData'])
    signature = base64.b64decode(data['signature'])
    user_id = base64.b64decode(data['userID']).decode('utf-8')

    user_info = user_db.get(user_id)
    if not user_info:
        return jsonify({"error": "User not found"}), 404

    try:
        public_key_der = base64.b64decode(user_info['public_key'])
        public_key = serialization.load_der_public_key(public_key_der)
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Unable to load public key: {str(e)}"}), 400

    # 서명 검증
    h = hashes.Hash(hashes.SHA256())
    h.update(client_data_json + authenticator_data)
    digest = h.finalize()
    try:
        public_key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return jsonify({"message": "Login successful"}), 200
    except Exception as e:
        return jsonify({"error": f"Invalid signature: {str(e)}"}), 400


if __name__ == '__main__':
    app.run(host='192.168.0.34', port=5000, debug=True)
