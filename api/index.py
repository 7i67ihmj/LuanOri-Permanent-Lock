from flask import Flask, request, Response, jsonify
import blackboxprotobuf as pb
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests, random, hashlib, json, os, time, threading
from datetime import datetime

# ============ PROTOBUF IMPORT ============
import ban_pb2
from Login_pb2 import getUID

app = Flask(__name__)

key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
decrypt = lambda x: unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(x), 16)
encrypt = lambda x: AES.new(key, AES.MODE_CBC, iv).encrypt(pad(x, 16))
sessions = {}
ssl = threading.Lock()

clearx = lambda headers: {k: v for k, v in headers.items() if k.lower() not in {"content-encoding", "content-length", "connection", "transfer-encoding", "host"}}

# ============ UID VALIDATION ============
# Vercel chỉ cho phép đọc/ghi trong /tmp
UID_FILE = "/tmp/uid.txt"
TOKEN_FILE = "/tmp/Tokenized.json"

def load_sessions_from_file():
    """Load sessions from JSON file"""
    global sessions
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                current_time = time.time()
                valid_sessions = {}
                
                for sid, data in loaded.items():
                    if data["expire"] > current_time:
                        valid_sessions[sid] = data
                    else:
                        print(f"[Load] Session {sid} expired, removing")
                
                sessions = valid_sessions
                print(f"[Load] Loaded {len(valid_sessions)} valid sessions from {TOKEN_FILE}")
                
                if len(valid_sessions) != len(loaded):
                    save_sessions_to_file()
        except Exception as e:
            print(f"[Load] Error loading sessions: {e}")
            sessions = {}
    else:
        sessions = {}

def save_sessions_to_file():
    """Save sessions to JSON file"""
    try:
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            json.dump(sessions, f, indent=2, ensure_ascii=False)
        print(f"[Save] Saved {len(sessions)} sessions to {TOKEN_FILE}")
    except Exception as e:
        print(f"[Save] Error saving sessions: {e}")

def fetchUIDsFromLocal() -> list:
    try:
        with open(UID_FILE, "r", encoding="utf-8") as file:
            uids = [line.strip() for line in file if line.strip().isdigit()]
        print(f"[UID] Loaded {len(uids)} UIDs from file")
        return uids
    except FileNotFoundError:
        # Vercel: tạo file mới nếu chưa có
        try:
            with open(UID_FILE, "w", encoding="utf-8") as f:
                f.write("")
        except:
            pass
        return []
    except Exception as e:
        print(f"[UID] Error: {e}")
        return []

def checkUIDExists(uid: str) -> bool:
    return uid.strip() in fetchUIDsFromLocal()

# ============ BAN RESPONSE ============
FAKE_LOGIN_RESPONSE_HEX = "6a0a0891a40118f697fcc4067a020801"
FAKE_LOGIN_RESPONSE_BYTES = bytes.fromhex(FAKE_LOGIN_RESPONSE_HEX)

# ============ ROUTES ============
@app.route("/start", methods=["GET"])
def start():
    access = request.args.get("token", str()).strip()
    if not access:
        return Response(b"Unauthorized", status=401)

    access_hash = hashlib.md5(access.encode()).hexdigest()
    sid = "".join(str(random.randint(0, 9)) for _ in range(10))
    
    # Thời gian hết hạn: 8 giờ
    exp = time.time() + 28800
    
    with ssl:
        sessions[sid] = {
            "hash": access_hash, 
            "expire": exp, 
            "token": access, 
            "banned_uid": None,
            "created_at": time.time()
        }
    
    save_sessions_to_file()
    
    exp_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp))
    
    return jsonify({
        "sid": sid,
        "hash": access_hash,
        "expire_timestamp": exp,
        "expire_time": exp_time_str,
        "expire_in": "8 hours",
        "message": f"Session will expire at {exp_time_str} (after 8 hours)",
        "server_url": f"{request.host_url}auth:{access_hash}:{sid}:"
    })

@app.route("/", defaults={"params": ""}, methods=["GET", "POST"])
@app.route("/<path:params>", methods=["GET", "POST"])
def proxy(params):
    try:
        # Parse URL format: /auth:hash:session:endpoint
        path = request.path
        if "auth:" not in path:
            return Response(b"Invalid path format", status=403)
        
        parts = path.split("auth:")[1].split(":", 2)
        if len(parts) < 3:
            return Response(b"Invalid auth format", status=403)
        
        token_hash, session, endpoint = parts
    except Exception as e:
        print(f"Parse error: {e}")
        return Response(b"Unauthorized!", status=403)

    with ssl:
        ss = sessions.get(session)
    
    if ss is None:
        return Response(b"Session not found", status=401)
    
    if time.time() > ss["expire"]:
        with ssl:
            sessions.pop(session, None)
            save_sessions_to_file()
        return Response(b"Session expired", status=401)
    
    # Verify token hash matches
    expected_hash = hashlib.md5(ss["token"].encode()).hexdigest()
    if token_hash != expected_hash:
        return Response(b"Invalid token hash", status=401)

    data = request.get_data()
    headers = clearx(dict(request.headers))
    headers["Host"] = "loginbp.ggpolarbear.com"

    try:
        if endpoint == "MajorLogin":
            inspect = requests.get(
                f"https://auth.garena.com/oauth/token/inspect?token={ss['token']}",
                timeout=10
            ).json()
            
            if "open_id" not in inspect:
                return Response(
                    FAKE_LOGIN_RESPONSE_BYTES,
                    status=200,
                    headers={"Content-Type": "application/x-protobuf"}
                )

            try:
                fields, typedef = pb.decode_message(decrypt(data))
                fields["22"] = str(inspect.get("open_id"))
                fields["23"] = str(inspect.get("main_active_platform"))
                fields["29"] = str(ss["token"])
                fields["99"] = str(inspect.get("platform"))
                fields["100"] = str(inspect.get("login_platform"))
                payload = encrypt(pb.encode_message(fields, typedef))
                
                response = requests.request(
                    method=request.method,
                    url=f"https://loginbp.ggpolarbear.com/{endpoint}",
                    data=payload,
                    headers=headers,
                    timeout=15
                )
                
                try:
                    decodedBody = getUID()
                    decodedBody.ParseFromString(response.content)
                    uid_str = str(decodedBody.uid)
                    
                    print(f"[Login] UID found: {uid_str}")
                    
                    if not checkUIDExists(uid_str):
                        print(f"[Login] UID {uid_str} NOT in whitelist")
                        with ssl:
                            sessions[session]["banned_uid"] = uid_str
                            # Lưu thông tin user
                            sessions[session]["user_uid"] = uid_str
                            sessions[session]["user_name"] = "Unknown"
                            sessions[session]["user_region"] = "VN"
                            save_sessions_to_file()
                        return Response(
                            FAKE_LOGIN_RESPONSE_BYTES,
                            status=200,
                            headers={"Content-Type": "application/x-protobuf"}
                        )
                    else:
                        print(f"[Login] UID {uid_str} is valid")
                        with ssl:
                            sessions[session]["banned_uid"] = None
                            sessions[session]["user_uid"] = uid_str
                            save_sessions_to_file()
                        
                except Exception as decode_error:
                    print(f"[Login] Could not decode UID: {decode_error}")
                
                return Response(
                    response.content,
                    status=response.status_code,
                    headers=clearx(dict(response.headers))
                )
                
            except Exception as error:
                print(f"[MajorLogin Error] {error}")
                return Response(
                    FAKE_LOGIN_RESPONSE_BYTES,
                    status=200,
                    headers={"Content-Type": "application/x-protobuf"}
                )

        elif "GetAccountBriefInfoBeforeLogin" in endpoint:
            with ssl:
                banned_uid = sessions.get(session, {}).get("banned_uid")
                user_uid = sessions.get(session, {}).get("user_uid", "0")
            
            if banned_uid and banned_uid != "0":
                print(f"[AccountBrief] Creating ban response for UID: {banned_uid}")
                
                ban_resp = ban_pb2.THUG4FF()
                ban_resp.account_id = int(banned_uid)
                ban_resp.region = "VN"
                ban_resp.nickname = f"[c][ff0000]BANNED[/c] Reason: UID not registered"
                
                return Response(
                    ban_resp.SerializeToString(),
                    status=200,
                    headers={"Content-Type": "application/x-protobuf"}
                )
            
            # Forward request
            response = requests.request(
                method=request.method,
                url=f"https://loginbp.ggpolarbear.com/{endpoint}",
                data=data,
                headers=headers,
                timeout=15
            )
            
            return Response(
                response.content,
                status=response.status_code,
                headers=clearx(dict(response.headers))
            )

        else:
            response = requests.request(
                method=request.method,
                url=f"https://loginbp.ggpolarbear.com/{endpoint}",
                data=data,
                headers=headers,
                timeout=15
            )
            
            return Response(
                response.content,
                status=response.status_code,
                headers=clearx(dict(response.headers))
            )

    except requests.exceptions.Timeout:
        return Response(b"Timeout", status=504)
    except requests.exceptions.RequestException as e:
        print(f"[Request Exception] {e}")
        return Response(str(e).encode(), status=500)


# ============ UTILITY ENDPOINTS ============
@app.route("/uid/list", methods=["GET"])
def list_uids():
    uids = fetchUIDsFromLocal()
    return jsonify({"uids": uids, "count": len(uids)})

@app.route("/uid/add", methods=["POST"])
def add_uid():
    data = request.get_json()
    uid = str(data.get("uid", "")).strip()
    if not uid.isdigit():
        return jsonify({"error": "Invalid UID"}), 400
    
    uids = fetchUIDsFromLocal()
    if uid not in uids:
        with open(UID_FILE, "a", encoding="utf-8") as f:
            f.write(uid + "\n")
        return jsonify({"status": "added", "uid": uid})
    return jsonify({"status": "already exists", "uid": uid})

@app.route("/uid/remove", methods=["POST"])
def remove_uid():
    data = request.get_json()
    uid = str(data.get("uid", "")).strip()
    
    uids = fetchUIDsFromLocal()
    if uid in uids:
        uids.remove(uid)
        with open(UID_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(uids) + ("\n" if uids else ""))
        return jsonify({"status": "removed", "uid": uid})
    return jsonify({"status": "not found", "uid": uid})

@app.route("/sessions", methods=["GET"])
def list_sessions():
    """Xem danh sách sessions đang hoạt động"""
    with ssl:
        sessions_list = []
        current_time = time.time()
        for sid, data in sessions.items():
            time_left = data["expire"] - current_time
            hours_left = int(time_left // 3600)
            minutes_left = int((time_left % 3600) // 60)
            
            sessions_list.append({
                "sid": sid,
                "expire_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data["expire"])),
                "time_left": f"{hours_left}h {minutes_left}m",
                "banned_uid": data.get("banned_uid"),
                "user_uid": data.get("user_uid"),
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data.get("created_at", 0)))
            })
    return jsonify({"sessions": sessions_list, "count": len(sessions_list)})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "sessions": len(sessions), "uids": len(fetchUIDsFromLocal())})


# ============ MAIN ============
if __name__ == "__main__":
    # Tạo file UID_FILE nếu chưa tồn tại
    try:
        if not os.path.exists(UID_FILE):
            with open(UID_FILE, "w") as f:
                f.write("")
    except:
        pass
    
    load_sessions_from_file()
    
    port = int(os.environ.get("PORT", 2026))
    
    print("=" * 50)
    print("Proxy Server with UID Ban")
    print(f"UID File: {UID_FILE}")
    print(f"Token File: {TOKEN_FILE}")
    print(f"Loaded {len(fetchUIDsFromLocal())} UIDs")
    print(f"Loaded {len(sessions)} active sessions")
    print("Session timeout: 8 hours")
    print(f"Listening on 0.0.0.0:{port}")
    print("=" * 50)
    
    app.run(host="0.0.0.0", port=port, threaded=True)