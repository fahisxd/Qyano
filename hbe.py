import hashlib
import base64

def hbe_engine(text, op):
    text_data = text.encode("utf-8")
    try:
        if op == "hash":
            sha256 = hashlib.sha256(text_data).hexdigest()
            md5 = hashlib.md5(text_data).hexdigest()
            sha1 = hashlib.sha1(text_data).hexdigest()
            return {"sha256" : sha256, "md5" : md5, "sha1" : sha1}
        elif op == "enc" :
            base_enc = base64.b64encode(text_data).decode("ascii")
            return {"base64/encode" : base_enc}
        elif op == "dec":
            base_dec = base64.b64decode(text_data, validate=True).decode("utf-8")
            return {"base64/decode" : base_dec}
        else:
            return {"error" : "error/engines/hbe/invalid-operation"}
    except Exception as e:
        return {"error" : f"error/engines/hbe/{str(e)}"}
