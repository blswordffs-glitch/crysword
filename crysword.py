from __future__ import annotations
from collections.abc import Sequence
from Crypto.Util.number import *
from gmpy2 import *
import importlib
algorithm = {}
def check(name):
    if name not in algorithm:
        algorithm[name] = {"module": None}
    dependency = algorithm[name]
    if dependency["module"] is None:
        if name == "sage":
            pathlib = importlib.import_module("pathlib")
            sageworker = importlib.import_module("sageworker")
            globals()["sage"] = sageworker.sage
            globals()["SAGE_CONFIG"] = (pathlib.Path(__file__).with_name("sageworker_config.json"))
            dependency["module"] = sageworker
        else:
            dependency["module"] = (importlib.import_module(name))
            globals()[name.rsplit(".", 1)[-1]] = dependency["module"]
def search(input_file, output_file, keyword):
    check("re")
    check("pathlib")
    pattern = re.compile(r"(?<![\w.])[+-]?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+)(?![\w.])")
    count = 0
    with open(input_file, "r", encoding="utf-8") as source, \
         pathlib.Path(output_file).open("x", encoding="utf-8") as target:
        for line in source:
            if keyword not in line:
                continue
            content = line.split(keyword, 1)[1]
            for match in pattern.finditer(content):
                token = match.group()
                unsigned = token.lstrip("+-").lower()
                base = 16 if unsigned.startswith("0x") else (2 if unsigned.startswith("0b") else 10)
                target.write(f"{int(token, base)}\n")
                count += 1
    return count
def read_numbers(file_path):
    numbers = []
    with open(file_path, "r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            token = line.strip()
            if not token:
                continue
            unsigned = token.lstrip("+-").lower()
            base = 16 if unsigned.startswith("0x") else (
                2 if unsigned.startswith("0b") else 10
            )
            try:
                numbers.append(int(token, base))
            except ValueError as exc:
                raise ValueError(f"第 {line_number} 行不是整数: {token}") from exc
    return numbers
def _read_integer_rows(file_path):
    check("re")
    rows = []
    with open(file_path, "r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            content = line.strip().strip("[]()")
            if not content:
                continue
            rows.append(_parse_integer_row(content, line_number, line))
    return rows
def _parse_integer_row(content, line_number, original_line):
    check("re")
    pattern = re.compile(
        r"[+-]?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+)"
    )
    tokens = content.replace(",", " ").split()
    if not tokens or any(pattern.fullmatch(token) is None for token in tokens):
        raise ValueError(
            f"第 {line_number} 行包含非整数内容: {original_line.strip()}"
        )
    row = []
    for token in tokens:
        unsigned = token.lstrip("+-").lower()
        base = (
            16 if unsigned.startswith("0x")
            else 2 if unsigned.startswith("0b")
            else 10
        )
        row.append(int(token, base))
    return row
def read_matrix(file_path):
    rows = _read_integer_rows(file_path)
    if not rows:
        return []
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        raise ValueError("矩阵每一行的列数必须相同")
    return rows
def _flatten_vector(value, name="vector"):
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{name} 必须是列表或矩阵行列表")
    if not value:
        return []
    nested = [item for item in value if isinstance(item, (list, tuple))]
    if nested and len(nested) != len(value):
        raise TypeError(f"{name} 不能混合一维元素和矩阵行")
    if nested:
        value = [item for row in value for item in row]
    return [int(item) for item in value]
def xor(a,b):
    a=a.encode()
    b=b.encode()
    if len(a)!=len(b):
        raise ValueError("逐字节XOR必须长度相同")
    return bytes([x^y for x,y in zip(a,b)])
def enc_md5_hexdigest(text):
    check("hashlib")
    return hashlib.md5(text.encode()).hexdigest()
def enc_sha1_hexdigest(text):
    check("hashlib")
    return hashlib.sha1(text.encode()).hexdigest()
def enc_sha256_hexdigest(text):
    check("hashlib")
    return hashlib.sha256(text.encode()).hexdigest()
def enc_sha512_hexdigest(text):
    check("hashlib")
    return hashlib.sha512(text.encode()).hexdigest()
def enc_md5_digest(text):
    check("hashlib")
    return hashlib.md5(text.encode()).digest()
def enc_sha1_digest(text):
    check("hashlib")
    return hashlib.sha1(text.encode()).digest()
def enc_sha256_digest(text):
    check("hashlib")
    return hashlib.sha256(text.encode()).digest()
def enc_sha512_digest(text):
    check("hashlib")
    return hashlib.sha512(text.encode()).digest()
def enc_base64(text):
    check("base64")
    return base64.b64encode(text.encode()).decode()
def dec_base64(text):
    check("base64")
    return base64.b64decode(text.encode()).decode()
def hex_enc(text):
    if isinstance(text,str):
        text=text.encode()
    return bytes(text).hex()
def hex_dec(text):
    return bytes.fromhex(text).decode()
def dec_Chacha20_ploy1305(ciphertext,tag,nonce,key):
    check("Crypto.Cipher.ChaCha20_Poly1305")
    if isinstance(key,str):
        key=key.encode()
    if isinstance(nonce,str):
        nonce=nonce.encode()
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    flag = cipher.decrypt_and_verify(ciphertext, tag)
    return flag
def enc_AES_ECB(plaintext, key):
    check("Crypto.Cipher.AES")
    check("Crypto.Util.Padding")
    aes = AES.new(key.encode(),AES.MODE_ECB)
    plaintext = Padding.pad(plaintext.encode(),AES.block_size,)
    return aes.encrypt(plaintext)
def dec_AES_ECB(ciphertext,key):
    check("Crypto.Cipher.AES")
    check("Crypto.Cipher.Padding")
    if isinstance(ciphertext,str):
        ciphertext=ciphertext.encode()
    else:
        ciphertext=bytes(ciphertext)
    aes=AES.new(key.encode(),AES.MODE_ECB)
    block_size=AES.block_size
    return Padding.unpad(aes.decrypt(ciphertext.encode()),block_size).decode()
def enc_AES_CBC(plaintext, key, IV):
    check("Crypto.Cipher.AES")
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    if isinstance(key, str):
        key = key.encode()
    if isinstance(IV, str):
        IV = IV.encode()
    aes = AES.new(key,AES.MODE_CBC,IV)
    return aes.encrypt(plaintext)
def dec_AES_CBC(ciphertext, key, IV):
    check("Crypto.Cipher.AES")
    if isinstance(key, str):
        key = key.encode()
    if isinstance(IV, str):
        IV = IV.encode()
    aes = AES.new(key,AES.MODE_CBC,IV)
    return aes.decrypt(ciphertext)
def enc_AES_CTR(plaintext, key, nonce):
    check("Crypto.Cipher.AES")
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    if isinstance(key, str):
        key = key.encode()
    if isinstance(nonce, str):
        nonce =nonce.encode()
    aes = AES.new(key,AES.MODE_CTR,nonce)
    return aes.encrypt(plaintext)
def dec_AES_CTR(ciphertext, key, nonce):
    check("Crypto.Cipher.AES")
    if isinstance(key, str):
        key = key.encode()
    if isinstance(nonce, str):
        nonce = nonce.encode()
    aes = AES.new(key,AES.MODE_CTR,nonce)
    return aes.decrypt(ciphertext)
def enc_gb2312(text):
    return text.encode("gb2312")
def dec_TOTP(secret):
    check("hmac")
    check("hashlib")
    check("time")
    check("base64")
    check("struct")
    secret = "".join(str(secret).split()).upper()
    secret += "=" * (-len(secret) % 8)
    key = base64.b32decode(secret,casefold=True)
    timestamp = int(time.time()) // 30
    message = struct.pack(">Q",timestamp)
    digest = hmac.new(key,message,hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I",digest[offset:offset + 4],)[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)
def number_base_conversion(number, original_base, target_base):
    original_base = int(original_base)
    target_base = int(target_base)
    number = int(str(number), original_base)
    if number == 0:
        return "0"
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = ""
    value = abs(number)
    while value:
        result = digits[value % target_base] + result
        value //= target_base
    if number < 0:
        result = "-" + result
    return result
def Z_iroot(number,count):
    root,exact=gmpy2.iroot(number,count)
    return root,exact
def D_iroot(number,count,precision):
    check("decimal")
    with decimal.localcontext() as context:
        context.prec = precision
        number=decimal.Decimal(str(number))
        count=decimal.Decimal(count)
        return number**(decimal.Decimal(1)/count)
def dec_caeser(text,shift):
    decrypt=""
    for char in text:
        if char.isalpha():
            base=ord('A') if char.isupper() else ord('a')
            decrypt+=chr((ord(char)-base-shift)%26+base)
        else:
            decrypt+=char
    return decrypt
def dec_caeser_bruteforce(text):
    for shift in range(26):
        print(shift,dec_caeser(text,shift))
def enc_caeser(text,shift):
    encrypt=""
    for char in text:
        if char.isalpha():
            base=ord('A') if char.isupper() else ord('a')
            encrypt+=chr((ord(char)-base+shift)%26+base)
        else:
            encrypt+=char
    return encrypt
def dec_vigenere(text,shift):
    plaintext=""
    key=str(shift).lower()
    if not key or not key.isalpha():
        raise ValueError("Vigenere 密钥必须是非空字母串")
    key_index=0
    for char in text:
      if char.isalpha():
        base=ord('A') if char.isupper() else ord('a')
        key_shift=ord(key[key_index%len(key)])-ord('a')
        plaintext+=chr((ord(char)-base-key_shift)%26+base)
        key_index+=1
      else:
        plaintext+=char
    return plaintext
def dec_emoji_aes(ciphertext, password, rotation=0):
    check("Crypto.Cipher.AES")
    check("Crypto.Util.Padding")
    check("Crypto.Protocol.KDF")
    import base64
    emoji_table = (
        "🍎", "🍌", "🏎", "🚪", "👁", "👣", "😀", "🖐", "ℹ", "😂",
        "🥋", "✉", "🚹", "🌉", "👌", "🍍", "👑", "👉", "🎤", "🚰",
        "☂", "🐍", "💧", "✖", "☀", "🦓", "🏹", "🎈", "😎", "🎅",
        "🐘", "🌿", "🌏", "🌪", "☃", "🍵", "🍴", "🚨", "📮", "🕹",
        "📂", "🛩", "⌨", "🔄", "🔬", "🐅", "🙃", "🐎", "🌊", "🚫",
        "❓", "⏩", "😁", "😆", "💵", "🤣", "☺", "😊", "😇", "😡",
        "🎃", "😍", "✅", "🔪", "🗒",
    )
    alphabet = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789+/="
    )
    rotation = int(rotation)
    if not 0 <= rotation <= 64:
        raise ValueError("rotation 必须在 0 到 64 之间")
    emoji_table = emoji_table[rotation:] + emoji_table[:rotation]
    emoji_to_base64 = dict(zip(emoji_table, alphabet))
    encoded = "".join(
        emoji_to_base64[char]
        for char in ciphertext
        if not char.isspace()
    )
    openssl_data = base64.b64decode(encoded)
    if openssl_data[:8] != b"Salted__":
        raise ValueError("密文缺少 OpenSSL Salted 前缀")
    salt = openssl_data[8:16]
    encrypted = openssl_data[16:]
    key_iv = KDF.EVP_BytesToKey( password.encode("utf-8"), salt, 48, 1, digest="md5" )
    aes = AES.new( key_iv[:32], AES.MODE_CBC, key_iv[32:48] )
    plaintext = Padding.unpad( aes.decrypt(encrypted), AES.block_size)
    return base64.b64encode(plaintext).decode("ascii")
def dec_fence(ciphertext, rails):
    length = len(ciphertext)
    fence = [["\n"] * length for _ in range(rails)]
    row = col = 0
    direction = 1
    for _ in range(length):
        fence[row][col] = "*"
        col += 1
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction
    index = 0
    for i in range(rails):
        for j in range(length):
            if fence[i][j] == "*":
                fence[i][j] = ciphertext[index]
                index += 1
    result = []
    row = col = 0
    direction = 1
    for _ in range(length):
        result.append(fence[row][col])
        col += 1
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction
    return "".join(result)
def rsa_dp_dq(dp,dq,p,q,c):
    m1=gmpy2.powmod(int(c),int(dp),p)
    m2=gmpy2.powmod(int(c),int(dq),q)
    t=((m2-m1)*gmpy2.invert(int(p),int(q)))%q
    n=p*q
    m=(m1-t*p)%n
    m=long_to_bytes(m)
    return m
def rsa_dp(e,n,c,dp):
    e=int(e)
    n=int(n)
    c=int(c)
    dp=int(dp)
    p=None
    q=None
    for i in range(2,e):
        if (e*dp-1)%i==0:
            p=(e*dp-1)//i+1
            if n%p==0:
                q=n//p
                break
    if p is None or q is None:
        raise ValueError("未找到与 dp 匹配的因子")
    phi=(p-1)*(q-1)
    d=gmpy2.invert(e,phi)
    m=long_to_bytes(gmpy2.powmod(c,d,n))
    return m
def rsa_common_modular(n,e1,e2,c1,c2):
    n=int(n)
    e1=int(e1)
    e2=int(e2)
    c1=int(c1)
    c2=int(c2)
    g,s1,s2=gmpy2.gcdext(e1,e2)
    a=gmpy2.powmod(c1,s1,n)
    b=gmpy2.powmod(c2,s2,n)
    return long_to_bytes((a*b)%n)
def rsa_low_public_exponent_broadcast(e):
    check("sympy.ntheory.modular")
    e=int(e)
    mod=[]
    ciphertext=[]
    for i in range(e):
      mod.append(int(input("输入n:")))
    for j in range(e):
      ciphertext.append(int(input("输入c:")))
    me,modulus=modular.crt(mod,ciphertext)
    m,ist=gmpy2.iroot(int(me),int(e))
    if ist:
      return long_to_bytes(int(m))
    raise ValueError("广播攻击未得到整数 e 次方根")
def rsa_anm(n, e, c):
    check("sympy.ntheory.modular")
    n = int(n)
    e = int(e)
    c = int(c)
    factors = list(gmpy2.factorint(n).items())
    if len(factors) != 2:
        raise ValueError("n 必须恰好分解为两个素因子")
    p = int(factors[0][0])
    q = int(factors[1][0])
    gp = int(gmpy2.gcd(e, p - 1))
    gq = int(gmpy2.gcd(e, q - 1))
    ep = e // gp
    eq = e // gq
    hp = (p - 1) // gp
    hq = (q - 1) // gq
    dp = int(gmpy2.invert(ep, hp))
    dq = int(gmpy2.invert(eq, hq))
    up = int(gmpy2.powmod(c, dp, p))
    uq = int(gmpy2.powmod(c, dq, q))
    res1 = range(gp)
    res2 = range(gq)
    for i in res1:
        for j in res2:
            mp = (up + i * p) % (p * gp)
            mq = (uq + j * q) % (q * gq)
            m, exact = modular.crt(
                [p * gp, q * gq],
                [mp, mq],
            )
            if exact:
                try:
                    return long_to_bytes(int(m))
                except Exception:
                    continue
    raise ValueError("未找到有效明文")
def rsa_wiener(e, n, c):
    check("math")
    e = int(e)
    n = int(n)
    c = int(c)
    def continued_fraction(a, b):
        while b:
            yield a // b
            a, b = b, a % b
    def convergents(a, b):
        p_prev, p = 0, 1
        q_prev, q = 1, 0
        for term in continued_fraction(a, b):
            p_next = term * p + p_prev
            q_next = term * q + q_prev
            yield p_next, q_next
            p_prev, p = p, p_next
            q_prev, q = q, q_next
    for k, d in convergents(e, n):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue
        root = math.isqrt(discriminant)
        if root * root != discriminant:
            continue
        p = (s + root) // 2
        q = (s - root) // 2
        if p * q != n:
            continue
        plaintext = gmpy2.powmod(c, d, n)
        return long_to_bytes( int(plaintext) )
    raise ValueError("Wiener attack 未找到有效私钥")
def rsa_format(n,e,c):
    n=int(n)
    e=int(e)
    c=int(c)
    a,res1=gmpy2.iroot(n,2)
    if not res1:
      a+=1
    while True:
      b,res2=gmpy2.iroot(a**2-n,2)
      if res2:
        p=a+b
        q=a-b
        break
    a+=1
    phi=(p-1)*(q-1)
    d=gmpy2.invert(e,phi)
    m=long_to_bytes(gmpy2.powmod(c,d,n))
    return m
def rsa_common_prime(n,e,c):
    def common_prime_rho(n,seed=2,add=3,max_step=20000):
        f=lambda x:(gmpy2.powmod(x,2,n)+add)%n
        x=seed
        y=seed
        for _ in range(max_step):
            x=f(x)
            y=f(f(y))
            d=gmpy2.gcd(abs(x-y),n)
            if 1<d<n:
                return d
            if d==n:
                return None
        return None
    def factor_common_prime_rsa(n):
        seeds = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
        adds = [2, 3, 5, 7, 11, 13, 17, 19]
        for seed in seeds:
            for add in adds:
                p = common_prime_rho(n, seed=seed, add=add)
                if p is not None and n % p == 0:
                    q = n // p
                    return int(p),int(q)
        return None
    factors=factor_common_prime_rsa(int(n))
    if factors is None:
        raise ValueError("Pollard rho 未找到公共素因子")
    p,q=factors
    phi=(p-1)*(q-1)
    d=gmpy2.invert(int(e),phi)
    return long_to_bytes(int(gmpy2.powmod(int(c),d,int(n))))
def rsa_branch_pruning(n, c, e, leak, bits, length):
    n = int(n)
    e = int(e)
    c = int(c)
    leak = int(leak)
    bits = int(bits)
    length = int(length)
    def dfs(p, index):
        if index == 0:
            q_high = p ^ leak
            q_start = q_high << bits
            for low in range(1 << bits):
                q = q_start | low
                if p * q == n:
                    return p, q
            return None
        for i in range(2):
            candidate_p = (p << 1) | i
            remaining = index - 1
            p_min = candidate_p << remaining
            p_max = p_min | ((1 << remaining) - 1)
            q_high = candidate_p ^ leak
            q_min = q_high << bits
            q_max = q_min | ((1 << bits) - 1)
            if p_min * q_min <= n <= p_max * q_max:
                result = dfs(candidate_p, remaining)
                if result is not None:
                    return result
        return None
    factors = dfs(1, length - 1)
    if factors is None:
        raise ValueError("未找到满足泄露关系的因子")
    p, q = factors
    phi = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi)
    return long_to_bytes(int(gmpy2.powmod(c, d, n)))
def rsa_p_high(n,e,c,p_high,total_bits=512):
    check("sage")
    source = r"""
from sage.all import *
n = ZZ(request["n"])
e = ZZ(request["e"])
c = ZZ(request["c"])
p_high = ZZ(request["p_high"])
total_bits = ZZ(request["total_bits"])
unknown_bits = total_bits - p_high.nbits()
p_high = p_high << unknown_bits
R = PolynomialRing(Zmod(n),"x",implementation="NTL")
x = R.gen()
f = p_high + x
res = f.small_roots(X=ZZ(1) << unknown_bits,beta=0.4,epsilon=0.02)
if not res:
    raise ValueError("没有找到 p 的未知低位")
p = ZZ(gcd(p_high + res[0], n))
if p == 1 or p == n:
    raise ValueError("恢复结果不是 n 的有效因子")
q = n // p
phi = (p - 1) * (q - 1)
d = inverse_mod(e, phi)
m = power_mod(c, d, n)
result = int(m)
"""
    result = sage(
        source,
        {"n": int(n),"e": int(e),"c": int(c),"p_high": int(p_high),"total_bits": int(total_bits)},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False
    )
    return long_to_bytes(result)
def rsa_m_high(n,e,c,m_high,total_bits):
    check("sage")
    source = r"""
from sage.all import *
n = ZZ(request["n"])
e = ZZ(request["e"])
c = ZZ(request["c"])
m_high = ZZ(request["m_high"])
total_bits = ZZ(request["total_bits"])
unknown_bits = total_bits - m_high.nbits()
m_high = m_high << unknown_bits
R = PolynomialRing(Zmod(n),"x",implementation="NTL",)
x = R.gen()
f = (m_high + x) ** e - c
res = f.small_roots(X=ZZ(1) << unknown_bits,beta=1,epsilon=0.02)
if not res:
    raise ValueError("没有找到 m 的未知低位")
m = ZZ(m_high + res[0])
if power_mod(m, e, n) != c % n:
    raise ValueError("恢复出的 m 无法通过验证")
result = int(m)
"""
    result = sage(
        source,
        {"n": int(n),"e": int(e),"c": int(c),"m_high": int(m_high),"total_bits": int(total_bits)},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False
    )
    return long_to_bytes(result)
def rsa_d_high_leak(n,e,c,d_high,total_bits,max_unknown_bits=24):
    check("sage")
    source = r"""
from sage.all import *
n = ZZ(request["n"])
e = ZZ(request["e"])
c = ZZ(request["c"])
d_high = ZZ(request["d_high"])
total_bits = ZZ(request["total_bits"])
max_unknown_bits = ZZ(request["max_unknown_bits"])
unknown_bits = total_bits - d_high.nbits()
if unknown_bits > max_unknown_bits:
    raise ValueError(
        "d 未知低位过多，无法直接枚举"
    )
d_start = d_high << unknown_bits
bound = 1 << int(unknown_bits)
m = power_mod(c, d_start, n)
found = None
for d_low in range(bound):
    if power_mod(m, e, n) == c % n:
        found = int(m)
        break
    m = m * c % n
if found is None:
    raise ValueError("没有找到有效的 d")
result = found
"""
    result = sage(
        source,
        {"n": int(n),"e": int(e),"c": int(c),"d_high": int(d_high),"total_bits": int(total_bits),"max_unknown_bits": int(max_unknown_bits)},
        config_path=SAGE_CONFIG,timeout=300,show_status=False)
    return long_to_bytes(result)
def dsa_k(s,k,e,r,q):
    s=int(s)
    k = int(k)
    e = int(e)
    r = int(r)
    q = int(q)
    x=((s*k-e)*gmpy2.invert(r,q)%q)
    return x
def dsa_double_k(s1,s2,r1,r2,message1,message2,p,q,g,y):
    check("hashlib")
    s1=int(s1)
    s2=int(s2)
    r1=int(r1)
    r2=int(r2)
    q=int(q)
    p=int(p)
    g=int(g)
    y=int(y)
    message1=message1.encode()
    message2=message2.encode()
    e1 = int.from_bytes(hashlib.sha256(message1).digest(), "big") % q
    e2 = int.from_bytes(hashlib.sha256(message2).digest(), "big") % q
    k = (e1 - e2) * gmpy2.invert(s1 - s2, q) % q
    x = ((s1 * k - e1) * gmpy2.invert(r1, q)) % q
    return x
def dsa_k_linear(s1,s2,r1,r2,a,b,message1,message2,p,q,g,y):
    check("hashlib")
    s1=int(s1)
    s2=int(s2)
    r1=int(r1)
    r2=int(r2)
    a=int(a)
    b=int(b)
    p=int(p)
    q=int(q)
    g=int(g)
    y=int(y)
    message1=message1.encode()
    message2=message2.encode()
    e1 = int.from_bytes(hashlib.sha256(message1).digest(), "big") % q
    e2 = int.from_bytes(hashlib.sha256(message2).digest(), "big") % q
    num = r2 * e1 - r1 * e2 + b * r1 * s2
    den = r2 * s1 - a * r1 * s2
    k1 = num * pow(den, -1, q) % q
    x = (s1 * k1 - e1) * pow(r1, -1, q) % q
    return x
def dsa_k_square(s1,s2,r1,r2,message1,message2,p,q,g,y):
    check("hashlib")
    s1=int(s1)
    s2=int(s2)
    r1=int(r1)
    r2=int(r2)
    p=int(p)
    q=int(q)
    g=int(g)
    y=int(y)
    message1=message1.encode()
    message2=message2.encode()
    def tonelli_shanks(n, p):
        if pow(n, (p - 1) // 2, p) != 1:
            return None
        if p % 4 == 3:
            return pow(n, (p + 1) // 4, p)
        q = p - 1
        s = 0
        while q % 2 == 0:
            q //= 2
            s += 1
        z = 2
        while pow(z, (p - 1) // 2, p) != p - 1:
            z += 1
        m = s
        c = pow(z, q, p)
        t = pow(n, q, p)
        r = pow(n, (q + 1) // 2, p)
        while t != 1:
            i = 1
            temp = t * t % p
            while temp != 1:
                temp = temp * temp % p
                i += 1
            b = pow(c, 1 << (m - i - 1), p)
            r = r * b % p
            t = t * b * b % p
            c = b * b % p
            m = i
        return r
    e1 = int.from_bytes(hashlib.sha256(message1).digest(), "big") % q
    e2 = int.from_bytes(hashlib.sha256(message2).digest(), "big") % q
    a=s2*r1
    b=-s1*r2
    c=(e1*r2)- (e2*r1)
    phi = (b ** 2 - 4 * a * c) % q
    root = tonelli_shanks(phi, q)
    if root is None or 2*a%q==0 or r1%q==0:
        return None
    inv = gmpy2.invert(2 * a, q)
    k1 = ((-b + root) * inv) % q
    k2 = ((-b - root) * inv) % q
    ks = [k1, k2]
    for k in ks:
        x = ((s1 * k - e1) * gmpy2.invert(r1, q)) % q
        if pow(g, int(x), p) == y:
            return x,k
    return None
def Elgamal_k(s,k,e,r,p,q,y,g):
    s=int(s)
    k=int(k)
    e=int(e)
    r=int(r)
    p=int(p)
    q=int(q)
    y=int(y)
    g=int(g)
    if r%q==0:
        return None
    x=(e-s*k)*pow(r,-1,q)%q
    if pow(g,k,p)!=r%p:
        return None
    if pow(g,x,p)!=y:
        return None
    return x
def Elgamal_double_k(s1,s2,r1,r2,message1,message2,p,q,y,g):
    check("hashlib")
    s1=int(s1)
    s2=int(s2)
    r1=int(r1)
    r2=int(r2)
    p=int(p)
    q=int(q)
    y=int(y)
    g=int(g)
    message1=message1.encode()
    message2=message2.encode()
    if r1%p!=r2%p:
        return None
    e1=int.from_bytes(hashlib.sha256(message1).digest(),"big")%q
    e2=int.from_bytes(hashlib.sha256(message2).digest(),"big")%q
    den=(s1-s2)%q
    if den==0 or r1%q==0:
        return None
    k=(e1-e2)*pow(den,-1,q)%q
    x=(e1-s1*k)*pow(r1,-1,q)%q
    if pow(g,k,p)!=r1%p:
        return None
    if pow(g,x,p)!=y:
        return None
    return x
def Elgamal_k_square(s1,s2,r1,r2,message1,message2,p,q,y,g):
    check("hashlib")
    check("sympy.ntheory.residue_ntheory")
    s1=int(s1)
    s2=int(s2)
    r1=int(r1)
    r2=int(r2)
    p=int(p)
    q=int(q)
    y=int(y)
    g=int(g)
    message1=message1.encode()
    message2=message2.encode()
    e1=int.from_bytes(hashlib.sha256(message1).digest(),"big")%q
    e2=int.from_bytes(hashlib.sha256(message2).digest(),"big")%q
    a=r1*s2%q
    b=-r2*s1%q
    c=(r2*e1-r1*e2)%q
    phi=(b*b-4*a*c)%q
    roots=residue_ntheory.sqrt_mod(phi,q,all_roots=True)
    if not roots or 2*a%q==0 or r1%q==0:
        return None
    inv=pow(2*a,-1,q)
    for root in roots:
        k=(-b+int(root))*inv%q
        k2=k*k%q
        x=(e1-s1*k)*pow(r1,-1,q)%q
        if pow(g,k,p)!=r1%p:
            continue
        if pow(g,k2,p)!=r2%p:
            continue
        if pow(g,x,p)==y:
            return x,k
    return None
def Elgamal_k_linear(s1,s2,s3,r1,r2,r3,message1,message2,message3,p,q,y,g):
    check("hashlib")
    s1=int(s1)
    s2=int(s2)
    s3=int(s3)
    r1=int(r1)
    r2=int(r2)
    r3=int(r3)
    p=int(p)
    q=int(q)
    y=int(y)
    g=int(g)
    message1=message1.encode()
    message2=message2.encode()
    message3=message3.encode()
    e1=int.from_bytes(hashlib.sha256(message1).digest(),"big")%q
    e2=int.from_bytes(hashlib.sha256(message2).digest(),"big")%q
    e3=int.from_bytes(hashlib.sha256(message3).digest(),"big")%q
    num=(e1*s2*s3+e2*s1*s3-e3*s1*s2)%q
    den=(r1*s2*s3+r2*s1*s3-r3*s1*s2)%q
    if den==0:
        return None
    x=num*pow(den,-1,q)%q
    if pow(g,x,p)!=y:
        return None
    return x
def ECDSA_k(s,k,e,r,p,q,y,g):
    s=int(s)
    k=int(k)
    e=int(e)
    r=int(r)
    p=int(p)
    q=int(q)
    if r%q==0:
        return None
    x=(s*k-e)*pow(r,-1,q)%q
    try:
        valid=int(x)*g==y
    except TypeError:
        valid=g*int(x)==y
    if not valid:
        return None
    return x
def ECDSA_double_k(s1,s2,r1,r2,message1,message2,p,q,y,g):
    check("hashlib")
    s1=int(s1)
    s2=int(s2)
    r1=int(r1)
    r2=int(r2)
    p=int(p)
    q=int(q)
    message1=message1.encode()
    message2=message2.encode()
    if r1!=r2:
        return None
    e1=int.from_bytes(hashlib.sha256(message1).digest(),"big")%q
    e2=int.from_bytes(hashlib.sha256(message2).digest(),"big")%q
    den=(s1-s2)%q
    if den==0 or r1%q==0:
        return None
    k=(e1-e2)*pow(den,-1,q)%q
    x=(s1*k-e1)*pow(r1,-1,q)%q
    try:
        valid=int(x)*g==y
    except TypeError:
        valid=g*int(x)==y
    if not valid:
        return None
    return x
def ECDSA_k_square(s1,s2,r1,r2,message1,message2,p,q,y,g):
    check("hashlib")
    check("sympy.ntheory.residue_ntheory")
    s1=int(s1)
    s2=int(s2)
    r1=int(r1)
    r2=int(r2)
    p=int(p)
    q=int(q)
    message1=message1.encode()
    message2=message2.encode()
    e1=int.from_bytes(hashlib.sha256(message1).digest(),"big")%q
    e2=int.from_bytes(hashlib.sha256(message2).digest(),"big")%q
    a=s2*r1%q
    b=-s1*r2%q
    c=(e1*r2-e2*r1)%q
    phi=(b*b-4*a*c)%q
    roots=residue_ntheory.sqrt_mod(phi,q,all_roots=True)
    if not roots or 2*a%q==0 or r1%q==0:
        return None
    inv=pow(2*a,-1,q)
    for root in roots:
        k=(-b+int(root))*inv%q
        x=(s1*k-e1)*pow(r1,-1,q)%q
        try:
            valid=int(x)*g==y
        except TypeError:
            valid=g*int(x)==y
        if valid:
            return x,k
    return None
def ECDSA_k_linear(s1,s2,s3,r1,r2,r3,message1,message2,message3,p,q,y,g):
    check("hashlib")
    s1=int(s1)
    s2=int(s2)
    s3=int(s3)
    r1=int(r1)
    r2=int(r2)
    r3=int(r3)
    p=int(p)
    q=int(q)
    message1=message1.encode()
    message2=message2.encode()
    message3=message3.encode()
    e1=int.from_bytes(hashlib.sha256(message1).digest(),"big")%q
    e2=int.from_bytes(hashlib.sha256(message2).digest(),"big")%q
    e3=int.from_bytes(hashlib.sha256(message3).digest(),"big")%q
    numerator=(e1*s2*s3+e2*s1*s3-e3*s1*s2)%q
    denominator=(r1*s2*s3+r2*s1*s3-r3*s1*s2)%q
    if denominator==0:
        return None
    x=-numerator*pow(denominator,-1,q)%q
    try:
        valid=int(x)*g==y
    except TypeError:
        valid=g*int(x)==y
    if not valid:
        return None
    return x
def Schnorr_k(s,k,e,r,p,q,y,g):
    s=int(s)
    k=int(k)
    e=int(e)
    r=int(r)
    p=int(p)
    q=int(q)
    y=int(y)
    g=int(g)
    if e%q==0:
        return None
    x=(s-k)*pow(e,-1,q)%q
    if pow(g,k,p)!=r%p:
        return None
    if pow(g,x,p)!=y:
        return None
    return x
def Schnorr_double_k(s1,s2,r1,r2,message1,message2,p,q,y,g):
    check("hashlib")
    s1=int(s1)
    s2=int(s2)
    r1=int(r1)
    r2=int(r2)
    p=int(p)
    q=int(q)
    y=int(y)
    g=int(g)
    message1=message1.encode()
    message2=message2.encode()
    if r1%p!=r2%p:
        return None
    size=(p.bit_length()+7)//8
    e1=int.from_bytes(hashlib.sha256(r1.to_bytes(size,"big")+message1).digest(),"big")%q
    e2=int.from_bytes(hashlib.sha256(r2.to_bytes(size,"big")+message2).digest(),"big")%q
    den=(e1-e2)%q
    if den==0:
        return None
    x=(s1-s2)*pow(den,-1,q)%q
    k=(s1-e1*x)%q
    if pow(g,k,p)!=r1%p:
        return None
    if pow(g,x,p)!=y:
        return None
    return x
def Schnorr_k_square(s1,s2,r1,r2,message1,message2,p,q,y,g):
    check("hashlib")
    check("sympy.ntheory.residue_ntheory")
    s1=int(s1)
    s2=int(s2)
    r1=int(r1)
    r2=int(r2)
    p=int(p)
    q=int(q)
    y=int(y)
    g=int(g)
    message1=message1.encode()
    message2=message2.encode()
    size=(p.bit_length()+7)//8
    e1=int.from_bytes(hashlib.sha256(r1.to_bytes(size,"big")+message1).digest(),"big")%q
    e2=int.from_bytes(hashlib.sha256(r2.to_bytes(size,"big")+message2).digest(),"big")%q
    a=e1
    b=-e2
    c=e2*s1-e1*s2
    phi=(b*b-4*a*c)%q
    roots=residue_ntheory.sqrt_mod(phi,q,all_roots=True)
    if not roots or 2*a%q==0:
        return None
    inv=pow(2*a,-1,q)
    for root in roots:
        k=(-b+int(root))*inv%q
        k2=k*k%q
        if e1==0:
            continue
        x=(s1-k)*pow(e1,-1,q)%q
        if pow(g,k,p)!=r1%p:
            continue
        if pow(g,k2,p)!=r2%p:
            continue
        if pow(g,x,p)==y:
            return x,k
    return None
def Schnorr_k_linear(s1,s2,s3,r1,r2,r3,message1,message2,message3,p,q,y,g):
    check("hashlib")
    s1=int(s1)
    s2=int(s2)
    s3=int(s3)
    r1=int(r1)
    r2=int(r2)
    r3=int(r3)
    p=int(p)
    q=int(q)
    y=int(y)
    g=int(g)
    message1=message1.encode()
    message2=message2.encode()
    message3=message3.encode()
    size=(p.bit_length()+7)//8
    e1=int.from_bytes(hashlib.sha256(r1.to_bytes(size,"big")+message1).digest(),"big")%q
    e2=int.from_bytes(hashlib.sha256(r2.to_bytes(size,"big")+message2).digest(),"big")%q
    e3=int.from_bytes(hashlib.sha256(r3.to_bytes(size,"big")+message3).digest(),"big")%q
    numerator=(s1+s2-s3)%q
    denominator=(e1+e2-e3)%q
    if denominator==0:
        return None
    x=numerator*pow(denominator,-1,q)%q
    k1=(s1-e1*x)%q
    k2=(s2-e2*x)%q
    k3=(s3-e3*x)%q
    if (k1+k2-k3)%q!=0:
        return None
    if pow(g,x,p)!=y:
        return None
    return x
def ECDSA_mirror(r,s,n):
    r=int(r)
    s=int(s)
    n=int(n)
    s=n-s
    return r,s
def Elgamal_hash_ignore_signing(p,y,g,v):
    check("random")
    v=int(v)
    p=int(p)
    y=int(y)
    g=int(g)
    if gcd(v,p-1)!=1:
        raise ValueError("v 必须与 p-1 互素")
    while True:
        u=random.randint(1,p-2)
        if gmpy2.gcd(v,p-1)==1:
            break
    r=int(gmpy2.powmod(g,u,p)*gmpy2.powmod(y,v,p)%p)
    s=int(((-r)*gmpy2.powmod(v,-1,p-1))%(p-1))
    m=int(u*s%(p-1))
    return r,s
def diffie_hellman_BOb_gets(p):
    p=int(p)
    b1=0
    s1=0
    b2=1
    s2=1
    b3=p
    s3=0
    b4=p-1
    s41=p-1
    s42=1
    return (f"b1={b1}",f"s1={s1}",f"b2={b2}",f"s2={s2}",f"b3={b3}",f"s3={s3}",f"b4={b4}",f"a为奇数时={s41}",f"a为偶数={s42}")
def diffie_hellman_subgroup(p,g):
    check("sympy")
    check("sympy.ntheory.modular")
    p=int(p)
    g=int(g)
    Max=10000
    def get_order1(g,p):
        order=p-1
        for q,e in sympy.factorint(order).items():
            q=int(q)
            for _ in range(int(e)):
                if pow(g,order//q,p)==1:
                    order//=q
                else:
                    break
        return order
    def get_order2(order,Max):
        orders=[]
        for q,e in sympy.factorint(order).items():
            q=int(q)
            e=int(e)
            r=1
            for _ in range(e):
                if r*q>Max:
                    break
                r*=q
            if r>1:
                orders.append(r)
        return sorted(orders)
    def recover(B,r,s,p):
        value=1
        s%=p
        for j in range(r):
            if value==s:
                return j
            value=value*B%p
        return None
    order=get_order1(g,p)
    orders=get_order2(order,Max)
    moduli=[]
    residues=[]
    for r in orders:
        B=pow(g,order//r,p)
        s=int(input(f"请将B={B}发送后输入反馈的s="))
        residue=recover(B,r,s,p)
        moduli.append(r)
        residues.append(residue)
    result=modular.crt(moduli,residues)
    a0,M=map(int,result)
    return a0,M
def rsa_Pohlig_hellman(n, e, c, m=None, order=None, order_factors=None):
    check("math")
    def is_prime(n):
        if n < 2:
            return False
        for prime in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % prime == 0:
                return n == prime
        odd, shifts = n - 1, 0
        while odd % 2 == 0:
            odd //= 2
            shifts += 1
        bases = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
        if n >= 1 << 64:
            bases = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43)
        for base in bases:
            value = pow(base, odd, n)
            if value in (1, n - 1):
                continue
            for _ in range(shifts - 1):
                value = value * value % n
                if value == n - 1:
                    break
            else:
                return False
        return True
    def bsgs(base, target, size_order):
        size = math.isqrt(size_order) + 1
        table, value = {}, 1
        for index in range(size):
            table.setdefault(value, index)
            value = value * base % modulus
        step = pow(pow(base, size, modulus), -1, modulus)
        value = target
        for block in range(size + 1):
            if value in table:
                candidate = block * size + table[value]
                if candidate < size_order:
                    return candidate
            value = value * step % modulus
        raise ValueError("离散对数不在给定子群内")
    if m is None:
        raise ValueError("Pohlig-Hellman 离散对数需要已知明文 m")
    modulus, e, g, h = int(n), int(e), int(c), int(m)
    if modulus < 2:
        raise ValueError("modulus 必须大于 1")
    g, h = g % modulus, h % modulus
    if e < 2 or pow(h, e, modulus) != g:
        raise ValueError("m^e (mod n) 与 c 不符")
    if math.gcd(g, modulus) != 1 or math.gcd(h, modulus) != 1:
        raise ValueError("g 和 h 必须属于模 modulus 的乘法群")
    if order is None:
        if not is_prime(modulus):
            raise ValueError("复合模数需要显式提供 c 的阶或其倍数")
        order = modulus - 1
    order = int(order)
    if order < 1 or pow(g, order, modulus) != 1:
        raise ValueError("order 不是 g 的阶的倍数")
    if order_factors is None:
        factors, leftover, divisor = {}, order, 2
        while divisor * divisor <= leftover:
            while leftover % divisor == 0:
                factors[divisor] = factors.get(divisor, 0) + 1
                leftover //= divisor
            divisor = 3 if divisor == 2 else divisor + 2
        if leftover > 1:
            factors[leftover] = factors.get(leftover, 0) + 1
    else:
        factors = {int(p): int(k) for p, k in order_factors.items()}
        if (any(k < 1 or not is_prime(p) for p, k in factors.items())
                or math.prod(p**k for p, k in factors.items()) != order):
            raise ValueError("order_factors 必须是 order 的完整素因子分解")
    for prime in tuple(factors):
        while factors[prime] and pow(g, order // prime, modulus) == 1:
            order //= prime
            factors[prime] -= 1
        if factors[prime] == 0:
            del factors[prime]
    if pow(h, order, modulus) != 1:
        raise ValueError("h 不在 g 生成的子群内")
    x, combined = 0, 1
    for prime, exponent in factors.items():
        residue = 0
        digit_base = pow(g, order // prime, modulus)
        for index in range(exponent):
            remaining = h * pow(pow(g, residue, modulus), -1, modulus) % modulus
            digit_target = pow(remaining, order // prime ** (index + 1), modulus)
            residue += bsgs(digit_base, digit_target, prime) * prime ** index
        prime_power = prime ** exponent
        x += combined * ((residue - x) * pow(combined, -1, prime_power) % prime_power)
        combined *= prime_power
    if pow(g, x, modulus) != h:
        raise ValueError("未找到离散对数")
    return x
def rsa_Pollard_p_1(n, e, c, bound=10000, stage2_bound=None, bases=(2, 3, 5, 7, 11),n_inner=None, bounds=None):
    check("math")
    n, e, c, bound = int(n), int(e), int(c), int(bound)
    if n < 4 or bound < 2 or not 0 <= c < n or e < 2:
        raise ValueError("n 和 bound 无效")
    if stage2_bound is not None:
        stage2_bound = int(stage2_bound)
        if stage2_bound < bound:
            raise ValueError("stage2_bound 不能小于 bound")
    def primes_upto(limit):
        sieve = bytearray(b"\x01") * (limit + 1)
        sieve[:2] = b"\x00\x00"
        for prime in range(2, math.isqrt(limit) + 1):
            if sieve[prime]:
                start = prime * prime
                sieve[start:limit + 1:prime] = b"\x00" * ((limit - start) // prime + 1)
        return [prime for prime in range(2, limit + 1) if sieve[prime]]
    def power_lcm(base, limit, modulus, primes):
        value = base % modulus
        for prime in primes:
            if prime > limit:
                break
            power = prime
            while power * prime <= limit:
                power *= prime
            value = pow(value, power, modulus)
        return value
    if n_inner is None:
        primes = primes_upto(max(bound, stage2_bound or bound))
        p = None
        if n % 2 == 0:
            p = 2
        else:
            for base in bases:
                factor = math.gcd(base, n)
                if not 1 < factor < n:
                    value = power_lcm(base, bound, n, primes)
                    factor = math.gcd(value - 1, n)
                    if not 1 < factor < n and stage2_bound is not None:
                        for prime in primes:
                            if bound < prime <= stage2_bound:
                                factor = math.gcd(pow(value, prime, n) - 1, n)
                                if 1 < factor < n:
                                    break
                if 1 < factor < n:
                    p = factor
                    break
        if p is None:
            raise ValueError("Pollard P-1 未找到因子，请调整边界或底数")
        q = n // p
        phi = (p - 1) * (q - 1)
        modulus = n
    else:
        import gmpy2
        n_inner = int(n_inner)
        if n_inner < 2 or not 0 <= c < n_inner:
            raise ValueError("n_inner 无效")
        if bounds is None:
            scan = list(range(1_048_576, 860_000, -20_000))
            for step in (5000, 2000, 1000, 500):
                scan.extend(range(1_048_576, 860_000, -step))
            bounds = tuple(dict.fromkeys(scan))
        else:
            bounds = tuple(int(item) for item in bounds)
        if not bounds or min(bounds) < 2:
            raise ValueError("bounds 必须包含大于 1 的搜索边界")
        primes = primes_upto(max(bounds))
        pending = [n]
        outer_primes = []
        while pending:
            current = pending.pop()
            if gmpy2.is_prime(current):
                outer_primes.append(current)
                continue
            factor = None
            for limit in bounds:
                for base in bases:
                    factor = math.gcd(base, current)
                    if not 1 < factor < current:
                        value = power_lcm(base, limit, current, primes)
                        factor = math.gcd(pow(value, n_inner, current) - 1, current)
                    if 1 < factor < current:
                        break
                if 1 < factor < current:
                    break
            if not 1 < factor < current:
                raise ValueError(f"未分解 {current.bit_length()} 位合数，请调整 bounds/bases")
            pending.extend((factor, current // factor))
        remaining = n_inner
        inner_primes = []
        for outer in sorted(outer_primes):
            factor = math.gcd(int(outer) - 1, remaining)
            if factor > 1:
                if not gmpy2.is_prime(factor):
                    raise ValueError("gcd(P-1,n_inner) 是合数")
                inner_primes.append(factor)
                remaining //= factor
        if remaining != 1 or len(set(inner_primes)) != len(inner_primes):
            raise ValueError("外层因子未覆盖 n_inner 的全部素因子")
        phi = math.prod(int(p) - 1 for p in inner_primes)
        modulus = n_inner
    d = pow(e, -1, phi)
    m = pow(c, d, modulus)
    if pow(m, e, modulus) != c:
        raise ValueError("分解结果无法还原密文")
    return m.to_bytes(max(1, (m.bit_length() + 7) // 8), "big")
def rsa_Willim_p_1(n, e, c, bound=1000, parameter_limit=100, exponent=None):
    import math
    n, e, c, bound = int(n), int(e), int(c), int(bound)
    parameter_limit = int(parameter_limit)
    if n < 4 or e < 2 or not 0 <= c < n or parameter_limit < 3 or (exponent is None and bound < 2):
        raise ValueError("n 和 bound 必须有效")
    def primes_upto(limit):
        sieve = bytearray(b"\x01") * (limit + 1)
        sieve[:2] = b"\x00\x00"
        for prime in range(2, math.isqrt(limit) + 1):
            if sieve[prime]:
                start = prime * prime
                sieve[start:limit + 1:prime] = b"\x00" * ((limit - start) // prime + 1)
        return [prime for prime in range(2, limit + 1) if sieve[prime]]
    def lucas_v(parameter, power):
        v_n, v_n_plus_1 = 2 % n, parameter % n
        for bit in bin(power)[2:]:
            v_2n = (v_n * v_n - 2) % n
            v_2n_plus_1 = (v_n * v_n_plus_1 - parameter) % n
            if bit == "0":
                v_n, v_n_plus_1 = v_2n, v_2n_plus_1
            else:
                v_n, v_n_plus_1 = v_2n_plus_1, (v_n_plus_1 * v_n_plus_1 - 2) % n
        return v_n
    if exponent is None:
        exponent = 1
        for prime in primes_upto(bound):
            power = prime
            while power * prime <= bound:
                power *= prime
            exponent *= power
    else:
        exponent = int(exponent)
    if exponent < 1:
        raise ValueError("exponent 必须大于零")
    for parameter in range(3, parameter_limit + 1):
        factor = math.gcd(parameter * parameter - 4, n)
        if not 1 < factor < n:
            factor = math.gcd(lucas_v(parameter, exponent) - 2, n)
        if 1 < factor < n:
            p, q = factor, n // factor
            d = pow(e, -1, (p - 1) * (q - 1))
            m = pow(c, d, n)
            if pow(m, e, n) != c:
                continue
            return m.to_bytes(max(1, (m.bit_length() + 7) // 8), "big")
    raise ValueError("Williams p+1 未找到因子")
def rsa_BF(n, e, c, delta=0.28, m=4, config_path=None, timeout=300):
    check("decimal")
    n, e, c, m = int(n), int(e), int(c), int(m)
    delta = decimal.Decimal(str(delta))
    source = """
from sage.all import Integer, Matrix, PolynomialRing, RealField, ZZ
from math import isqrt
n = Integer(request["n"])
e = Integer(request["e"])
delta = RealField(128)(request["delta"])
mm = int(request["m"])
tt = int((1 - 2 * delta) * mm)
XX = 2 * int(RealField(128)(n) ** delta)
YY = isqrt(int(n))
A = (n + 1) // 2
PR = PolynomialRing(ZZ, names=("u", "x", "y"))
u, x, y = PR.gens()
Q = PR.quotient(x * y + 1 - u)
pol = 1 + x * (A + y)
polZ = Q(pol).lift()
UU = XX * YY + 1
gg = []
for kk in range(mm + 1):
    for ii in range(mm - kk + 1):
        gg.append(x**ii * e**(mm - kk) * polZ**kk)
gg.sort()
monomials = sorted({mon for polynomial in gg for mon in polynomial.monomials()})
for jj in range(1, tt + 1):
    for kk in range((mm // tt) * jj, mm + 1):
        gg.append(Q(y**jj * polZ**kk * e**(mm - kk)).lift())
        monomials.append(u**kk * y**jj)
dimension = len(monomials)
if len(gg) != dimension:
    raise ValueError("格基向量与单项式数量不一致")
BB = Matrix(ZZ, dimension)
for ii in range(dimension):
    BB[ii, 0] = gg[ii](0, 0, 0)
    for jj in range(1, ii + 1):
        if monomials[jj] in gg[ii].monomials():
            BB[ii, jj] = (gg[ii].monomial_coefficient(monomials[jj])* monomials[jj](UU, XX, YY))
def prune(matrix, mons, bound, current):
    if current < 0 or matrix.nrows() <= 7:
        return matrix
    for ii in range(current, -1, -1):
        if matrix[ii, ii] < bound:
            continue
        affected = [jj for jj in range(ii + 1, matrix.nrows()) if matrix[jj, ii]]
        if not affected:
            matrix = matrix.delete_columns([ii]).delete_rows([ii])
            mons.pop(ii)
            return prune(matrix, mons, bound, ii - 1)
        if len(affected) == 1:
            deeper = affected[0]
            if (all(matrix[kk, deeper] == 0 for kk in range(deeper + 1, matrix.nrows()))
                    and abs(bound - matrix[deeper, deeper]) < abs(bound - matrix[ii, ii])):
                matrix = matrix.delete_columns([deeper, ii]).delete_rows([deeper, ii])
                mons.pop(deeper)
                mons.pop(ii)
                return prune(matrix, mons, bound, ii - 1)
    return matrix
BB = prune(BB, monomials, e**mm, dimension - 1)
dimension = BB.nrows()
BB = BB.LLL()
R2 = PolynomialRing(ZZ, names=("w", "z"))
w, z = R2.gens()
Rz = PolynomialRing(ZZ, "z")
Rw = PolynomialRing(Rz, "w")
Rint = PolynomialRing(ZZ, "w")
z_var = Rz.gen()
w_var = Rw.gen()
def reconstruct(row):
    polynomial = R2.zero()
    for jj, mon in enumerate(monomials):
        scale = mon(UU, XX, YY)
        coefficient = BB[row, jj]
        if coefficient % scale:
            raise ValueError("LLL 结果的系数不可整除格基缩放量")
        polynomial += R2(mon(w * z + 1, w, z)) * (coefficient // scale)
    return polynomial
def as_univariate(polynomial):
    return sum((Rw(coefficient * z_var**powers[1]) * w_var**powers[0]for powers, coefficient in polynomial.dict().items()),Rw.zero())
result = None
for i in range(dimension - 1):
    pol1 = reconstruct(i)
    first = as_univariate(pol1)
    for j in range(i + 1, dimension):
        pol2 = reconstruct(j)
        rr = first.resultant(as_univariate(pol2))
        if rr.is_zero():
            continue
        if rr.degree() <= 0:
            continue
        for root_y, _ in rr.roots(ring=ZZ):
            rx = Rint([coefficient(root_y) for coefficient in first.list()])
            if rx.is_zero():
                continue
            for root_x, _ in rx.roots(ring=ZZ):
                if root_x <= 0 or pol2(root_x, root_y) != 0:
                    continue
                phi = 2 * (A + root_y)
                summed = n + 1 - phi
                discr = summed * summed - 4 * n
                if phi <= 0 or discr < 0:
                    continue
                square = isqrt(int(discr))
                if square * square != discr or (summed + square) % 2:
                    continue
                p = (summed + square) // 2
                q = (summed - square) // 2
                if p <= 1 or q <= 1 or p * q != n:
                    continue
                value = 1 + root_x * (A + root_y)
                if value % e or (e * (value // e) - 1) % phi:
                    continue
                result = {"d": str(value // e), "p": str(p), "q": str(q)}
                break
            if result is not None:
                break
        if result is not None:
            break
    if result is not None:
        break
if result is None:
    raise ValueError("Boneh-Durfee 未找到可验证的私钥，请调整 delta 和 m")
"""
    check("sage")
    found = sage(
        source,
        {"n": str(n), "e": str(e), "delta": str(delta), "m": m},
        config_path=config_path,
        timeout=timeout,
        show_status=False,
    )
    d, p, q = (int(found[name]) for name in ("d", "p", "q"))
    if p * q != n or (e * d - 1) % ((p - 1) * (q - 1)):
        raise ValueError("Sage 返回了无效的私钥")
    plaintext = pow(c, d, n)
    return plaintext.to_bytes(max(1, (plaintext.bit_length() + 7) // 8), "big")
def hash_brute_force(n,suffix_former,suffix_latter,target=None):
    check("string")
    check("hashlib")
    check("itertools")
    if target is None:
        raise ValueError("必须提供目标哈希 target")
    chars=string.ascii_letters + string.digits+string.punctuation
    for _ in itertools.product(chars, repeat=n):
        prefix="".join(x for x in _)
        candidate=suffix_former+prefix+suffix_latter
        result=hashlib.sha256(candidate.encode()).hexdigest()
        if result==target:
            return prefix
    return None
def hash_md5_length_extension(old_hash,message,append,start,end):
    check("math")
    check("struct")
    MASK = 0xffffffff
    S = ([7, 12, 17, 22] * 4+ [5, 9, 14, 20] * 4+ [4, 11, 16, 23] * 4+ [6, 10, 15, 21] * 4)
    K = [int(abs(math.sin(i + 1)) * 2 ** 32) & MASK for i in range(64)]
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & MASK
    def md5_padding(message_len):
        zero_len = (56 - (message_len + 1) % 64) % 64
        return b"\x80" + b"\x00" * zero_len + struct.pack("<Q", message_len * 8)
    def md5_compress(chunk, state):
        a, b, c, d = state
        aa, bb, cc, dd = a, b, c, d
        m = struct.unpack("<16I", chunk)
        for i in range(64):
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16
            f = (f + a + K[i] + m[g]) & MASK
            a, d, c, b = d, c, b, (b + rol(f, S[i])) & MASK
        return ((aa + a) & MASK,(bb + b) & MASK,(cc + c) & MASK,(dd + d) & MASK)
    def md5_extend(data, state, count):
        work = data + md5_padding(count + len(data))
        for i in range(0, len(work), 64):
            state = md5_compress(work[i:i + 64], state)
        return struct.pack("<4I", *state).hex()
    old_state = struct.unpack("<4I", bytes.fromhex(old_hash))
    candidates=[]
    for key_len in range(start, end + 1):
        glue = md5_padding(key_len + len(message))
        forged_message = message + glue + append
        count = key_len + len(message) + len(glue)
        forged_hash = md5_extend(append, old_state, count)
        candidates.append((forged_message, forged_hash))
    if not candidates:
        raise ValueError("start 和 end 没有覆盖任何密钥长度")
    return candidates
def mt19937_reverse(outputs,position=None,start=None,end=None):
    outputs=list(outputs)
    mask=0xffffffff
    def invert(y,shift,right=True,bitmask=mask):
        x=y
        for _ in range(32//shift):
            x=y^((x>>shift if right else x<<shift)&bitmask)
        return x&mask
    state=[invert(invert(invert(invert(y,18),15,False,0xefc60000),7,False,0x9d2c5680),11)for y in outputs]
    initial=state[:]
    def recover(i):
        y=initial[i]^initial[(i+397)%624]
        if y&0x80000000:
            y=((y^0x9908b0df)<<1)|1
        else:
            y<<=1
        return y&mask
    for i in range(623,-1,-1):
        initial[i]=(recover(i)&0x80000000)|(recover(i-1)&0x7fffffff)
    inverse=pow(1812433253,-1,1<<32)
    seed=initial[623]
    for i in range(623,0,-1):
        seed=invert(((seed-i)*inverse)&mask,30)
    mt=[seed]
    for i in range(1,624):
        mt.append((1812433253*(mt[-1]^(mt[-1]>>30))+i)&mask)
    check("random")
    rng=random.Random()
    rng.setstate((3,tuple(mt+[624]),None))
    if any(rng.getrandbits(32)!=x for x in outputs):
        raise ValueError("输出不符合从起始位置使用init_genrand(seed)生成的序列")
    if position is None and start is None:
        return seed
    rng.setstate((3,tuple(state+[624]),None))
    value=None
    segment=[] if start is not None else None
    limit=max(position+1 if position is not None else 0,end or 0)
    for i in range(limit):
        word=rng.getrandbits(32)
        if i==position:
            value=word
        if segment is not None and start<=i<end:
            segment.append(word)
    return seed,value,segment
def mt19937_blackbox(outputs,matrix_path,position=None,start=None,end=None):
    outputs=list(outputs)
    matrix_path = str(matrix_path)
    if len(matrix_path) >= 2 and matrix_path[1] == ":":
        matrix_path = matrix_path.replace("\\", "/")
        matrix_path = "/mnt/" + matrix_path[0].lower() + matrix_path[2:]
    check("sage")
    source=r"""
from sage.all import GF,vector,load
N=624
MASK=0xffffffff
loaded=load(request["matrix_path"])
if isinstance(loaded,tuple):
    A,zero=loaded
else:
    A=loaded
    zero=vector(GF(2),A.nrows())
b=vector(GF(2),[(x>>j)&1 for x in request["outputs"] for j in range(32)])+zero
bits=A.solve_right(b)
state=[
    sum(int(bits[32*i+j])<<j for j in range(32))&MASK
    for i in range(N)
]
J=[0]*N
def g(x):
    return ((x^(x>>30))*1566083941)&MASK
J[1]=((state[1]+1)&MASK)^g(state[623])
J[2]=((state[2]+2)&MASK)^g(J[1])
for i in range(3,N):
    J[i]=((state[i]+i)&MASK)^g(state[i-1])
initial=[19650218]
for i in range(1,N):
    initial.append((1812433253*(initial[-1]^(initial[-1]>>30))+i)&MASK)
result=int((J[3]-(initial[3]^(((J[2]^(J[2]>>30))*1664525)&MASK)))&MASK)
"""
    seed=int(sage(
        source,
        {"outputs":outputs,"matrix_path":str(matrix_path)},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    ))
    check("random")
    rng=random.Random(seed)
    if any(rng.getrandbits(32)!=x for x in outputs):
        raise ValueError("系数错误")
    if position is None and start is None:
        return seed
    value=None
    segment=[] if start is not None else None
    limit=max(position+1 if position is not None else 0,end or 0)
    for i in range(limit):
        word=rng.getrandbits(32)
        if i==position:
            value=word
        if segment is not None and start<=i<end:
            segment.append(word)
    return seed,value,segment
def lfsr_recover(bits,n=None,position=None,start=None,end=None):
    if isinstance(bits,str):
        bits="".join(bits.split())
    bits=[int(x) for x in bits]
    n=len(bits)//2 if n is None else int(n)
    check("sage")
    source=r"""
from sage.all import GF,matrix,vector
bits=request["bits"]
n=request["n"]
A=matrix(GF(2),[bits[i:i+n]for i in range(len(bits)-n)])
B=vector(GF(2),bits[n:])
if A.rank()<n:
    raise ValueError("输出不足以唯一确定反馈系数")
result=[int(x) for x in A.solve_right(B)]
"""
    taps=sage(
        source,
        {"bits":bits,"n":n},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    )
    seed=bits[:n]
    if position is None and start is None:
        return seed,taps
    state=bits[-n:]
    value=None
    segment=[] if start is not None else None
    limit=max(position+1 if position is not None else 0,end or 0)
    for i in range(limit):
        bit=sum(taps[j]*state[j] for j in range(n))%2
        state=state[1:]+[bit]
        if i==position:
            value=bit
        if segment is not None and start<=i<end:
            segment.append(bit)
    return seed,taps,value,segment
def detect_ECC(a,b,p):
    check("sage")
    a=int(a)
    b=int(b)
    p=int(p)
    source=r"""
from sage.all import GF,EllipticCurve,ZZ
a=ZZ(request["a"])
b=ZZ(request["b"])
p=ZZ(request["p"])
E=EllipticCurve(GF(p),[a,b])
result=int(E.order())
"""
    return int(sage(
        source,
        {"a":a,"b":b,"p":p},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    ))
def ECC_BSGS(xp,yp,xq,yq,a,b,q):
    check("sage")
    source=r"""
from sage.all import EllipticCurve,GF,ZZ,discrete_log
p=ZZ(request["q"])
xp=ZZ(request["xp"])
yp=ZZ(request["yp"])
xq=ZZ(request["xq"])
yq=ZZ(request["yq"])
a=ZZ(request["a"])
b=ZZ(request["b"])
E=EllipticCurve(GF(p),[a,b])
P=E(xp,yp)
Q=E(xq,yq)
n=ZZ(P.order())
result=ZZ(discrete_log(Q,P,ord=n,operation="+",algorithm="bsgs"))
"""
    return int(sage(
        source,
        {"xp":int(xp),"yp":int(yp),"xq":int(xq),"yq":int(yq),"a":int(a),"b":int(b),"q":int(q)},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    ))
def ECC_smart(xp,yp,xq,yq,a,b,q):
    check("sage")
    source=r"""
from sage.all import EllipticCurve,GF,ZZ,Qp,randint
p=ZZ(request["q"])
xp=ZZ(request["xp"])
yp=ZZ(request["yp"])
xq=ZZ(request["xq"])
yq=ZZ(request["yq"])
a=ZZ(request["a"])
b=ZZ(request["b"])
E=EllipticCurve(GF(p),[a,b])
P=E(xp,yp)
Q=E(xq,yq)
if E.order()!=p:
    raise ValueError("该曲线不是异常曲线，不能使用Smart攻击")
Eqp=EllipticCurve(
    Qp(p,2),
    [ZZ(t)+randint(0,int(p)-1)*p for t in E.a_invariants()])
def lift_point(point):
    lifts=Eqp.lift_x(ZZ(point.xy()[0]),all=True)
    for lifted in lifts:
        if GF(p)(lifted.xy()[1])==point.xy()[1]:
            return lifted
P_Qp=lift_point(P)
Q_Qp=lift_point(Q)
P_times=P_Qp*p
Q_times=Q_Qp*p
x_P,y_P=P_times.xy()
x_Q,y_Q=Q_times.xy()
phi_P=-(x_P/y_P)
phi_Q=-(x_Q/y_Q)
result=int(ZZ((phi_Q/phi_P).lift()))%int(p)
"""
    return int(sage(
        source,
        {"xp":int(xp),"yp":int(yp),"xq":int(xq),"yq":int(yq),"a":int(a),"b":int(b),"q":int(q)},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    ))
def ECC_mov(xp,yp,xq,yq,a,b,q):
    check("sage")
    source=r"""
from sage.all import EllipticCurve,GF,ZZ,gcd,discrete_log
p=ZZ(request["q"])
xp=ZZ(request["xp"])
yp=ZZ(request["yp"])
xq=ZZ(request["xq"])
yq=ZZ(request["yq"])
a=ZZ(request["a"])
b=ZZ(request["b"])
E=EllipticCurve(GF(p),[a,b])
P=E(xp,yp)
Q=E(xq,yq)
n=ZZ(P.order())
if gcd(n,p)!=1:
    raise ValueError("子群阶不能被特征p整除")
embedding_degree=1
while (p**embedding_degree-1)%n!=0:
    embedding_degree+=1
Fpk=GF(p**embedding_degree,name="z",)
EK=EllipticCurve(Fpk,[Fpk(a),Fpk(b)])
PK=EK(Fpk(xp),Fpk(yp))
QK=EK(Fpk(xq),Fpk(yq))
while True:
    R=EK.random_point()
    if R.is_zero():
        continue
    pairing_P=PK.tate_pairing(R,n,embedding_degree)
    if pairing_P!=1:
        break
pairing_Q=QK.tate_pairing(R,n,embedding_degree)
result=int(discrete_log(pairing_Q,pairing_P,ord=n,operation="*"))%int(n)
if result*P!=Q:
    raise ValueError("MOV攻击结果验证失败")
"""
    return int(sage(
        source,
        {"xp":int(xp),"yp":int(yp),"xq":int(xq),"yq":int(yq),"a":int(a),"b":int(b),"q":int(q)},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    ))
def ECC_invalid(xp,yp,xq,yq,q):
    check("sage")
    source=r"""
from sage.all import (EllipticCurve,GF,ZZ,factor,discrete_log,crt)
p=ZZ(request["q"])
xp=ZZ(request["xp"])
yp=ZZ(request["yp"])
xq=ZZ(request["xq"])
yq=ZZ(request["yq"])
a=ZZ(3)
b=(yp**2-xp**3-a*xp)%p
E=EllipticCurve(GF(p),[a,b])
P=E(xp,yp)
Q=E(xq,yq)
order=ZZ(P.order())
res=[]
mods=[]
for prime,exp in factor(order):
    pe=ZZ(prime)**int(exp)
    m=order//pe
    Pi=m*P
    Qi=m*Q
    if Pi.is_zero():
        raise ValueError("存在无法使用的子群因子")
    ki=discrete_log(Qi,Pi,ord=pe,operation="+")
    res.append(ZZ(ki))
    mods.append(pe)
if not mods:
    raise ValueError("无法分解点的阶")
result=int(ZZ(crt(res,mods))%order)
if result*P!=Q:
    raise ValueError("无效曲线攻击结果验证失败")
"""
    return int(sage(
        source,
        {"xp":int(xp),"yp":int(yp),"xq":int(xq),"yq":int(yq),"q":int(q)},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    ))
def ECC_kangaroo(xp,yp,xq,yq,a,b,q,start,end):
    check("sage")
    start=int(start)
    end=int(end)
    source=r"""
from sage.all import EllipticCurve,GF,ZZ,discrete_log,oo
p=ZZ(request["q"])
xp=ZZ(request["xp"])
yp=ZZ(request["yp"])
xq=ZZ(request["xq"])
yq=ZZ(request["yq"])
a=ZZ(request["a"])
b=ZZ(request["b"])
start=ZZ(request["start"])
end=ZZ(request["end"])
E=EllipticCurve(GF(p),[a,b])
P=E(xp,yp)
Q=E(xq,yq)
result=ZZ(discrete_log(Q,P,ord=oo,bounds=(start,end),operation="+",algorithm="lambda"))
if not start<=result<=end:
    raise ValueError("结果不在指定范围内")
if result*P!=Q:
    raise ValueError("Pollard Kangaroo结果验证失败")
"""
    return int(sage(
        source,
        {"xp":int(xp),"yp":int(yp),"xq":int(xq),"yq":int(yq),"a":int(a),"b":int(b),"q":int(q),"start":start,"end":end},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    ))
def ECB_MITM(ciphertext,message,key1_know,key2_know):
    check("Crypto.Cipher.AES")
    if isinstance(message,str):
        message=message.encode()
    if isinstance(ciphertext,str):
        ciphertext=bytes.fromhex(ciphertext)
    if isinstance(key1_know,str):
        key1_know=key1_know.encode()
    if isinstance(key2_know,str):
        key2_know=key2_know.encode()
    key1_know=bytes(key1_know)
    key2_know=bytes(key2_know)
    mulu={}
    for a in range(256):
        for b in range(256):
            for c in range(256):
                guess1=bytes([a,b,c])
                key1=key1_know+guess1
                aes1=AES.new(key1,AES.MODE_ECB)
                middle=aes1.encrypt(message)
                mulu[middle]=key1
    for d in range(256):
        for e in range(256):
            for f in range(256):
                guess2=bytes([d,e,f])
                key2=key2_know+guess2
                aes2=AES.new(key2,AES.MODE_ECB)
                middle=aes2.decrypt(ciphertext)
                if middle in mulu:
                    return mulu[middle],key2
    raise ValueError("key不存在")
def ECB_pkcs7(base_ciphertext,message,ciphertext):
    check("Crypto.Cipher.AES")
    check("string")
    def to_bytes(value):
        if isinstance(value,bytes):
            return value
        if isinstance(value,bytearray):
            return bytes(value)
        if isinstance(value,str):
            return bytes.fromhex(value.strip())
        return bytes(value)
    base_ciphertext=to_bytes(base_ciphertext)
    ciphertext=[to_bytes(value)for value in ciphertext]
    base_length=len(base_ciphertext)
    flag_length=None
    for i in range(1,min(18,len(ciphertext))):
        if len(ciphertext[i])>base_length:
            flag_length=base_length-i+1
            break
    if flag_length is None:
        raise ValueError("未找到可用于确定明文长度的密文反馈")
    known=b""
    for pos in range(flag_length):
        pad_length=15-pos%16
        block_start=(pos//16)*16
        if pad_length>=len(ciphertext):
            raise ValueError("缺少目标密文反馈")
        target=ciphertext[pad_length]
        target_block=target[block_start:block_start+AES.block_size]
        found=False
        for char in string.printable.encode():
            text_data=(b"A"*pad_length+known+bytes([char]))
            response=input(f"请发送{ text_data!r }，输入返回密文hex: ").strip()
            test_block=bytes.fromhex(response)[block_start:block_start+AES.block_size]
            if test_block==target_block:
                known+=bytes([char])
                found=True
                break
        if not found:
            raise ValueError("当前字符集范围内未找到匹配字符")
    return known
def CBC_struct(ciphertext, plaintext, index=[], target=[], src_index=1):
    BLOCK_SIZE = 16
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode()
    else:
        ciphertext = bytes(ciphertext)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    else:
        plaintext = bytes(plaintext)
    ciphertext_blocks = [ciphertext[i:i + BLOCK_SIZE]for i in range(0, len(ciphertext), BLOCK_SIZE)]
    plaintext_blocks = [plaintext[i:i + BLOCK_SIZE]for i in range(0, len(plaintext), BLOCK_SIZE)]
    src_index=int(src_index)
    positions=[int(pos) for pos in index]
    target=[int(value) for value in target]
    if len(positions)!=len(target):
        raise ValueError("index 和 target 长度必须相同")
    if not positions:
        return b""
    if len(positions)!=len(set(positions)):
        raise ValueError("index 不能包含重复位置")
    if any(value<0 or value>255 for value in target):
        raise ValueError("target 中的字节必须在 0 到 255 之间")
    if src_index<=0 or src_index>=len(ciphertext_blocks):
        raise ValueError("src_index 超出密文块范围")
    if src_index>=len(plaintext_blocks):
        raise ValueError("src_index 超出明文块范围")
    if any(pos<0 or pos//BLOCK_SIZE==0 for pos in positions):
        raise ValueError("CBC 控制位置不能位于第一个明文块")
    src = ciphertext_blocks[src_index]
    state = bytes(left ^ right for left, right in zip(plaintext_blocks[src_index],ciphertext_blocks[src_index - 1]))
    max_block = max(pos // BLOCK_SIZE for pos in positions)
    target_blocks={pos//BLOCK_SIZE for pos in positions}
    crafted = [bytearray(BLOCK_SIZE) for _ in range(max_block + 1)]
    for block in target_blocks:
        crafted[block][:] = src
    for pos, value in zip(positions, target):
        block, offset = divmod(pos, BLOCK_SIZE)
        crafted[block - 1][offset] = state[offset] ^ value
    return b"".join(bytes(block) for block in crafted)
def HLP(n,m,r,N,C=[],scale_bits=200,C_path=None,):
    n, m, r, N, scale_bits = (int(n),int(m),int(r),int(N),int(scale_bits))
    if (C is None or C == []) and C_path is not None:
        C = read_matrix(C_path)
    source=r"""
from sage.all import (IntegerLattice,Matrix,QQ,ZZ,block_matrix,identity_matrix,vector,zero_matrix)
n = ZZ(request["n"])
m = ZZ(request["m"])
r = ZZ(request["r"])
N = ZZ(request["N"])
C = Matrix(ZZ, request["C"])
scale = ZZ(1) << ZZ(request["scale_bits"])
T = block_matrix(ZZ,[[identity_matrix(ZZ, m),scale * C.transpose(),],[zero_matrix(ZZ, r, m),scale * N * identity_matrix(ZZ, r),],])
embedding_reduced = Matrix(ZZ, IntegerLattice(T).reduced_basis)
tail = embedding_reduced[:, m:]
tail_left_kernel = tail.left_kernel().basis_matrix()
orthogonal_lattice = Matrix(ZZ,tail_left_kernel * embedding_reduced[:, :m])
orthogonal_reduced = Matrix(ZZ,
IntegerLattice(orthogonal_lattice).reduced_basis)
hidden_perp_dimension = m - n
hidden_perp_rows = []
for current in sorted(orthogonal_reduced.rows(),key=lambda row: vector(ZZ, row).norm()):
    current = vector(ZZ, current)
    if current == 0:
        continue
    if any(int(value) % int(N) for value in current * C.transpose()):
        continue
    trial = hidden_perp_rows + [current]
    if Matrix(QQ, trial).rank() > len(hidden_perp_rows):
        hidden_perp_rows.append(current)
    if len(hidden_perp_rows) == hidden_perp_dimension:
        break
if len(hidden_perp_rows) != hidden_perp_dimension:
    raise ValueError("没有找到足够多的隐藏正交向量")
hidden_perp = Matrix(ZZ, hidden_perp_rows)
hidden_basis = Matrix(ZZ,hidden_perp.right_kernel(algorithm="pari").basis_matrix())
if hidden_basis.nrows() != n:
    raise ValueError("恢复格秩与输入 n 不一致")
hidden_reduced = Matrix(ZZ,IntegerLattice(hidden_basis).reduced_basis)
def rows_of(value):
    return [[int(value[i, j]) for j in range(value.ncols())]for i in range(value.nrows())]
result = {
    "hidden_perp": rows_of(hidden_perp),
    "hidden_basis": rows_of(hidden_basis),
    "hidden_reduced": rows_of(hidden_reduced),
    "norms": [
        str(vector(ZZ, row).norm())
        for row in hidden_reduced.rows()
    ],
}
"""
    check("sage")
    return sage(
        source,
        {"n": n,"m": m,"r": r,"N": N,"C": [[int(value) for value in row] for row in C],"scale_bits": scale_bits},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    )
def CVP(B=[],target=[],B_path=None,target_path=None,):
    if (B is None or B == []) and B_path is not None:
        B = read_matrix(B_path)
    if (target is None or target == []) and target_path is not None:
        target = read_matrix(target_path)
    target=_flatten_vector(target,"target")
    source=r"""
from sage.all import IntegerLattice, Matrix, ZZ, vector
B = Matrix(ZZ, request["B"])
target = vector(ZZ, request["target"])
if B.ncols() != len(target):
    raise ValueError("target 的长度必须等于 B 的列数")
if B.rank() != B.nrows():
    raise ValueError("B 的行向量必须线性无关")
lattice = IntegerLattice(B, lll_reduce=True)
closest = vector(ZZ, lattice.closest_vector(target))
difference = target - closest
coefficients = B.solve_left(closest)
result = {
    "closest_vector": [int(value) for value in closest],
    "difference": [int(value) for value in difference],
    "coefficients": [int(value) for value in coefficients],
    "distance_squared": int(sum(value * value for value in difference)),
}
"""
    check("sage")
    return sage(
        source,
        {"B": B,"target": target,},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    )
def HNP_ECDSA_nonce(q,pubx,puby,leak,data=[],data_path=None,):
    if (data is None or data == []) and data_path is not None:
        data = read_matrix(data_path)
    source=r"""
from sage.all import EllipticCurve, GF, Matrix, ZZ

q = ZZ(request["q"])
pubx = ZZ(request["pubx"])
puby = ZZ(request["puby"])
B = ZZ(1) << ZZ(request["leak"])
data = request["data"]
A = []
C = []
for h, r, s, b in data:
    h, r, s, b = map(ZZ, (h, r, s, b))
    if not r or not s:
        raise ValueError("r 和 s 不能为零")
    s_inv = s.inverse_mod(q)
    A.append((r * s_inv) % q)
    C.append(((-b * s) * s_inv) % q)
n = len(data)
M = Matrix(ZZ, n + 2, n + 2)
for i in range(n):
    M[i, i] = q
    M[n, i] = A[i]
    M[n + 1, i] = C[i]
M[n, n] = B
M[n + 1, n + 1] = 1
reduced = M.LLL()
candidates = []
for row in reduced.rows():
    last = ZZ(row[-1])
    if abs(last) != 1:
        continue
    value = ZZ(row[-2]) * last
    if value % B:
        continue
    candidate = (value // B) % q
    if candidate not in candidates:
        candidates.append(candidate)
field_modulus = ZZ("0xffffffffffffffffffffffffffffffff7fffffff")
curve = EllipticCurve(GF(field_modulus),[field_modulus - 3,ZZ("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45")])
P = curve(ZZ("0x4a96b5688ef573284664698968c38bb913cbfc82"),ZZ("0x23a628553168947d59dcc912042351377ac5fb32"))
Q = curve(pubx, puby)
for candidate in candidates:
    if candidate * P == Q:
        result = int(candidate)
        break
else:
    raise ValueError("HNP 未找到可验证的私钥候选")
"""
    check("sage")
    return int(
        sage(
            source,
            {"q": q,"pubx": pubx,"puby": puby,"leak": leak,"data": [[int(value) for value in item] for item in data]},
            config_path=SAGE_CONFIG,
            timeout=300,
            show_status=False,
        )
    )
def HNP_LCG_state_low(m,a,b,bits,c=[],c_path=None,):
    if (c is None or c == []) and c_path is not None:
        c = read_matrix(c_path)
    c = _flatten_vector(c, "c")
    source=r"""
from sage.all import Matrix, ZZ, gcd
m = ZZ(request["m"])
a = ZZ(request["a"])
b = ZZ(request["b"])
bits = ZZ(request["bits"])
c = [ZZ(value) for value in request["c"]]
n = len(c)
if gcd(a, m) != 1:
    raise ValueError("构造需要 gcd(a, m) = 1")
ge = [[ZZ(0)] * (n + 1) for _ in range(n + 1)]
for i in range(n - 1):
    ge[i][i] = m
ge[-2][-2] = 1
ge[-1][-1] = 1
ge[-2][0] = a
ge[-1][0] = a * (c[0] << bits) + b - (c[1] << bits)
for i in range(1, n - 1):
    ge[-2][i] = a ** (n - 1)
    ge[-1][i] = (ge[-1][i - 1] * a+ a * (c[i] << bits)+ b- (c[i + 1] << bits))
reduced = Matrix(ZZ, ge).LLL()
seed = None
state0 = None
for row in reduced.rows():
    if abs(ZZ(row[-1])) != 1:
        continue
    low = ZZ(row[-2]) * ZZ(row[-1])
    candidate_state = low + (c[0] << bits)
    if not 0 <= candidate_state < m:
        continue
    candidate_seed = ((candidate_state - b) * a.inverse_mod(m)) % m
    state = candidate_seed
    valid = True
    for observed in c:
        if state >> bits != observed:
            valid = False
            break
        state = (a * state + b) % m
    if valid:
        seed = candidate_seed
        state0 = candidate_state
        break
if seed is None:
    raise ValueError("未找到可验证的 seed")
result = {"seed": int(seed), "state": int(state0)}
"""
    check("sage")
    return sage(
        source,
        {"m": m,"a": a,"b": b,"bits": bits,"c": [int(value) for value in c]},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    )
def HNP_LCG_state_recurrence(m,c=[],c_path=None,):
    if (c is None or c == []) and c_path is not None:
        c = read_matrix(c_path)
    c = _flatten_vector(c, "c")
    source=r"""
from sage.all import ZZ, gcd
m = ZZ(request["m"])
c = [ZZ(value) % m for value in request["c"]]
if gcd(c[0], m) != 1:
    raise ValueError("c[0] 与 m 不互素，无法直接求 multiplier")
a = (c[1] * c[0].inverse_mod(m)) % m
if any(c[i + 1] != a * c[i] % m for i in range(len(c) - 1)):
    raise ValueError("输入序列不是同一乘法递推序列")
seed = (c[0] * a.inverse_mod(m)) % m
result = {"multiplier": int(a), "seed": int(seed)}
"""
    check("sage")
    return sage(
        source,
        {"m": m, "c": [int(value) for value in c]},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    )
def HSSP(n,m,M,h=[],h_path=None,):
    if (h is None or h == []) and h_path is not None:
        h = read_matrix(h_path)
    h = _flatten_vector(h, "h")
    n, m, M = int(n), int(m), int(M)
    source=r"""
from sage.all import Matrix, QQ, ZZ, Zmod, matrix, vector
n = ZZ(request["n"])
m = ZZ(request["m"])
modulus = ZZ(request["M"])
h = vector(ZZ, request["h"])
if h[0].gcd(modulus) != 1:
    raise ValueError("h[0] 与 M 不互素")
ge1 = Matrix(ZZ, m, m)
tmp = h[0].inverse_mod(modulus)
for i in range(1, m):
    ge1[i, 0] = -h[i] * tmp
    ge1[i, i] = 1
ge1[0, 0] = modulus
L1 = ge1.BKZ()
Lx = Matrix(ZZ, L1[:m - n, :])
Lx = Matrix(ZZ,Lx.right_kernel(algorithm="pari").basis_matrix(),)
one = matrix(ZZ, 1, m, [1] * m)
B = one.stack(2 * Lx)
L2 = B.BKZ()
space = Lx.row_space()
one_vector = vector(ZZ, [1] * m)
zero_vector = vector(ZZ, [0] * m)
rows = []
for row in L2.rows():
    if not all(int(value) in (-1, 1) for value in row):
        continue
    candidate = vector(
        ZZ,
        [(int(value) + 1) // 2 for value in row],
    )
    if candidate not in space:
        candidate = one_vector - candidate
    if candidate not in space or candidate == zero_vector:
        continue
    if candidate not in rows:
        rows.append(candidate)
    if len(rows) == n:
        break
if len(rows) != n:
    raise ValueError("HSSP 未找到足够的二值向量")
A = matrix(Zmod(modulus), rows)
vh = vector(Zmod(modulus), h)
a = A.solve_left(vh)
result = {
    "A": [[int(value) for value in row] for row in A.rows()],
    "a": [int(value) for value in a],
}
"""
    check("sage")
    return sage(
        source,
        {"n": n, "m": m, "M": M, "h": [int(value) for value in h]},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    )
def LWE(q,secret_bound,error_bound,M,data=[],A_path=None,b_path=None,):
    if (data is None or data == []) and (A_path is not None or b_path is not None):
        if A_path is None or b_path is None:
            raise ValueError("LWE 必须同时指定 A_path 和 b_path")
        data = {"A": read_matrix(A_path),"b": read_matrix(b_path)}
    A, b = data["A"], _flatten_vector(data["b"], "b")
    q, secret_bound, error_bound, M = (int(q),int(secret_bound),int(error_bound),int(M))
    source=r"""
from sage.all import Matrix, ZZ, vector, zero_matrix
q = ZZ(request["q"])
s_bound = ZZ(request["secret_bound"])
e_bound = ZZ(request["error_bound"])
embedding = ZZ(request["M"])
A = Matrix(ZZ, request["A"])
b = vector(ZZ, request["b"])
m = A.nrows()
n = A.ncols()
B = zero_matrix(ZZ, m + n + 1, m + n + 1)
for i in range(m):
    B[i, i] = q
for i in range(n):
    for j in range(m):
        B[m + i, j] = A[j, i]
    B[m + i, m + i] = 1
for j in range(m):
    B[m + n, j] = b[j]
B[m + n, m + n] = embedding
def centered(value):
    return (ZZ(value) + q // 2) % q - q // 2
result = None
for row in B.LLL().rows():
    last = ZZ(row[-1])
    if abs(last) != embedding:
        continue
    direction = -last // embedding
    s = vector(ZZ,[direction * ZZ(row[m + i]) for i in range(n)])
    if any(abs(value) > s_bound for value in s):
        continue
    e = vector(ZZ,[centered(b[i] - sum(A[i, j] * s[j] for j in range(n)))for i in range(m)])
    if any(abs(value) > e_bound for value in e):
        continue
    result = {"s": [int(value) for value in s],"e": [int(value) for value in e]}
    break
if result is None:
    raise ValueError("未找到满足边界")
"""
    check("sage")
    return sage(
        source,
        {"q": q,"secret_bound": secret_bound,"error_bound": error_bound,"M": M,"A": [[int(value) for value in row] for row in A],"b": [int(value) for value in b]},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    )
def AHSSP(h=[],e=[],n=None,m=None,p=None,h_path=None,e_path=None):
    if (h is None or h == []) and h_path is not None:
        h = read_matrix(h_path)
    if (e is None or e == []) and e_path is not None:
        e = read_matrix(e_path)
    h = _flatten_vector(h, "h")
    e = _flatten_vector(e, "e")
    n, m, p = int(n), int(m), int(p)
    source=r"""
from sage.all import Matrix, QQ, ZZ, Zmod, block_matrix, identity_matrix
from sage.all import matrix, vector, zero_matrix
h = vector(ZZ, request["h"])
e = vector(ZZ, request["e"])
n = ZZ(request["n"])
m = ZZ(request["m"])
p = ZZ(request["p"])
tmp = block_matrix([[h.column(), e.column()]])
Ge = block_matrix([[tmp, identity_matrix(ZZ, m)],[p * identity_matrix(ZZ, 2), zero_matrix(ZZ, 2, m)],])
L = Ge.BKZ()
orthogonal_dimension = m - n - 1
orthogonal_rows = []
for row in L.rows():
    if row[0] != 0 or row[1] != 0:
        continue
    candidate = vector(ZZ, row[2:])
    trial = orthogonal_rows + [candidate]
    if Matrix(QQ, trial).rank() > len(orthogonal_rows):
        orthogonal_rows.append(candidate)
    if len(orthogonal_rows) == orthogonal_dimension:
        break
M = matrix(ZZ, orthogonal_rows)
A_space = M.right_kernel(algorithm="pari").basis_matrix()
if A_space.nrows() != n + 1:
    raise ValueError("AHSSP 恢复空间维度错误")
one_row = matrix(ZZ, 1, m, [1] * m)
B = (-one_row).stack(2 * A_space)
L = B.BKZ()
space = A_space.row_space()
one = vector(ZZ, [1] * m)
zero = vector(ZZ, [0] * m)
e_is_binary = all(int(value) in (0, 1) for value in e)
A_rows = []
for row in L.rows():
    if not all(int(value) in (-1, 1) for value in row):
        continue
    candidate = vector(
        ZZ,
        [(int(value) + 1) // 2 for value in row],
    )
    if candidate not in space:
        candidate = one - candidate
    if candidate not in space or candidate == zero or candidate == one:
        continue
    if e_is_binary and (candidate == e or candidate == one - e):
        continue
    if candidate in A_rows:
        continue
    if Matrix(QQ, A_rows + [candidate]).rank() > len(A_rows):
        A_rows.append(candidate)
    if len(A_rows) == n:
        break
if len(A_rows) != n:
    raise ValueError("AHSSP 未找到足够的 A 行")
F = Zmod(p)
A = matrix(F, A_rows)
vh = vector(F, h)
ve = vector(F, e)
E_lattice = block_matrix([[e.column(), identity_matrix(ZZ, m)],[matrix(ZZ, 1, 1, [p]), zero_matrix(ZZ, 1, m)],])
E_lattice[:, :1] *= p
E_lattice = E_lattice.LLL()
e_kernel_rows = [vector(ZZ, row[1:])for row in E_lattice.rows()if row[0] == 0]
E_kernel_mod = matrix(F, e_kernel_rows)
a = (A * E_kernel_mod.transpose()).solve_left(vh * E_kernel_mod.transpose())
s_vector = matrix(F, [ve]).solve_left(a * A - vh)
s = s_vector[0]
result = {
    "A": [[int(value) for value in row] for row in A.rows()],
    "a": [int(value) for value in a],
    "s": int(s),
}
"""
    check("sage")
    return sage(
        source,
        {"h": [int(value) for value in h],"e": [int(value) for value in e],"n": n,"m": m,"p":p},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    )
def NTRU(N,p,q,f=[],g=[],r=[],message=[],ciphertext=[],h=[],message_bound=1,f_path=None,g_path=None,r_path=None,message_path=None,ciphertext_path=None,h_path=None):
    N, p, q, message_bound = (int(N),int(p),int(q),int(message_bound))
    def as_list(value, name):
        if value is None or value == []:
            return []
        if isinstance(value, bytes):
            value = list(value)
        value = _flatten_vector(value, name)
        return value
    def load_vector(value, path, name):
        if (value is None or value == []) and path is not None:
            value = read_matrix(path)
        return as_list(value, name)
    f = load_vector(f, f_path, "f")
    g = load_vector(g, g_path, "g")
    r = load_vector(r, r_path, "r")
    message = load_vector(message, message_path, "message")
    ciphertext = load_vector(ciphertext, ciphertext_path, "ciphertext")
    h = load_vector(h, h_path, "h")
    if not h and (not f or not g):
        raise ValueError("请提供 h，或同时提供 f 和 g")
    if (r and not message) or (message and not r):
        raise ValueError("r 和 message 必须同时提供")
    source=r"""
from sage.all import PolynomialRing, ZZ, Zmod, identity_matrix, matrix
N = ZZ(request["N"])
p = ZZ(request["p"])
q = ZZ(request["q"])
message_bound = ZZ(request["message_bound"])
f = [ZZ(value) for value in request["f"]]
g = [ZZ(value) for value in request["g"]]
r = [ZZ(value) for value in request["r"]]
message = [ZZ(value) for value in request["message"]]
ciphertext = [ZZ(value) for value in request["ciphertext"]]
h = [ZZ(value) for value in request["h"]]
def cyclic_mul(a, b, modulus=None):
    result = [ZZ(0)] * N
    for i in range(N):
        for j in range(N):
            result[(i + j) % N] += a[i] * b[j]
    if modulus is not None:
        result = [value % modulus for value in result]
    return result
def centered(values, modulus):
    return [(ZZ(value) + modulus // 2) % modulus - modulus // 2 for value in values]
def polynomial_inverse(values, modulus):
    ring = PolynomialRing(Zmod(modulus), "x")
    x = ring.gen()
    quotient = ring.quotient(x ** N - 1)
    element = quotient(ring([value % modulus for value in values]))
    inverse = element ** (-1)
    coefficients = [ZZ(value) for value in inverse.lift().list()]
    coefficients += [ZZ(0)] * (N - len(coefficients))
    return coefficients[:N]
result = {}
if not h:
    fq = polynomial_inverse(f, q)
    h = cyclic_mul([p * value for value in g], fq, q)
result["h"] = [int(value) for value in h]
if not ciphertext and r and message:
    ciphertext = [(value + message[index]) % q for index, value in enumerate(cyclic_mul(r, h, q))]
if ciphertext:
    result["ciphertext"] = [int(value) for value in ciphertext]
if f and ciphertext:
    fp = polynomial_inverse(f, p)
    a = centered(cyclic_mul(f, ciphertext, q), q)
    normal_message = centered(cyclic_mul(fp, [value % p for value in a], p),p)
    result["decrypted"] = [int(value) for value in normal_message]
if ciphertext and not f:
    H = matrix(ZZ,N,N,lambda i, j: h[(j - i) % N])
    attack_basis = identity_matrix(ZZ, N).augment(H)
    attack_basis = attack_basis.stack(matrix(ZZ, N, N, 0).augment(q * identity_matrix(ZZ, N)))
    attack_basis = attack_basis.LLL()
    attack = None
    for row in attack_basis.rows():
        candidate_f = [ZZ(value) for value in row[:N]]
        candidate_pg = [ZZ(value) for value in row[N:]]
        if any(value % p for value in candidate_pg):
            continue
        try:
            candidate_fp = polynomial_inverse(candidate_f, p)
        except Exception:
            continue
        candidate_a = centered(
            cyclic_mul(candidate_f, ciphertext, q),
            q,
        )
        candidate_message = centered(
            cyclic_mul(candidate_fp,[value % p for value in candidate_a],p),p)
        if all(abs(value) <= message_bound for value in candidate_message):
            attack = {"f": [int(value) for value in candidate_f],"p_times_g": [int(value) for value in candidate_pg],"message": [int(value) for value in candidate_message]}
            break
    result["attack"] = attack
"""
    check("sage")
    return sage(
        source,
        {"N": N,"p": p,"q": q,"f": f,"g": g,"r": r,"message": message,"ciphertext": ciphertext,"h": h,"message_bound": message_bound},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    )
def NTRU_component(N,p,q,f=[],g=[],r=[],message=[],ciphertext=[],h=[],f_path=None,g_path=None,r_path=None,message_path=None,ciphertext_path=None,h_path=None,message_bound=1):
    return NTRU(N,p,q,f=f,g=g,r=r,message=message,ciphertext=ciphertext,h=h,f_path=f_path,g_path=g_path,r_path=r_path,message_path=message_path,ciphertext_path=ciphertext_path,h_path=h_path,message_bound=message_bound)
def ACD(x=[],lam=200,error_bound=None,x_path=None):
    if (x is None or x == []) and x_path is not None:
        x = read_matrix(x_path)
    x = _flatten_vector(x, "x")
    source=r"""
from sage.all import ZZ, zero_matrix
x = [ZZ(value) for value in request["x"]]
lam = ZZ(request["lam"])
error_bound = request.get("error_bound")
if error_bound is not None:
    error_bound = ZZ(error_bound)
count = len(x)
scale = ZZ(1) << lam
B = zero_matrix(ZZ, count, count)
B[0, 0] = scale
for index in range(1, count):
    B[0, index] = x[index]
    B[index, index] = -x[0]
def nearest_dividend(value, divisor):
    if value >= 0:
        return (value + divisor // 2) // divisor
    return -((-value + divisor // 2) // divisor)
candidates = []
for row in B.LLL().rows():
    if row[0] == 0 or row[0] % scale:
        continue
    quotient0 = abs(row[0] // scale)
    if quotient0 == 0:
        continue
    p_candidate = nearest_dividend(x[0], quotient0)
    if p_candidate <= 1:
        continue
    quotients = [nearest_dividend(value, p_candidate) for value in x]
    remainders = [
        x[index] - quotients[index] * p_candidate
        for index in range(count)
    ]
    maximum = max(abs(value) for value in remainders)
    if error_bound is not None and maximum > error_bound:
        continue
    candidates.append({
        "p": int(p_candidate),
        "quotients": [int(value) for value in quotients],
        "remainders": [int(value) for value in remainders],
        "max_error": int(maximum),
        "short_vector": [int(value) for value in row],
    })
if not candidates:
    raise ValueError("调整 lam 或 error_bound")
result = min(candidates, key=lambda item: item["max_error"])
"""
    check("sage")
    return sage(
        source,
        {"x": x,"lam": lam,"error_bound": error_bound},
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    )
def GGH_Nguyen(B=[],C=[],n=None,delta=1,B_path=None,C_path=None):
    if (B is None or B == []) and B_path is not None:
        B = read_matrix(B_path)
    if (C is None or C == []) and C_path is not None:
        C = read_matrix(C_path)
    C = _flatten_vector(C, "C")
    if n is None:
        n = len(B)
    n, delta = int(n), int(delta)
    B = [[int(value) for value in row] for row in B]
    C = [int(value) for value in C]
    source=r"""
from sage.all import ZZ, Zmod, matrix, vector
n = ZZ(request["n"])
delta = ZZ(request["delta"])
B = matrix(ZZ, request["B"])
C = vector(ZZ, request["C"])
shift = vector(ZZ, [delta] * n)
B_mod = B.change_ring(Zmod(2 * delta))
low = B_mod.solve_left((C + shift).change_ring(Zmod(2 * delta)))
low = vector(ZZ, [ZZ(value) for value in low])
residual = C - vector(ZZ, [sum(low[j] * B[j, i] for j in range(n))for i in range(n)])
if any(value % delta for value in residual):
    raise ValueError("GGH 模 2delta 恢复失败")
new_c = vector(ZZ, [value // delta for value in residual])
embedding = matrix(ZZ, n + 1, n + 1)
for i in range(n):
    for j in range(n):
        embedding[i, j] = 2 * B[i, j]
for j in range(n):
    embedding[n, j] = new_c[j]
embedding[n, n] = 1
candidates = []
for row in embedding.BKZ().rows():
    shortest = vector(ZZ, row)
    rhs = vector(ZZ, [new_c[i] - shortest[i] for i in range(n)])
    try:
        middle = (2 * B).solve_left(rhs)
    except Exception:
        continue
    if any(value not in ZZ for value in middle):
        continue
    middle = vector(ZZ, middle)
    message = vector(ZZ,[2 * delta * middle[i] + low[i] for i in range(n)])
    error = C - message * B
    if all(abs(value) <= delta for value in error):
        candidates.append({"message": [int(value) for value in message],"error": [int(value) for value in error],"low": [int(value) for value in low],"short_vector": [int(value) for value in shortest]})
if not candidates:
    raise ValueError("GGH Nguyen 未找到满足误差边界的候选")
result = candidates[0]
"""
    check("sage")
    return sage(
        source,
        {"B": B,"C": C,"n": n,"delta": delta
        },
        config_path=SAGE_CONFIG,
        timeout=300,
        show_status=False,
    )


