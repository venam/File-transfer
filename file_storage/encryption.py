#encryption.py
def _xor(a,b): return a^b

def _not(a,b): return _xor(a,0b11111111)

_ror = lambda val, r_bits: \
    ((val & (2**8-1)) >> r_bits%8) | (val << (8-(r_bits%8)) & (2**8-1))

_rol = lambda val, r_bits: \
    (val << r_bits%8) & (2**8-1) | ((val & (2**8-1)) >> (8-(r_bits%8)))

# This is dumb - encryption can only be done with rol ror xor,
# nothing else will work
#TODO: clean this and make it simpler
enc_meth = {
    '^': _xor,
    '~': _not,
    'ror': _ror,
    'rol': _rol
}

def create_lambda(op, val): return lambda x: op(x,val)

def interpret_enc(encryption_scheme):
    enc = []
    parts = encryption_scheme.split(";")
    for part in parts:
        ops =  part.split(":")
        for x in range(int(ops[1])):
            if ops[0][0] in enc_meth.keys():
                if ops[0][0] == "~":
                    enc.append(create_lambda(enc_meth[ops[0][0]], 0))
                else:
                    enc.append(create_lambda(enc_meth[ops[0][0]], int(ops[0][1:])))
            elif ops[0][0:3] in enc_meth.keys():
                enc.append(create_lambda(enc_meth[ops[0][0:3]], int(ops[0][3:])))
    return enc

def interpret_dec(encryption_scheme):
    dec = []
    parts = encryption_scheme.split(";")
    for part in parts:
        ops =  part.split(":")
        for x in range(int(ops[1])):
            if ops[0][0] == '^':
                dec.append(create_lambda(enc_meth[ops[0][0]], int(ops[0][1:]) ))
            elif ops[0][0] == '~':
                dec.append(create_lambda(enc_meth[ops[0][0]], 0))
            elif ops[0][0:3] == 'ror':
                dec.append(create_lambda(enc_meth['rol'], int(ops[0][3:]) ))
            elif ops[0][0:3] == 'rol':
                dec.append(create_lambda(enc_meth['ror'], int(ops[0][3:]) ))
    return dec

# Assuming all operations are done on bytes
def encrypt(message, encryption_scheme):
    encrypted = bytearray()
    enc_operations = interpret_enc(encryption_scheme)
    i = 0
    for m in message:
        i %= len(enc_operations)
        encrypted.append(enc_operations[i](m))
        i += 1
    return encrypted

def decrypt(message, encryption_scheme):
    decrypted = bytearray()
    dec_operations = interpret_dec(encryption_scheme)
    i = 0
    for m in message:
        i %= len(dec_operations)
        decrypted.append(dec_operations[i](m))
        i += 1
    return decrypted

