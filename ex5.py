from Crypto.Cipher import AES

def xor_bytes(byte1, byte2):
    xor_result = bytearray(byte1)
    for i, b in enumerate(byte2):
        xor_result[i] ^= b        
    return bytes(xor_result)

def cbc_custom_decrypt(k, n, cipher):
    aes=AES.new(k,AES.MODE_ECB)
    plaintext=xor_bytes(aes.decrypt(cipher[16:32]),cipher[0:16]) #first xor for example
    for i in range(2,n+1):
        plaintext+=xor_bytes(aes.decrypt(cipher[ i*16 : (i+1)*16 ]), cipher[ (i-1)*16 : i*16 ])
    return plaintext    


def Check_index(byte1):
    counter=0
    for i in range(1,14):        
         if (byte1[i]!= byte1[i+1] and  byte1[i] !=  byte1[i-1])
            index=i
            counter+=1

    if (i==0 and byte1[0] != byte1[1])
           index=0
           counter+=1  

    if (i==15 and byte1[15] != byte1[14])
           index=15
           counter+=1  

    if (counter==1)
        return index
    else
        return 0            


def cbc_flip_fix(k,n,cipher):
    co_plaintext=cbc_custom_decrypt(k,n,Cipher)
    while not Check_index(co_plaintext[i*16:(i+1)*16]) 
        i+=1
    end while
    index=Check_index(co_plaintext[i*16:(i+1)*16])  #index in next plantext corrupted
    flip_in_one_byte= co_plaintext[i*16:(i+1)*16]   # have one byte corrupted

    original_block_cipher=cipher[i*16:(i+1)*16]      
    byte_mask=xor_bytes(flip_in_one_byte ,original_block_cipher)
    
    corrupted_block=co_plaintext[(i-1)*16:i*16]
    fixed_chiper_block=for i xor_bytes(corrupted_block ,byte_mask)

    fixed_plaintext_block=





if __name__ == "__main__":
    
    key = b"1111111111111111"
    iv = b"2222222222222222"
    message = b"hello hello hello wow GGG TTT rrr DDD SSS H H H $$#$%^TREW111111"
    aes = AES.new(key, AES.MODE_CBC, iv)
    print("b1")
    cipher = aes.encrypt(message)
    print("b2")
    print(f'Message: {message}\nKey: {key}\nIV: {iv}\nCipher: {cipher}')
    try:
        print(f"Decryption: {cbc_custom_decrypt(key, 4, iv + cipher)}")
    except IndexError as err:
        print(f"ERROR: {err}")
        pass

    
