#Ronen,Rozin,318257011
#Python 3.7.7

from Crypto.Cipher import AES

def xor_bytes(byte1, byte2): 
    xor_result = bytearray(byte1)
    for i, b in enumerate(byte2):
        xor_result[i] ^= b        
    return bytes(xor_result)

def cbc_custom_decrypt(k, n, cipher):
    aes=AES.new(k,AES.MODE_ECB)
    plaintext=xor_bytes(aes.decrypt(cipher[16:32]),cipher[0:16]) # initialize
    for i in range(2,n+1):
        plaintext+=xor_bytes(aes.decrypt(cipher[ i*16 : (i+1)*16 ]), cipher[ (i-1)*16 : i*16 ])
    return plaintext    


def get_corrupted_plaintext_byte_index(plaintext):
    index_of_byte = -1

    if (plaintext[0] != plaintext[1] and plaintext[1] == plaintext[2]): # check if the first byte is different from others
        index_of_byte = 0
        return index_of_byte

    for i in range (1,14): # check bytes 2 to 15       
         if (plaintext[i] != plaintext[i+1] and plaintext[i] != plaintext[i-1] and plaintext[i+1] == plaintext[i-1]):
             index_of_byte = i             
             return index_of_byte
        
    if (plaintext[14] != plaintext[15] and plaintext[13] == plaintext[14]): # check last byte
        index_of_byte = 15
        return index_of_byte
    
    return index_of_byte         


def cbc_flip_fix(k, n, cipher):
    aes=AES.new(k,AES.MODE_ECB)
    corrupted_plaintext=cbc_custom_decrypt(k,n,cipher) # get the corrupted text
    i=0
    corrupted_plaintext_byte_index = get_corrupted_plaintext_byte_index(corrupted_plaintext[0:16]) # initialize
    while (corrupted_plaintext_byte_index == -1): # search for plaintext with one different byte (the one next to the corrupted)
        i+=1
        corrupted_plaintext_byte_index = get_corrupted_plaintext_byte_index(corrupted_plaintext[i*16:(i+1)*16])

    fixed_plaintext = bytes([corrupted_plaintext[i*16:(i+1)*16][15-corrupted_plaintext_byte_index]] * 16) # fix plaintext by concatenating the correct byte 16 times

    find_bit = xor_bytes(fixed_plaintext, corrupted_plaintext[i*16:(i+1)*16]) # find the flipped bit by xoring between the corrupted and the correct

    fixed_cipher = xor_bytes(find_bit,cipher[(i)*16:(i+1)*16]) # fix thr corrupted cipher by xoring with the bit we found

    plain_text_to_return = xor_bytes(aes.decrypt(fixed_cipher),cipher[(i-1)*16:i*16]) # decryprion with the fixed inputs
     
    return plain_text_to_return
    