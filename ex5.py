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



testsing_dict_decrypt = [{
        "key": b"1111111111111111",
        "iv": b"2222222222222222",
        "plain": [b"hello to you!, task completed!!!", b"you can make your day abcdefpoqa"],
        "cipher": [b"\xae('\x17\xc0<\xcan%\x83\xdf\xae\xddg\xf3\x864\x97\xa3\xc9\x01\x81a\x9e\x0b\x96\x05\x0f\xc3P\x8b\x06",
                   b'\x11\xb3\x8e\xb3,/\x92\x01\x9b\x97\x8b\x05\xdd\xa9\xc6\xebl\xbc\x98\xd80p\x10\xf9o\xfc\x89^p\xd1V\x99']
    },
    {
        "key": b"1123411115461190",
        "iv": b"9122622795742201",
        "plain": [b"hello to you!, task completed!!!", b"you can make your day abcdefpoqa"],
        "cipher": [b'\xeb+\xd0\xd2\x04\x9d\x9b\x0c\xe3Dez\xff\x03\xdfd\xa8\x9f{3&5P\x95\xf5\x15*x\xdc!\x978',
                   b'0\x94\x9e6\xb6\xf2+\xaeMyb\x1f\x94\xea\xcd\x84s\x98\x99\xe0\xda`U\x8d6\x91\x1a\x00S\x7f{=']
    }
]
testsing_dict_flipped = [
        {
            "key": b"1234598705461190",
            "iv": b"1234562795743333",
            "description" : [
                "changed the FIRST bit (msb) of the FIRST byte of the FIRST block (bbbbb...)",
                "changed the bit 00000100 [value = 4] of byte #6 of the FIRST block (bbbbb...)",
                "changed the bit 00000001 (lsb [value = 1]) of 16th byte of the last-1 block (fffff..)",
                "changed the bit 00001000 [value = 8] of 3rd byte of the second block (yyyyyy...)"
            ],
            "original_message" : [
                b'bbbbbbbbbbbbbbbbaaaaaaaaaaaaaaaaddddddddddddddddfffffffffffffffftttttttttttttttt', #"changed the FIRST bit (msb) of the FIRST byte of the FIRST block (bbbbb...)"
                b"bbbbbbbbbbbbbbbbaaaaaaaaaaaaaaaaddddddddddddddddfffffffffffffffftttttttttttttttt", #"changed the bit 00000100 [value = 4] of byte #6 of the FIRST block (bbbbb...)"
                b"bbbbbbbbbbbbbbbbyyyyyyyyyyyyyyyyddddddddddddddddffffffffffffffffpppppppppppppppp",#"changed the bit 00000001 (lsb [value = 1]) of 16th byte of the last-1 block (fffff..)"
                b"bbbbbbbbbbbbbbbbyyyyyyyyyyyyyyyyddddddddddddddddffffffffffffffffpppppppppppppppp", #"changed the bit 00001000 [value = 8] of 3rd byte of the second block (yyyyyy...)"
            ],
            "corrupted_message" : [
                b'\xfc\xceU\x1f\xeb[\xc8\xa01\x17\x18\xf3\xc8x\xc2\xf9\xe1aaaaaaaaaaaaaaaddddddddddddddddfffffffffffffffftttttttttttttttt',
                b'\x92\xab\xbe\xed\x1e=\xe9\xd7\xb2\\\xca\xd2\xad\xb6\x8a`aaaaaeaaaaaaaaaaddddddddddddddddfffffffffffffffftttttttttttttttt',
                b'bbbbbbbbbbbbbbbbyyyyyyyyyyyyyyyydddddddddddddddd\x8c\t)8r\x88JfN\xe7\xa8K\x1aZ\x0e\xe1pppppppppppppppq',
                b'bbbbbbbbbbbbbbbb\xa6\xe4\xe9\x05p4\xe4h1\xde\xa5\xa9..I\xe4ddldddddddddddddffffffffffffffffpppppppppppppppp',
            ],
            "corrupted_cipher": [
                b'\x9b\x7f\x9c>H\x97\n\xac\xb0\x06\xd8z\x87\xa5H\xf5.v\x9b\xc9p\x9a\xb9\xaf\x8f\xc4\t\x85>^\xa0\xff\xe3\t\xcf\x9c\xbc\x820\x96\xb1\x0bK[\xd8p\x05\xac\x9ac\xa5\xe1\xd6\xaeRz\x8b\xe3\xd0\xee\xbb\xe36\\\x8a\xacZ\\F\x0e(\x06\x02\x7f\x93Tp_\xd9;',
                b'\x1b\x7f\x9c>H\x93\n\xac\xb0\x06\xd8z\x87\xa5H\xf5.v\x9b\xc9p\x9a\xb9\xaf\x8f\xc4\t\x85>^\xa0\xff\xe3\t\xcf\x9c\xbc\x820\x96\xb1\x0bK[\xd8p\x05\xac\x9ac\xa5\xe1\xd6\xaeRz\x8b\xe3\xd0\xee\xbb\xe36\\\x8a\xacZ\\F\x0e(\x06\x02\x7f\x93Tp_\xd9;',
                b'\x1b\x7f\x9c>H\x97\n\xac\xb0\x06\xd8z\x87\xa5H\xf5\x13)|N\\\xbez\x10n_$\xe5+\x90\x89d+\x8c\xd0\x9e(\xf7,3C\x1e\x84B0\xaa\xd0CP;\x01\x08\x10\x8f\xadW\x1f\xdf\xc7N\xd7\x1b\x1b\x0e8\x96\xb3\xcb\xe1\xcb\x17\xde\xdfNk[\xa2MDV',
                b'\x1b\x7f\x9c>H\x97\n\xac\xb0\x06\xd8z\x87\xa5H\xf5\x13)tN\\\xbez\x10n_$\xe5+\x90\x89d+\x8c\xd0\x9e(\xf7,3C\x1e\x84B0\xaa\xd0CP;\x01\x08\x10\x8f\xadW\x1f\xdf\xc7N\xd7\x1b\x1b\x0f8\x96\xb3\xcb\xe1\xcb\x17\xde\xdfNk[\xa2MDV'
            ],
            "block_to_return": [
                b"bbbbbbbbbbbbbbbb",
                b"bbbbbbbbbbbbbbbb",
                b'ffffffffffffffff',
                b'yyyyyyyyyyyyyyyy'
            ]
        },
    ]



def testing_decrypt(testsing_dict):
    errors = 1
    test_num = 1
    for test in testsing_dict:
        key, iv = test["key"], test["iv"]
        for plain_text, c in zip(test["plain"], test["cipher"]):
            num_of_blocks = len(c) // 16
            my_output = cbc_custom_decrypt(key, num_of_blocks, iv + c)
            if my_output != plain_text:
                print("Error #{} in Test #{}".format(errors, test_num))
                print("in: {}\n\tplain text should be: {}\n\tcipher is: {}\n".format(errors, my_output, plain_text, c))
                errors += 1
            else:
                print("Passed Test #{}".format(test_num))
            test_num+=1
    if errors == 1:
        print("Passed The Test: testing_decrypt")
    else:
        print("Didn't Pass The Test")

def testing_flip(testsing_dict_flipped):
    errors = 1
    test_num = 1
    for test in testsing_dict_flipped:
        key, iv = test["key"], test["iv"]
        answers, ciphers, test_descriptions = test["block_to_return"], test["corrupted_cipher"], test["description"]
        for answer, corrupted_cipher, test_description in zip(answers, ciphers, test_descriptions):
            print("{}:".format(test_description))
            num_of_blocks = len(corrupted_cipher) // 16
            my_output = cbc_flip_fix(key, num_of_blocks, iv + corrupted_cipher)
            if my_output != answer:
                print("Error #{} in Test #{}".format(errors, test_num))
                print("my output: {}\n\toriginal block is: {}\n".format(errors, my_output, answer))
                errors += 1
            else:
                print("Passed Test #{}".format(test_num))
            test_num += 1
            print("")
    if errors == 1:
        print("Passed The Test: testing_flip")
    else:
        print("Didn't Pass The Test: testing_flip")


if __name__ == "__main__":
    testing_decrypt(testsing_dict_decrypt)
    testing_flip(testsing_dict_flipped)

    
