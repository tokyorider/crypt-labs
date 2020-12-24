import grasshopper_consts as consts


def xor(block1, block2):
    return [byte1 ^ byte2 for byte1, byte2 in zip(block1, block2)]

#Нелинейное преобразование
def nl_transform(block):
    return list(map(lambda byte: consts.NLT_TABLE[byte], block))

#Обратное нелинейное преобразование
def nl_transform_inv(block):
    return list(map(lambda byte: consts.NLT_TABL_INV[byte], block))

#Линейное преобразование
def linear_transform(block):
    transformed_block = block

    for i in range(len(block)):
        transformed_block = shift(transformed_block)

    return transformed_block

#Сдвиг блока и вычисление элемента в младшей разряде - операция, применяемая при линейном преобразовании
def shift(block):
    shifted_block = list(range(len(block)))
    an = 0

    for i in range(len(block) - 1, 0, -1):
        shifted_block[(i - 1) % len(block)] = block[i]
        an ^= gf_mul(block[i], consts.LT_VECTOR[i])
    shifted_block[len(block) - 1] = an ^ gf_mul(block[0], consts.LT_VECTOR[0])

    return shifted_block

#Обратное линейное преобразование
def linear_transform_inv(block):
    transformed_block = block

    for i in range(len(block)):
        transformed_block = shift_inv(transformed_block)

    return transformed_block

#Операция, обратная сдвигу
def shift_inv(block):
    shifted_block = list(range(len(block)))
    a0 = block[len(block) - 1]

    for i in range(1, len(block)):
        shifted_block[i] = block[i - 1]
        a0 ^= gf_mul(shifted_block[i], consts.LT_VECTOR[i])
    shifted_block[0] = a0

    return shifted_block

#Умножение двух чисел в поле Галуа над предопределенным многочленом
def gf_mul(a, b):
    c = 0

    while b != 0:
        if b & 1 != 0:
            c ^= a
        a = (a << 1) ^ (consts.BASE_POLYNOM if a & 0x80 else 0x00)
        b >>= 1

    return c % 256

#Вычисляем константы, применяемые при рассчете ключей
iter_consts = [linear_transform([i] + [0] * 15) for i in range(1, 33)]

#Вычисления ячейки Фейстеля - операция, применяемая при рассчете ключей
def compute_feistel_cell(key1, key2, c):
    return (xor(linear_transform(nl_transform(xor(key1, c))), key2), key1)

#Рассчет всех 10 ключей на основе первых двух
def expand_keys(key1, key2):
    keys = [key1, key2]

    for i in range(4):
        #Каждые новые два ключа считаем на основе двух предыдущих
        new_keys = keys[i * 2:i * 2 + 2:]

        for j in range(8):
            new_keys = compute_feistel_cell(new_keys[0], new_keys[1], iter_consts[i * 8 + j])
        keys += new_keys

    return keys

keys = expand_keys(consts.KEY_1, consts.KEY_2)

def grasshopper_encrypt(block):
    encrypted_block = block
    
    #Совершаем 9 полных итераций преобразования и одну неполную
    for i in range(9):
        encrypted_block = linear_transform(nl_transform(xor(keys[i], encrypted_block)))
    encrypted_block = xor(keys[9], encrypted_block)

    return encrypted_block

def grasshopper_decrypt(block):
    decrypted_block = block

    decrypted_block = xor(keys[9], decrypted_block)
    for i in range(8, -1, -1):
        decrypted_block = xor(keys[i], nl_transform_inv(linear_transform_inv(decrypted_block)))

    return decrypted_block

#Итоговый хеш сообщения считается путем применения операций, сходных операциям при кодировании для блока и дальнейшего 
#xor блока с уже получившимся хешем. Размер блока при подсчете хеша - 64 бита
def compute_partial_hash(prev_hash, block):
    partial_hash = prev_hash

    for i in range(5):
        block = linear_transform(nl_transform(xor(keys[i], block)))
    partial_hash = xor(prev_hash, block)

    return partial_hash

#Тест совпадения изначального текста, и текста полученного при декодировании закодированного текста
with open("test.txt", "rb") as i, open("encoded_text.txt", "wb") as o:
    message = i.read()
    splitted_message = [list(message[i:i + 16]) for i in range(0, len(message), 16)]

    for block in splitted_message:
        o.write(bytes(grasshopper_encrypt(block)))

with open("encoded_text.txt", "rb") as i, open("decoded_text.txt", "wb") as o:
    message = i.read()
    splitted_message = [list(message[i:i + 16]) for i in range(0, len(message), 16)]

    for block in splitted_message:
        o.write(bytes(grasshopper_decrypt(block)))

#Сравниваем содержимое изначального файла и файла, получившевогося в результате расшифрования
with open("test.txt", "rb") as origin, open("decoded_text.txt", "rb") as decoded:
    print(origin.read() == decoded.read())

#Тест на различие хешей(файлы отличаются на один символ)
with open("test.txt", "rb") as i1, open("test2.txt", "rb") as i2:
    message1, message2 = i1.read(), i2.read()
    splitted_message1 = [list(message1[i:i + 8]) for i in range(0, len(message1), 8)]
    splitted_message2 = [list(message2[i:i + 8]) for i in range(0, len(message2), 8)]

    hash1, hash2 = [0] * 8, [0] * 8
    for block in splitted_message1:
        hash1 = compute_partial_hash(hash1, block)
    for block in splitted_message2:
        hash2 = compute_partial_hash(hash2, block)

    print(hash1 == hash2)

#Тест на совпаденией хешей для идентичных файлов
with open("test.txt", "rb") as i1, open("decoded_text.txt", "rb") as i2:
    message1, message2 = i1.read(), i2.read()
    splitted_message1 = [list(message1[i:i + 8]) for i in range(0, len(message1), 8)]
    splitted_message2 = [list(message2[i:i + 8]) for i in range(0, len(message2), 8)]

    hash1, hash2 = [0] * 8, [0] * 8
    for block in splitted_message1:
        hash1 = compute_partial_hash(hash1, block)
    for block in splitted_message2:
        hash2 = compute_partial_hash(hash2, block)

    print(hash1 == hash2)

