DIVISION_MODULE = (1 << 32)

KEY = [0x53, 0x01, 0xac, 0xbb, 0xb5, 0x7a, 0x99, 0xae]

NONCE = [0xbd, 0x86]

#Левый циклический сдвиг
def lcs(number, bits_count):
    return (number << bits_count | number >> (32 - bits_count)) % DIVISION_MODULE

#Операция по представлению числа в другой endian записи
def change_endian(number):
    return ((number << 24) & 0xff000000 | (number << 8) & 0x00ff0000 | (number >> 8) & 0x0000ff00 | (number >> 24) & 0x000000ff) % DIVISION_MODULE

def quarter_round(words):
    z = list(range(4))
    z[1] = (words[1] ^ lcs((words[0] + words[3]) % DIVISION_MODULE, 7)) % DIVISION_MODULE
    z[2] = (words[2] ^ lcs((z[1] + words[0]) % DIVISION_MODULE, 9)) % DIVISION_MODULE
    z[3] = (words[3] ^ lcs((z[2] + z[1]) % DIVISION_MODULE, 13)) % DIVISION_MODULE
    z[0] = (words[0] ^ lcs((z[3] + z[2]) % DIVISION_MODULE, 18)) % DIVISION_MODULE

    return z

#Данная функция производит оборот либо по строкам, либо по столбцам, в зависимости от переданной функции индексов
def round(words, indices_function):
    z = list(range(16))
    for i in range(4):
        indices = indices_function(i)
        qr = quarter_round([words[j] for j in indices])
        for k in range(4):
            z[indices[k]] = qr[k]

    return z

def row_indices(i):
    return (i * 4 + i, i * 4 + (i + 1) % 4, i * 4 + (i + 2) % 4, i * 4 + (i + 3) % 4)

def column_indices(i):
    return (i + (i * 4), i + ((i + 1) % 4) * 4, i + ((i + 2) % 4) * 4, i + ((i + 3) % 4) * 4)

#Данная функция производит сначала оборот по столбцам, а потом по строкам
def double_round(words):
    return round(round(words, column_indices), row_indices)

#Собственно алгоритм шифрования блока ключа
def salsa20(words):
    words = list(map(change_endian, words))
    dr = words
    for i in range(10):
        dr = double_round(dr)

    return [change_endian((words[i] + dr[i])) for i in range(16)]

#Формирование блока ключа для дальнейшего шифрования
def salsa20_key_stream(key, nonce, pos):
    key_stream = list(range(16))

    #Предопределенные константы - "expa", "nd 3", "2-by", "te k"
    sigma = [0x65787061, 0x6e642033, 0x322d6279, 0x7465206b]
    for i in range(4):
        key_stream[i * 5] = sigma[i]

    #Уникальный идентификатор сообщения
    for i in range(2):
        key_stream[6 + i] = nonce[i]

    #Номер блока в сообщении
    for i in range(2):
        key_stream[8 + i] = pos[i]

    #Собственно ключ
    for i in range(4):
        key_stream[1 + i] = key[i]
        key_stream[11 + i] = key[4 + i]

    return salsa20(key_stream)

def salsa20_encrypt(s, key, nonce):
    key_stream = salsa20_key_stream(key, nonce, [0] * 2)
    crypted_string = s
    
    for i in range(len(s)):
        if (i % 64 == 0):
            #Позиция по формату записывается по little-endian формату и может занимать до 64 бит, а слова 
            #в Salsa состоят из 32 бит, поэтому пришлось раздеять
            pos = [change_endian((i // 64) >> 32), change_endian((i // 64) % DIVISION_MODULE)]
            key_stream = salsa20_key_stream(key, nonce, pos)

        #Поочереденый xor исходного текста с ключем
        c = chr(ord(s[i]) ^ get_byte(key_stream[((i % 64) // 4)], i % 4))
        crypted_string = "".join((crypted_string[:i], c, crypted_string[i + 1:]))

    return crypted_string

#Функция, получающая отдельный байт из 32-битного слова
def get_byte(number, pos):
    return (number & (0xff << (8 * (3 - pos)))) >> (8 * (3 - pos))

message = input("Введите строку для шифрования")
crypted_message = salsa20_encrypt(message, KEY, NONCE)
decrypted_message = salsa20_encrypt(crypted_message, KEY, NONCE)
print(decrypted_message)
