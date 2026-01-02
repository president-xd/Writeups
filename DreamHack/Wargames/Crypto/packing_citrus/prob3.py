import base64
import string

STD_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
MY_TABLE  = STD_TABLE[::-1]

def truck(data):
    encoded = base64.b64encode(data).decode()
    trans_table = str.maketrans(STD_TABLE, MY_TABLE)
    return encoded.translate(trans_table)