from bcrypt import *
import nltk

nltk.download('words')
from nltk.corpus import words
import datetime

if __name__ == "__main__":
    og_time = datetime.datetime.now()
    new_time = datetime.datetime.now()
    word_list = words.words()
    word_list = [word for word in word_list if 6 <= len(word) <= 10]
    not_1 = 1
    not_2 = 1
    not_3 = 1
    for i in word_list:
        new_hash = hashpw(i.encode('utf-8'), b"$2b$11$/8UByex2ktrWATZOBLZ0Du")  # same salt
        if not_1 and new_hash == b"$2b$11$/8UByex2ktrWATZOBLZ0DuAXTQl4mWX1hfSjliCvFfGH7w1tX5/3q":  # first hash
            print("Found 1!")
            print(i)
            new_time = datetime.datetime.now()
            print("Total time: ", new_time - og_time)
            not_1 = 0
        if not_2 and new_hash == b"$2b$11$/8UByex2ktrWATZOBLZ0Dub5AmZeqtn7kv/3NCWBrDaRCFahGYyiq":  # second hash
            print("Found 2!")
            print(i)
            new_time = datetime.datetime.now()
            print("Total time: ", new_time - og_time)
            not_2 = 0
        if not_3 and new_hash == b"$2b$11$/8UByex2ktrWATZOBLZ0DuER3Ee1GdP6f30TVIXoEhvhQDwghaU12":  # third hash
            print("Found 3!")
            print(i)
            new_time = datetime.datetime.now()
            print("Total time: ", new_time - og_time)
            not_3 = 0

        if not not_1 and not not_2 and not not_3:
            break
