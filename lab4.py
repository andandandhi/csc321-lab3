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
    for i in word_list:
        if checkpw(i.encode('utf-8'), b"$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq"):
            print("Found!")
            print(i)
            new_time = datetime.datetime.now()
            print("Total time: ", new_time - og_time)
