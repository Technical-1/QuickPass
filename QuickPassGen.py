import requests
from threading import Thread
from user_agent import generate_user_agent, generate_navigator
import threading
import random

def passGen(length):
    r3 = requests.get("https://passwordsgenerator.net/calc.php?Length=" + str(length) + "&Symbols=1&Lowercase=1&Uppercase=1&Numbers=1&Nosimilar=1&Last=" + str(random.randint(600,800)))
    print(r3.text[0:int(length)])

def main(passNum, passLength):
    for i in range(passNum):
        t = Thread(target = passGen, args = (passLength,))
        t.start()

numPass = input('How many passwords do you want?')
numLength = input('How long do you want them to be?')

main(int(numPass), int(numLength))
