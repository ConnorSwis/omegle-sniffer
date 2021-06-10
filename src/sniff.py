from pynput import keyboard
import pyshark
import requests
from collections import Counter
import os

BLOCK_LIST = ['192', '76', '31', '104', '24']

capture = pyshark.LiveCapture(
    interface='Ethernet',
    display_filter=f"udp && ip.src_host matches \"^(?!({'|'.join(BLOCK_LIST)})).*\"",
    )


def common(L):
    if len(L) > 0:
        return Counter(L).most_common(1)[0][0]
    return None


def sniff():
    capture.sniff(timeout=1)
    ip = common([packet.ip.src for packet in capture._packets])
    if ip:
        os.system('cls')
        request = requests.get(f'http://ip-api.com/json/{str(ip)}')
        json = request.json()
        print('Country: ' + json.get('country', ''))
        print('State: ' + json.get('regionName', ''))
        print('City: ' + json.get('city', ''))
        print('isp: ' + json.get('isp', ''))
        print('Org: ' + json.get('org', ''))
        print('IP: ' + json.get('query', ''))
        capture.clear()


cmb = [{keyboard.Key.shift, keyboard.KeyCode(char='a')},{keyboard.Key.shift, keyboard.KeyCode(char='A')}]
  
current = set()
  
def on_press(key):
    if any([key in z for z in cmb]):
        current.add(key)
        if any(all(k in current for k in z) for z in cmb):
            sniff()

def on_release(key):
    global current
    if any([key in z for z in cmb]):
        try:
            current.remove(key)
        except KeyError:
            current = set()

with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
  listener.join()
