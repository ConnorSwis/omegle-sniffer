import sys
from collections import Counter

import pyshark
import requests
from PyQt6 import QtGui, QtCore
from PyQt6.QtWidgets import (QApplication, QLabel, QMainWindow, QPushButton,
                             QVBoxLayout, QWidget)

BLOCK_LIST = ['31', '192', '75', '10', '162', '73']
ALWAYS_ON_TOP = True

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        if ALWAYS_ON_TOP:
            self.setWindowFlags(QtCore.Qt.WindowType.WindowStaysOnTopHint)
        self.block_list = BLOCK_LIST

        self.capture = pyshark.LiveCapture(
            interface='Ethernet',
            display_filter=(
                "udp && ip.src_host matches" +
                " \"^(?!({'|'.join(self.block_list)})).*\""
            ),
        )

        self.setWindowTitle("Sniffer")

        self.button = QPushButton("Sniff!")
        self.button.setCheckable(True)
        self.button.clicked.connect(self.sniff)

        self.label = QLabel(
            '\n'.join((
                'Country: ', 'State: ', 'City: ',
                'isp: ', 'Org: ', 'IP: '
            ))
        )
        self.button.setFont(QtGui.QFont('Arial', 11))
        self.label.setFont(QtGui.QFont('Arial', 11))

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.button)
        widget = QWidget()
        widget.setLayout(layout)
        self.setFixedSize(210, 150)
        self.setWindowIcon(QtGui.QIcon('./src/sniffer.png'))
        self.setCentralWidget(widget)

    @staticmethod
    def common(L):
        if len(L) > 0:
            return Counter(L).most_common(1)[0][0]
        return None


    def sniff(self):
        self.capture.sniff(timeout=1)
        if len(self.capture._packets) > 0:
            ip = Counter(
                [packet.ip.src for packet in self.capture._packets]
            ).most_common(1)[0][0]
            if ip:
                request = requests.get(f'http://ip-api.com/json/{str(ip)}')
                json = request.json()
                text = '\n'.join((
                    'Country: ' + json.get('country', ''),
                    'State: ' + json.get('regionName', ''),
                    'City: ' + json.get('city', ''),
                    'isp: ' + json.get('isp', ''),
                    'Org: ' + json.get('org', ''),
                    'IP: ' + json.get('query', '')
                ))
                self.capture.clear()
                self.label.setText(text)


if __name__ == '__main__':
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()
    app.exec()
