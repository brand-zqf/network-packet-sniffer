import sys
import time
from queue import Queue

from scapy import all as cap
from scapy.all import Raw
from scapy.all import Padding
from scapy.arch.common import compile_filter
from scapy.error import Scapy_Exception
from scapy.utils import hexdump
from scapy.layers.inet import IP
from PySide6 import QtWidgets
from PySide6 import QtCore
from PySide6.QtWidgets import QTableWidgetItem as QTItem
from PySide6.QtWidgets import QTreeWidgetItem as QRItem
from PySide6.QtWidgets import QMainWindow

from gui import ui_main


class Signal(QtCore.QObject):
    recv = QtCore.Signal()


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.ui = ui_main.Ui_MainWindow()
        self.ui.setupUi(self)
        self.sniffer = None
        self.counter = 0
        self.start_time = 0
        self.signal = Signal()
        self.queue = Queue()
        self.init_interfaces()

    def init_interfaces(self):
        for interface in cap.get_working_ifaces():
            self.ui.interfaceBox.addItem(interface.name)
        self.ui.filterEdit.editingFinished.connect(self.validate_filter)
        self.ui.startButton.clicked.connect(self.start_click)
        self.ui.packetTable.horizontalHeader().setStretchLastSection(True)
        self.ui.packetTable.cellPressed.connect(self.update_content)
        self.ui.treeWidget.itemPressed.connect(self.update_layer_content)
        self.signal.recv.connect(self.update_packet_list)


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
