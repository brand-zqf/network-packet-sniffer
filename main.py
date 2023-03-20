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

MAXSIZE = 1024


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

    def validate_filter(self):
        exp = self.ui.filterEdit.text().strip()
        if not exp:
            self.ui.filterEdit.setStyleSheet('')
            self.ui.startButton.setEnabled(True)
            return

        try:
            compile_filter(filter_exp=exp)
            # 输入框背景变绿
            self.ui.filterEdit.setStyleSheet('QLineEdit { background-color: rgb(33, 186, 69);}')
            self.ui.startButton.setEnabled(True)
        except Scapy_Exception:
            # 将输入框背景变红
            self.ui.startButton.setEnabled(False)
            self.ui.filterEdit.setStyleSheet('QLineEdit { background-color: rgb(219, 40, 40);}')
            return

    def start_click(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
            self.ui.startButton.setText("Start")
            self.ui.interfaceBox.setEnabled(True)
            self.ui.filterEdit.setEnabled(True)
            return
        exp = self.ui.filterEdit.text()
        iface = self.get_iface()
        self.sniffer = cap.AsyncSniffer(
            iface=iface,
            prn=self.sniff_action,
            filter=exp,
        )
        self.sniffer.start()
        self.counter = 0
        self.start_time = time.time()
        self.ui.startButton.setText("Stop")
        self.ui.interfaceBox.setEnabled(False)
        self.ui.filterEdit.setEnabled(False)
        self.ui.packetTable.clearContents()
        self.ui.packetTable.setRowCount(0)
        self.ui.treeWidget.clear()
        self.ui.contentEdit.clear()

    def get_iface(self):
        index = self.ui.interfaceBox.currentIndex()
        iface = cap.get_working_ifaces()[index]
        return iface

    def sniff_action(self, packet):
        if not self.sniffer:
            return
        self.queue.put(packet)
        self.signal.recv.emit()

    def update_packet_list(self):
        packet = self.queue.get(False)
        if not packet:
            return
        if self.ui.packetTable.rowCount() >= MAXSIZE:
            self.ui.packetTable.removeRow(0)
        row = self.ui.packetTable.rowCount()
        self.ui.packetTable.insertRow(row)
        # No.
        self.counter += 1
        self.ui.packetTable.setItem(row, 0, QTItem(str(self.counter)))
        # Time
        elapse = time.time() - self.start_time
        self.ui.packetTable.setItem(row, 1, QTItem(f"{elapse:2f}"))
        # source
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
        else:
            src = packet.src
            dst = packet.dst
        self.ui.packetTable.setItem(row, 2, QTItem(src))
        # destination
        self.ui.packetTable.setItem(row, 3, QTItem(dst))
        # protocol
        layer = None
        for var in self.get_packet_layers(packet):
            if not isinstance(var, (Padding, Raw)):
                layer = var
        protocol = layer.name
        self.ui.packetTable.setItem(row, 4, QTItem(str(protocol)))
        # length
        length = f"{len(packet)}"
        self.ui.packetTable.setItem(row, 5, QTItem(length))
        # info
        info = str(packet.summary())
        item = QTItem(info)
        item.packet = packet
        self.ui.packetTable.setItem(row, 6, item)

    def update_layer_content(self, item):
        if not hasattr(item, 'layer'):
            return
        layer = item.layer
        self.ui.contentEdit.setText(hexdump(layer, dump=True))

    def update_content(self, x):
        item = self.ui.packetTable.item(x, 6)
        if not hasattr(item, 'packet'):
            return
        packet = item.packet
        self.ui.contentEdit.setText(hexdump(packet, dump=True))
        self.ui.treeWidget.clear()
        for layer in self.get_packet_layers(packet):
            item = QRItem(self.ui.treeWidget)
            item.layer = layer
            item.setText(0, layer.name)
            for name, value in layer.fields.items():
                child = QRItem(item)
                child.setText(0, f"{name}: {value}")

    @staticmethod
    def get_packet_layers(packet):
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            yield layer
            counter += 1


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
