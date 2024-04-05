import os
import ctypes
import tkinter as tk
from tkinter import messagebox
from scapy.all import *

# Список для хранения всех пакетов
all_packets = []

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Traffic Analyzer")

        self.general_list = []
        self.blocked_list = []

        self.scanning = False

        self.create_widgets()

    def create_widgets(self):
        # Создание кнопок для начала и завершения сканирования
        self.button_start = tk.Button(self, text="Сканировать", command=self.start_scan)
        self.button_start.pack()

        self.button_stop = tk.Button(self, text="Остановить", command=self.stop_scan, state=tk.DISABLED)
        self.button_stop.pack()

        # Лейбл для "Общий список"
        self.label_general = tk.Label(self, text="Общий список")
        self.label_general.pack()

        # Список для "Общий список"
        self.listbox_general = tk.Listbox(self, width=50, height=10)
        self.listbox_general.pack()

        # Лейбл для "Список заблокированных"
        self.label_blocked = tk.Label(self, text="Список заблокированных")
        self.label_blocked.pack()

        # Список для "Список заблокированных"
        self.listbox_blocked = tk.Listbox(self, width=50, height=5)
        self.listbox_blocked.pack()

        # Обновление списков при запуске приложения
        self.update_lists()

    def update_lists(self):
        # Очистка списков перед обновлением
        self.listbox_general.delete(0, tk.END)
        self.listbox_blocked.delete(0, tk.END)

        # Обновление "Общий список"
        for item in self.general_list:
            self.listbox_general.insert(tk.END, item)

        # Обновление "Список заблокированных"
        for item in self.blocked_list:
            self.listbox_blocked.insert(tk.END, item)

    def start_scan(self):
        # Здесь должен быть ваш код для начала сканирования
        # Примерно так:
        self.scanning = True
        self.button_start.config(state=tk.DISABLED)
        self.button_stop.config(state=tk.NORMAL)
        self.start_sniffing()

    def stop_scan(self):
        # Здесь должен быть ваш код для остановки сканирования
        # Примерно так:
        self.scanning = False
        self.button_start.config(state=tk.NORMAL)
        self.button_stop.config(state=tk.DISABLED)

    def analyze_packet(self, packet):
        if IP in packet:
            # Получаем IP-адрес источника и назначения
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Проверяем, если у пакета есть заголовок TCP
            if TCP in packet:
                # Получаем номера портов источника и назначения
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # Выводим информацию о пакете
                packet_size = len(packet)
                packet_size_kb = packet_size / 1024  # размер в килобайтах
                item_info = f"TCP packet: Source IP: {src_ip}, Source Port: {src_port}, Destination IP: {dst_ip}, Destination Port: {dst_port}, Size: {packet_size_kb:.2f} KB"
                self.general_list.append(item_info)

            # Проверяем, если у пакета есть заголовок UDP
            elif UDP in packet:
                # Получаем номера портов источника и назначения
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                
                # Выводим информацию о пакете
                packet_size = len(packet)
                packet_size_kb = packet_size / 1024  # размер в килобайтах
                item_info = f"UDP packet: Source IP: {src_ip}, Source Port: {src_port}, Destination IP: {dst_ip}, Destination Port: {dst_port}, Size: {packet_size_kb:.2f} KB"
                self.general_list.append(item_info)

            # Обновляем списки после анализа пакета
            self.update_lists()

    def start_sniffing(self):
        # Запуск сниффинга в отдельном потоке
        sniff_thread = threading.Thread(target=self.sniff_traffic)
        sniff_thread.start()

    def sniff_traffic(self):
        # Функция для сниффинга сетевого трафика
        while self.scanning:
            sniff(prn=self.analyze_packet, store=0)

if __name__ == "__main__":
    app = Application()
    app.mainloop()
