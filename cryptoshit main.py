#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import hashlib
import time
import base64
import math
import random
import os
import sys
import struct
import threading
import queue
from datetime import datetime, timedelta

# ============== ИМПОРТ ГОСТОВСКИХ АЛГОРИТМОВ ==============
KUZNECHIK_AVAILABLE = False
STREEBOG_AVAILABLE = False
try:
    import gostcrypto
    if hasattr(gostcrypto.gostcipher, 'new'):
        KUZNECHIK_AVAILABLE = True
    if hasattr(gostcrypto.gosthash, 'new'):
        STREEBOG_AVAILABLE = True
    if KUZNECHIK_AVAILABLE and STREEBOG_AVAILABLE:
        print("gostcrypto загружен (Кузнечик и Стрибог).")
except ImportError:
    print("Установите gostcrypto: pip install gostcrypto")

# ============== ПРОВЕРКА ДОПОЛНИТЕЛЬНЫХ БИБЛИОТЕК ==============
PYAUDIO_AVAILABLE = False
CV2_AVAILABLE = False
PSUTIL_AVAILABLE = False
PIL_AVAILABLE = False

try:
    import pyaudio
    PYAUDIO_AVAILABLE = True
except ImportError:
    pass

try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
except ImportError:
    pass

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    pass

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    pass

# ===================================================================
# ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ДЛЯ HEX-ДАМПА
# ===================================================================
def hex_dump(data: bytes, max_bytes=512) -> str:
    """Возвращает hex-представление первых max_bytes байт."""
    if len(data) == 0:
        return "(пусто)"
    dump = data[:max_bytes]
    lines = []
    for i in range(0, len(dump), 16):
        chunk = dump[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:04x}: {hex_part:<48} {ascii_part}")
    if len(data) > max_bytes:
        lines.append(f"... и ещё {len(data)-max_bytes} байт")
    return '\n'.join(lines)

# ===================================================================
# КЛАССЫ ШИФРОВ (без изменений)
# ===================================================================

class AESCipher:
    def __init__(self, key=None):
        if key is None:
            self.key = Fernet.generate_key()
        else:
            if isinstance(key, str):
                try:
                    base64.urlsafe_b64decode(key)
                    self.key = key.encode('utf-8')
                except Exception:
                    raise ValueError("Неверный формат ключа.")
            elif isinstance(key, bytes):
                self.key = key
            else:
                raise TypeError("Ключ должен быть str или bytes")
        self.cipher = Fernet(self.key)

    def get_key_str(self) -> str:
        return self.key.decode('utf-8')

    def encrypt(self, plain_text: str) -> str:
        return self.cipher.encrypt(plain_text.encode('utf-8')).decode('utf-8')

    def decrypt(self, encrypted_text: str) -> str:
        return self.cipher.decrypt(encrypted_text.encode('utf-8')).decode('utf-8')


class RSACipher:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self, key_size=2048):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        self.public_key = self.private_key.public_key()
        return self.get_public_pem(), self.get_private_pem()

    def get_public_pem(self):
        if not self.public_key:
            return None
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def get_private_pem(self):
        if not self.private_key:
            return None
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

    def load_public_key(self, pem_data: str):
        self.public_key = serialization.load_pem_public_key(pem_data.encode('utf-8'))

    def load_private_key(self, pem_data: str):
        self.private_key = serialization.load_pem_private_key(pem_data.encode('utf-8'), password=None)

    def encrypt(self, plain_text: str) -> str:
        if not self.public_key:
            raise ValueError("Нет публичного ключа")
        ciphertext = self.public_key.encrypt(
            plain_text.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, encrypted_b64: str) -> str:
        if not self.private_key:
            raise ValueError("Нет приватного ключа")
        ciphertext = base64.b64decode(encrypted_b64.encode('utf-8'))
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')


class ChaCha20Cipher:
    def __init__(self, key=None):
        if key is None:
            self.key = ChaCha20Poly1305.generate_key()
        else:
            self.key = base64.urlsafe_b64decode(key)
        self.cipher = ChaCha20Poly1305(self.key)

    def get_key_str(self) -> str:
        return base64.urlsafe_b64encode(self.key).decode('utf-8')

    def encrypt(self, plain_text: str) -> str:
        nonce = os.urandom(12)
        ciphertext = self.cipher.encrypt(nonce, plain_text.encode('utf-8'), None)
        combined = nonce + ciphertext
        return base64.urlsafe_b64encode(combined).decode('utf-8')

    def decrypt(self, encrypted_b64: str) -> str:
        combined = base64.urlsafe_b64decode(encrypted_b64.encode('utf-8'))
        nonce = combined[:12]
        ciphertext = combined[12:]
        plaintext = self.cipher.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')


class KuznechikCipher:
    def __init__(self, key=None):
        if not KUZNECHIK_AVAILABLE:
            raise RuntimeError("gostcrypto не установлен.")
        if key is None:
            self.key = os.urandom(32)
        else:
            if isinstance(key, str):
                self.key = base64.urlsafe_b64decode(key)
            elif isinstance(key, bytes):
                self.key = key
            else:
                raise TypeError("Ключ должен быть str или bytes")
            if len(self.key) != 32:
                raise ValueError("Ключ должен быть длиной 32 байта")
        self.key_ba = bytearray(self.key)

    def get_key_str(self) -> str:
        return base64.urlsafe_b64encode(self.key).decode('utf-8')

    def encrypt(self, plain_text: str) -> str:
        init_vect = os.urandom(8)
        cipher_obj = gostcrypto.gostcipher.new(
            'kuznechik',
            self.key_ba,
            gostcrypto.gostcipher.MODE_CTR,
            init_vect=bytearray(init_vect)
        )
        plain_ba = bytearray(plain_text.encode('utf-8'))
        ciphertext = cipher_obj.encrypt(plain_ba)
        combined = init_vect + bytes(ciphertext)
        return base64.urlsafe_b64encode(combined).decode('utf-8')

    def decrypt(self, encrypted_b64: str) -> str:
        combined = base64.urlsafe_b64decode(encrypted_b64.encode('utf-8'))
        init_vect = combined[:8]
        ciphertext = combined[8:]
        cipher_obj = gostcrypto.gostcipher.new(
            'kuznechik',
            self.key_ba,
            gostcrypto.gostcipher.MODE_CTR,
            init_vect=bytearray(init_vect)
        )
        plain_ba = cipher_obj.decrypt(bytearray(ciphertext))
        return bytes(plain_ba).decode('utf-8')


# ===================================================================
# ХЭШИ (включая Streebog) – без изменений
# ===================================================================

class HashTool:
    @staticmethod
    def compute_sha256(data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def compute_sha3_256(data: str) -> str:
        return hashlib.sha3_256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def compute_blake2b(data: str) -> str:
        return hashlib.blake2b(data.encode('utf-8')).hexdigest()

    @staticmethod
    def compute_sha512(data: str) -> str:
        return hashlib.sha512(data.encode('utf-8')).hexdigest()

    @staticmethod
    def compute_streebog256(data: str) -> str:
        if not STREEBOG_AVAILABLE:
            return "Ошибка: gostcrypto не установлен"
        hash_obj = gostcrypto.gosthash.new('streebog256')
        hash_obj.update(data.encode('utf-8'))
        return hash_obj.hexdigest()

    @staticmethod
    def compute_streebog512(data: str) -> str:
        if not STREEBOG_AVAILABLE:
            return "Ошибка: gostcrypto не установлен"
        hash_obj = gostcrypto.gosthash.new('streebog512')
        hash_obj.update(data.encode('utf-8'))
        return hash_obj.hexdigest()


# ===================================================================
# ДИАЛОГ УСТАНОВКИ СРОКА ДЕЙСТВИЯ (без изменений)
# ===================================================================

class ExpirationDialog:
    def __init__(self, parent, callback):
        self.parent = parent
        self.callback = callback
        self.window = tk.Toplevel(parent)
        self.window.title("Установка срока действия")
        self.window.geometry("350x250")
        self.window.resizable(False, False)
        self.window.grab_set()
        self.window.configure(bg='#1a1a2e')

        ttk.Label(self.window, text="Введите дату и время истечения срока", font=('Consolas', 10)).pack(pady=5)

        frm = ttk.Frame(self.window)
        frm.pack(pady=2)
        ttk.Label(frm, text="Год:").pack(side=tk.LEFT, padx=5)
        self.year_var = tk.StringVar(value=str(datetime.now().year + 1))
        year_spin = ttk.Spinbox(frm, from_=2024, to=2099, textvariable=self.year_var, width=6)
        year_spin.pack(side=tk.LEFT)

        frm = ttk.Frame(self.window)
        frm.pack(pady=2)
        ttk.Label(frm, text="Месяц:").pack(side=tk.LEFT, padx=5)
        self.month_var = tk.StringVar(value="01")
        month_spin = ttk.Spinbox(frm, from_=1, to=12, textvariable=self.month_var, width=4, format="%02.0f")
        month_spin.pack(side=tk.LEFT)

        frm = ttk.Frame(self.window)
        frm.pack(pady=2)
        ttk.Label(frm, text="День:").pack(side=tk.LEFT, padx=5)
        self.day_var = tk.StringVar(value="01")
        day_spin = ttk.Spinbox(frm, from_=1, to=31, textvariable=self.day_var, width=4, format="%02.0f")
        day_spin.pack(side=tk.LEFT)

        frm = ttk.Frame(self.window)
        frm.pack(pady=2)
        ttk.Label(frm, text="Час:").pack(side=tk.LEFT, padx=5)
        self.hour_var = tk.StringVar(value="00")
        hour_spin = ttk.Spinbox(frm, from_=0, to=23, textvariable=self.hour_var, width=4, format="%02.0f")
        hour_spin.pack(side=tk.LEFT)

        frm = ttk.Frame(self.window)
        frm.pack(pady=2)
        ttk.Label(frm, text="Минута:").pack(side=tk.LEFT, padx=5)
        self.minute_var = tk.StringVar(value="00")
        minute_spin = ttk.Spinbox(frm, from_=0, to=59, textvariable=self.minute_var, width=4, format="%02.0f")
        minute_spin.pack(side=tk.LEFT)

        btn_frm = ttk.Frame(self.window)
        btn_frm.pack(pady=10)
        ttk.Button(btn_frm, text="Установить", command=self.set_expiration).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frm, text="Отмена", command=self.window.destroy).pack(side=tk.LEFT, padx=5)

        self.window.transient(parent)
        self.window.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 175
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 125
        self.window.geometry(f"+{x}+{y}")

    def set_expiration(self):
        try:
            year = int(self.year_var.get())
            month = int(self.month_var.get())
            day = int(self.day_var.get())
            hour = int(self.hour_var.get())
            minute = int(self.minute_var.get())
            dt = datetime(year, month, day, hour, minute)
            if dt <= datetime.now():
                messagebox.showwarning("Ошибка", "Дата должна быть в будущем.")
                return
            self.callback(dt)
            self.window.destroy()
        except ValueError:
            messagebox.showerror("Ошибка", "Введите корректные числовые значения.")


# ===================================================================
# ГЕНЕРАТОР ЭНТРОПИИ ПО ДВИЖЕНИЮ МЫШИ (ИСПРАВЛЕН)
# ===================================================================

class MouseEntropyGenerator:
    def __init__(self, parent, callback):
        self.parent = parent
        self.callback = callback
        self.entropy_data = []
        self.start_time = time.time_ns()

        self.window = tk.Toplevel(parent)
        self.window.title("Генерация ключа из движений мыши")
        self.window.geometry("500x650")
        self.window.resizable(False, False)
        self.window.grab_set()

        ttk.Label(self.window, text="Водите мышкой и кликайте для генерации энтропии",
                  font=('Arial', 10)).pack(pady=5)

        self.canvas = tk.Canvas(self.window, width=450, height=300,
                                bg='#0a0a2a', highlightthickness=0)
        self.canvas.pack(pady=5)

        self.draw_grid()

        self.canvas.bind("<Motion>", self.on_mouse_move)
        self.canvas.bind("<Button-1>", self.on_click)

        btn_frame = ttk.Frame(self.window)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="Готово (сгенерировать ключ)", command=self.finish).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=self.cancel).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Очистить следы", command=self.clear_trails).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Очистить лог", command=self.clear_log).pack(side=tk.LEFT, padx=5)

        self.counter_label = ttk.Label(self.window, text="Собрано точек: 0")
        self.counter_label.pack(pady=2)

        # ДОБАВЛЯЕМ status_label (был пропущен)
        self.status_label = ttk.Label(self.window, text="Статус: собирайте данные...", foreground='#4A90E2')
        self.status_label.pack(pady=2)

        log_frame = ttk.LabelFrame(self.window, text="Сырые данные (движения и клики)", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=6, width=60,
                                                  font=('Courier', 8), bg='#1a1a2e', fg='#00ffcc')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.insert(tk.END, "=== Лог событий мыши ===\n")
        self.log_text.insert(tk.END, "Формат: ТИП | X=... Y=... | время=... нс\n\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

        self.window.after(10000, self.auto_finish)

        self.window.transient(parent)
        self.window.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 250
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 325
        self.window.geometry(f"+{x}+{y}")

        self.particles = []
        self.animating = False

    def draw_grid(self):
        w, h = 450, 300
        step = 30
        color = "#00ccff"
        for x in range(0, w, step):
            self.canvas.create_line(x, 0, x, h, fill=color, width=1, tags="grid")
        for y in range(0, h, step):
            self.canvas.create_line(0, y, w, y, fill=color, width=1, tags="grid")
        self.canvas.create_line(w//2, 0, w//2, h, fill="#ff00ff", width=2, tags="grid")
        self.canvas.create_line(0, h//2, w, h//2, fill="#ff00ff", width=2, tags="grid")

    def add_log(self, event_type, x, y, t):
        self.log_text.config(state=tk.NORMAL)
        log_line = f"{event_type:8} | X={x:3d} Y={y:3d} | время={t} нс\n"
        self.log_text.insert(tk.END, log_line)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, "=== Лог событий мыши ===\n")
        self.log_text.insert(tk.END, "Формат: ТИП | X=... Y=... | время=... нс\n\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def on_mouse_move(self, event):
        x, y = event.x, event.y
        t = time.time_ns()
        self.entropy_data.append((x, y, t))
        self.counter_label.config(text=f"Собрано точек: {len(self.entropy_data)}")
        self.add_log("ДВИЖЕНИЕ", x, y, t)
        r = 6
        self.canvas.create_oval(x-r, y-r, x+r, y+r,
                                fill="#00ffcc", outline="#00ffcc", width=1, tags="trail")
        self.canvas.create_oval(x-2, y-2, x+2, y+2,
                                fill="white", outline="white", tags="trail")

    def on_click(self, event):
        x, y = event.x, event.y
        t = time.time_ns()
        self.entropy_data.append((x, y, t))
        self.counter_label.config(text=f"Собрано точек: {len(self.entropy_data)}")
        self.add_log("КЛИК     ", x, y, t)
        r = 6
        self.canvas.create_oval(x-r, y-r, x+r, y+r,
                                fill="#ff00ff", outline="#ff00ff", width=1, tags="trail")
        self.canvas.create_oval(x-2, y-2, x+2, y+2,
                                fill="white", outline="white", tags="trail")
        self.explode_particles(x, y)

    def explode_particles(self, cx, cy):
        num = 30
        for _ in range(num):
            angle = random.uniform(0, 2 * math.pi)
            speed = random.uniform(2, 6)
            vx = speed * math.cos(angle)
            vy = speed * math.sin(angle)
            size = random.randint(2, 5)
            color = random.choice(["#ff00ff", "#00ffff", "#ffcc00", "#ff3366"])
            item = self.canvas.create_oval(cx-size, cy-size, cx+size, cy+size,
                                           fill=color, outline=color, tags="particle")
            self.particles.append({
                'id': item,
                'x': cx,
                'y': cy,
                'vx': vx,
                'vy': vy,
                'life': 50,
                'size': size
            })
        if not self.animating:
            self.animating = True
            self.animate_particles()

    def animate_particles(self):
        if not self.particles:
            self.animating = False
            return
        for p in self.particles[:]:
            p['x'] += p['vx']
            p['y'] += p['vy']
            p['vy'] += 0.1
            p['life'] -= 1
            size = p['size']
            x, y = p['x'], p['y']
            self.canvas.coords(p['id'], x-size, y-size, x+size, y+size)
            if p['life'] <= 0:
                self.canvas.delete(p['id'])
                self.particles.remove(p)
        if self.particles:
            self.window.after(30, self.animate_particles)
        else:
            self.animating = False

    def clear_trails(self):
        self.canvas.delete("trail")
        self.canvas.delete("particle")
        self.particles.clear()
        self.animating = False

    def generate_key_from_entropy(self):
        if len(self.entropy_data) < 10:
            messagebox.showwarning("Мало данных", "Соберите хотя бы 10 точек, двигая мышью.")
            return None
        seed = str(self.start_time).encode('utf-8') + b'||'
        for x, y, t in self.entropy_data:
            seed += f"{x},{y},{t}".encode('utf-8') + b';'
        digest = hashlib.sha256(seed).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8')

    def finish(self):
        key = self.generate_key_from_entropy()
        if key:
            self.callback(key)
            self.status_label.config(text="Статус: ключ сгенерирован, окно можно закрыть")
        else:
            self.status_label.config(text="Статус: ошибка генерации")

    def auto_finish(self):
        if self.window.winfo_exists():
            if len(self.entropy_data) >= 10:
                self.finish()
            else:
                messagebox.showinfo("Недостаточно движений", "Вы почти не двигали мышью.\nГенерация отменена.")
                self.window.destroy()

    def cancel(self):
        self.window.destroy()


# ===================================================================
# ГЕНЕРАТОР ЭНТРОПИИ ИЗ МИКРОФОНА (10 сек, с дампом и сохранением)
# ===================================================================

class MicrophoneEntropyGenerator:
    def __init__(self, parent, callback, duration=10):
        self.parent = parent
        self.callback = callback
        self.duration = duration
        self.audio_data = bytearray()
        self.is_recording = False
        self.is_finished = False
        self.pyaudio_instance = None

        self.window = tk.Toplevel(parent)
        self.window.title("Генерация ключа из шума микрофона")
        self.window.geometry("700x650")
        self.window.resizable(False, False)
        self.window.grab_set()
        self.window.configure(bg='#1a1a2e')

        ttk.Label(self.window, text=f"Запись микрофона в течение {duration} секунд",
                  font=('Consolas', 10), foreground='#4A90E2').pack(pady=5)

        self.canvas = tk.Canvas(self.window, width=650, height=100,
                                bg='#0a0a2a', highlightthickness=0)
        self.canvas.pack(pady=5)
        self.draw_axes()

        log_frame = ttk.LabelFrame(self.window, text="📋 Детальный лог", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, width=70,
                                                  font=('Courier', 8), bg='#1a1a2e', fg='#00ffcc')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.insert(tk.END, "=== Лог записи микрофона ===\n")
        self.log_text.insert(tk.END, "Нажмите '▶ Записать' для начала.\n")
        self.log_text.config(state=tk.DISABLED)

        btn_frame = ttk.Frame(self.window)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="▶ Записать", command=self.start_recording).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="✅ Готово (сгенерировать ключ)", command=self.finish).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🔍 Показать дамп", command=self.show_dump).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="💾 Сохранить данные в файл", command=self.save_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Отмена", command=self.cancel).pack(side=tk.LEFT, padx=5)

        self.status_label = ttk.Label(self.window, text="Статус: готов", foreground='#4A90E2')
        self.status_label.pack(pady=2)

        self.window.transient(parent)
        self.window.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 350
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 325
        self.window.geometry(f"+{x}+{y}")

        self.add_log("Объект создан, ожидание команды.")

    def draw_axes(self):
        self.canvas.delete("all")
        w, h = 650, 100
        self.canvas.create_line(50, 50, 630, 50, fill='#4A90E2', width=2)
        self.canvas.create_line(50, 10, 50, 90, fill='#4A90E2', width=2)
        self.canvas.create_text(30, 50, text="0", fill='#4A90E2', font=('Consolas', 8))
        self.canvas.create_text(50, 10, text="+", fill='#4A90E2', font=('Consolas', 8))
        self.canvas.create_text(50, 90, text="-", fill='#4A90E2', font=('Consolas', 8))

    def update_canvas(self, data_chunk):
        if not CV2_AVAILABLE:
            return
        try:
            import numpy as np
            if len(data_chunk) < 100:
                return
            samples = np.frombuffer(data_chunk, dtype=np.int16)[:500]
            if len(samples) == 0:
                return
            max_val = np.max(np.abs(samples))
            if max_val == 0:
                max_val = 1
            norm = samples.astype(np.float32) / max_val
            w, h = 650, 100
            step = (w - 60) / len(norm)
            points = []
            for i, val in enumerate(norm):
                x = 50 + i * step
                y = 50 - val * 35
                points.append((x, y))
            self.canvas.delete("wave")
            for i in range(len(points)-1):
                self.canvas.create_line(points[i][0], points[i][1],
                                        points[i+1][0], points[i+1][1],
                                        fill='#00ffcc', width=2, tags="wave")
        except Exception as e:
            self.add_log(f"⚠️ update_canvas ошибка: {e}")

    def add_log(self, msg):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def start_recording(self):
        self.add_log("▶ start_recording: вызван")
        if not PYAUDIO_AVAILABLE:
            self.add_log("❌ Ошибка: pyaudio не установлен")
            messagebox.showerror("Ошибка", "Библиотека pyaudio не установлена.\nУстановите: pip install pyaudio")
            return
        if self.is_recording:
            self.add_log("ℹ️ start_recording: уже идёт запись")
            return
        self.is_recording = True
        self.audio_data = bytearray()
        self.status_label.config(text="Статус: запись...")
        self.add_log("🚀 Запуск потока записи...")
        threading.Thread(target=self._record_audio, daemon=True).start()

    def _record_audio(self):
        self.add_log("⚙️ _record_audio: поток запущен")
        try:
            import pyaudio
            p = pyaudio.PyAudio()
            self.pyaudio_instance = p
            self.add_log("🔍 Поиск устройств ввода...")
            device_index = None
            for i in range(p.get_device_count()):
                dev_info = p.get_device_info_by_index(i)
                if dev_info['maxInputChannels'] > 0:
                    device_index = i
                    self.add_log(f"   Найдено устройство {i}: {dev_info['name']} (каналов: {dev_info['maxInputChannels']})")
                    break
            if device_index is None:
                raise RuntimeError("Не найдено ни одного устройства ввода (микрофона).")
            self.add_log(f"✅ Выбрано устройство {device_index}")

            self.add_log("🔓 Открываю поток audio...")
            stream = p.open(format=pyaudio.paInt16,
                            channels=1,
                            rate=44100,
                            input=True,
                            input_device_index=device_index,
                            frames_per_buffer=1024)
            self.add_log("✅ Поток открыт, начинаю чтение данных...")

            start_time = time.time()
            last_log_time = time.time()
            while time.time() - start_time < self.duration:
                data = stream.read(1024, exception_on_overflow=False)
                self.audio_data.extend(data)
                now = time.time()
                if now - last_log_time > 0.3:
                    self.window.after(0, lambda d=data: self.update_canvas(d))
                    hex_preview = data[:16].hex() if data else "(пусто)"
                    self.window.after(0, lambda: self.add_log(f"📦 Записано {len(self.audio_data)} байт, hex: {hex_preview}"))
                    last_log_time = now
            stream.stop_stream()
            stream.close()
            p.terminate()
            self.is_recording = False
            self.add_log(f"✅ _record_audio: запись завершена, всего байт: {len(self.audio_data)}")
            self.window.after(0, lambda: self.status_label.config(text="Статус: запись завершена, нажмите 'Готово' для генерации ключа"))
        except Exception as e:
            self.is_recording = False
            error_msg = f"❌ Ошибка записи: {str(e)}"
            self.add_log(error_msg)
            self.window.after(0, lambda: self.status_label.config(text="Статус: ошибка"))
            self.window.after(0, lambda: messagebox.showerror("Ошибка записи", error_msg))

    def generate_key_from_audio(self):
        self.add_log("🔑 generate_key_from_audio: начало")
        if len(self.audio_data) < 100:
            self.add_log("⚠️ generate_key_from_audio: данных недостаточно")
            messagebox.showwarning("Мало данных", "Соберите больше звуковых данных.")
            return None
        self.add_log(f"📊 Данных {len(self.audio_data)} байт, хэширую SHA-256...")
        digest = hashlib.sha256(self.audio_data).digest()
        key = base64.urlsafe_b64encode(digest).decode('utf-8')
        self.add_log(f"✅ Ключ сгенерирован (первые 10 симв: {key[:10]}...)")
        return key

    def finish(self):
        self.add_log("🏁 finish: вызван")
        if self.is_recording:
            self.add_log("⏳ finish: запись ещё идёт, жду")
            messagebox.showinfo("Ожидание", "Подождите окончания записи.")
            return
        self.add_log("🔜 finish: запись завершена, генерирую ключ...")
        key = self.generate_key_from_audio()
        if key:
            self.add_log("📨 finish: ключ получен, вызываю callback")
            try:
                self.callback(key)
                self.add_log("✅ finish: callback выполнен успешно")
                self.status_label.config(text="Статус: ключ сгенерирован, окно можно закрыть")
            except Exception as e:
                self.add_log(f"❌ finish: ошибка в callback: {e}")
                messagebox.showerror("Ошибка", f"Ошибка в callback: {e}")
        else:
            self.add_log("❌ finish: ключ не сгенерирован (None)")

    def show_dump(self):
        if len(self.audio_data) == 0:
            messagebox.showinfo("Нет данных", "Сначала запишите звук.")
            return
        dump_win = tk.Toplevel(self.window)
        dump_win.title("Hex-дамп аудиоданных")
        dump_win.geometry("700x500")
        dump_win.configure(bg='#1a1a2e')
        text = scrolledtext.ScrolledText(dump_win, font=('Courier', 10), bg='#1a1a2e', fg='#00ffcc')
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        dump = hex_dump(self.audio_data, max_bytes=512)
        text.insert(tk.END, dump)
        text.config(state=tk.DISABLED)

    def save_data(self):
        if len(self.audio_data) == 0:
            messagebox.showinfo("Нет данных", "Сначала запишите звук.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Бинарные файлы", "*.bin"), ("Все", "*.*")])
        if path:
            try:
                with open(path, 'wb') as f:
                    f.write(self.audio_data)
                self.add_log(f"✅ Данные сохранены в {path}")
                messagebox.showinfo("Сохранено", f"Файл сохранён:\n{path}")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

    def cancel(self):
        self.add_log("❌ cancel: отмена")
        self.is_recording = False
        if self.pyaudio_instance:
            self.pyaudio_instance.terminate()
        self.window.destroy()


# ===================================================================
# ГЕНЕРАТОР ЭНТРОПИИ ИЗ ВЕБ-КАМЕРЫ (30 кадров, с дампом и сохранением)
# ===================================================================

class CameraEntropyGenerator:
    def __init__(self, parent, callback, num_frames=30):
        self.parent = parent
        self.callback = callback
        self.num_frames = num_frames
        self.captured_data = bytearray()
        self.is_capturing = False
        self.cap = None
        self.thread = None
        self.stop_capture = False

        self.window = tk.Toplevel(parent)
        self.window.title("Генерация ключа из шума камеры")
        self.window.geometry("900x750")
        self.window.resizable(False, False)
        self.window.grab_set()
        self.window.configure(bg='#1a1a2e')

        top_frame = ttk.Frame(self.window)
        top_frame.pack(fill=tk.X, pady=5)
        ttk.Label(top_frame, text="Захват шума матрицы камеры (в темноте или с закрытым объективом)",
                  font=('Consolas', 10), foreground='#4A90E2').pack()

        self.canvas = tk.Canvas(self.window, width=640, height=480,
                                bg='#0a0a2a', highlightthickness=0)
        self.canvas.pack(pady=5)

        log_frame = ttk.LabelFrame(self.window, text="📋 Детальный лог", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, width=70,
                                                  font=('Courier', 8), bg='#1a1a2e', fg='#00ffcc')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.insert(tk.END, "=== Лог захвата камеры ===\n")
        self.log_text.insert(tk.END, "Нажмите '📷 Захватить кадры' для начала.\n")
        self.log_text.config(state=tk.DISABLED)

        btn_frame = ttk.Frame(self.window)
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="📷 Захватить кадры", command=self.start_capture).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="✅ Готово (сгенерировать ключ)", command=self.finish).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="🔍 Показать дамп", command=self.show_dump).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="💾 Сохранить данные в файл", command=self.save_data).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="❌ Отмена", command=self.cancel).pack(side=tk.LEFT, padx=10)

        self.status_label = ttk.Label(self.window, text="Статус: готов", foreground='#4A90E2')
        self.status_label.pack(pady=2)

        self.window.transient(parent)
        self.window.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 450
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 375
        self.window.geometry(f"+{x}+{y}")

        self.photo = None
        self.add_log("Объект камеры создан, ожидание команды.")

    def add_log(self, msg):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def update_canvas(self, frame):
        if not CV2_AVAILABLE or not PIL_AVAILABLE:
            return
        try:
            import cv2
            from PIL import Image, ImageTk
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(frame_rgb)
            imgtk = ImageTk.PhotoImage(image=img)
            self.canvas.imgtk = imgtk
            self.canvas.create_image(320, 240, image=imgtk)
        except Exception as e:
            self.add_log(f"⚠️ update_canvas ошибка: {e}")

    def start_capture(self):
        self.add_log("▶ start_capture: вызван")
        if not CV2_AVAILABLE:
            self.add_log("❌ Ошибка: opencv-python не установлен")
            messagebox.showerror("Ошибка", "Библиотека opencv-python не установлена.\nУстановите: pip install opencv-python")
            return
        if not PIL_AVAILABLE:
            self.add_log("❌ Ошибка: Pillow не установлен")
            messagebox.showerror("Ошибка", "Библиотека Pillow не установлена.\nУстановите: pip install Pillow")
            return
        if self.is_capturing:
            self.add_log("ℹ️ start_capture: уже идёт захват")
            return
        self.is_capturing = True
        self.captured_data = bytearray()
        self.stop_capture = False
        self.status_label.config(text="Статус: захват...")
        self.add_log("🚀 Запуск потока захвата кадров...")
        self.thread = threading.Thread(target=self._capture_frames, daemon=True)
        self.thread.start()

    def _capture_frames(self):
        self.add_log("⚙️ _capture_frames: поток запущен")
        import cv2
        try:
            self.add_log("🔍 Поиск доступной камеры...")
            for idx in range(3):
                cap = cv2.VideoCapture(idx)
                if cap.isOpened():
                    self.cap = cap
                    self.add_log(f"✅ Камера с индексом {idx} открыта.")
                    break
            if self.cap is None:
                raise RuntimeError("Не удалось открыть камеру (проверены индексы 0,1,2).")

            frame_count = 0
            self.add_log(f"🔓 Начинаю захват {self.num_frames} кадров...")
            while not self.stop_capture and frame_count < self.num_frames:
                ret, frame = self.cap.read()
                if not ret:
                    self.add_log("⚠️ Ошибка чтения кадра, прерываю.")
                    break
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                self.captured_data.extend(gray.tobytes())
                frame_count += 1
                self.window.after(0, lambda f=frame: self.update_canvas(f))
                hex_preview = gray.tobytes()[:16].hex()
                self.window.after(0, lambda: self.add_log(f"📷 Кадр {frame_count}: {len(gray.tobytes())} байт, hex: {hex_preview}"))
                time.sleep(0.1)

            self.cap.release()
            self.is_capturing = False
            self.add_log(f"✅ Захват завершён. Кадров: {frame_count}, всего байт: {len(self.captured_data)}")
            self.window.after(0, lambda: self.status_label.config(text="Статус: захват завершён, нажмите 'Готово' для генерации ключа"))
        except Exception as e:
            self.is_capturing = False
            error_msg = f"❌ Ошибка захвата: {str(e)}"
            self.add_log(error_msg)
            self.window.after(0, lambda: self.status_label.config(text="Статус: ошибка"))
            self.window.after(0, lambda: messagebox.showerror("Ошибка захвата", error_msg))
            if self.cap and self.cap.isOpened():
                self.cap.release()

    def generate_key_from_camera(self):
        self.add_log("🔑 generate_key_from_camera: начало")
        if len(self.captured_data) < 100:
            self.add_log("⚠️ generate_key_from_camera: данных недостаточно")
            messagebox.showwarning("Мало данных", "Соберите больше кадров.")
            return None
        self.add_log(f"📊 Данных {len(self.captured_data)} байт, хэширую SHA-256...")
        digest = hashlib.sha256(self.captured_data).digest()
        key = base64.urlsafe_b64encode(digest).decode('utf-8')
        self.add_log(f"✅ Ключ сгенерирован (первые 10 симв: {key[:10]}...)")
        return key

    def finish(self):
        self.add_log("🏁 finish: вызван")
        if self.is_capturing:
            self.add_log("⏳ finish: захват ещё идёт, жду")
            messagebox.showinfo("Ожидание", "Подождите окончания захвата.")
            return
        self.add_log("🔜 finish: захват завершён, генерирую ключ...")
        key = self.generate_key_from_camera()
        if key:
            self.add_log("📨 finish: ключ получен, вызываю callback")
            try:
                self.callback(key)
                self.add_log("✅ finish: callback выполнен успешно")
                self.status_label.config(text="Статус: ключ сгенерирован, окно можно закрыть")
            except Exception as e:
                self.add_log(f"❌ finish: ошибка в callback: {e}")
                messagebox.showerror("Ошибка", f"Ошибка в callback: {e}")
        else:
            self.add_log("❌ finish: ключ не сгенерирован (None)")

    def show_dump(self):
        if len(self.captured_data) == 0:
            messagebox.showinfo("Нет данных", "Сначала захватите кадры.")
            return
        dump_win = tk.Toplevel(self.window)
        dump_win.title("Hex-дамп данных камеры")
        dump_win.geometry("700x500")
        dump_win.configure(bg='#1a1a2e')
        text = scrolledtext.ScrolledText(dump_win, font=('Courier', 10), bg='#1a1a2e', fg='#00ffcc')
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        dump = hex_dump(self.captured_data, max_bytes=512)
        text.insert(tk.END, dump)
        text.config(state=tk.DISABLED)

    def save_data(self):
        if len(self.captured_data) == 0:
            messagebox.showinfo("Нет данных", "Сначала захватите кадры.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Бинарные файлы", "*.bin"), ("Все", "*.*")])
        if path:
            try:
                with open(path, 'wb') as f:
                    f.write(self.captured_data)
                self.add_log(f"✅ Данные сохранены в {path}")
                messagebox.showinfo("Сохранено", f"Файл сохранён:\n{path}")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

    def cancel(self):
        self.add_log("❌ cancel: отмена")
        self.stop_capture = True
        if self.cap and self.cap.isOpened():
            self.cap.release()
        self.is_capturing = False
        self.window.destroy()


# ===================================================================
# ГЕНЕРАТОР СИСТЕМНОГО ШУМА (10 сек, с дампом и сохранением)
# ===================================================================

class SystemEntropyGenerator:
    def __init__(self, parent, callback, duration=10):
        self.parent = parent
        self.callback = callback
        self.duration = duration
        self.samples = bytearray()
        self.is_collecting = False

        self.window = tk.Toplevel(parent)
        self.window.title("Генерация ключа из системного шума")
        self.window.geometry("700x650")
        self.window.resizable(False, False)
        self.window.grab_set()
        self.window.configure(bg='#1a1a2e')

        ttk.Label(self.window, text=f"Сбор системной энтропии в течение {duration} секунд",
                  font=('Consolas', 10), foreground='#4A90E2').pack(pady=5)

        self.canvas = tk.Canvas(self.window, width=650, height=100,
                                bg='#0a0a2a', highlightthickness=0)
        self.canvas.pack(pady=5)
        self.draw_axes()

        log_frame = ttk.LabelFrame(self.window, text="📋 Детальный лог", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, width=70,
                                                  font=('Courier', 8), bg='#1a1a2e', fg='#00ffcc')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.insert(tk.END, "=== Лог сбора системных данных ===\n")
        self.log_text.insert(tk.END, "Нажмите '🖥 Собрать данные' для начала.\n")
        self.log_text.config(state=tk.DISABLED)

        btn_frame = ttk.Frame(self.window)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="🖥 Собрать данные", command=self.start_collect).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="✅ Готово (сгенерировать ключ)", command=self.finish).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🔍 Показать дамп", command=self.show_dump).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="💾 Сохранить данные в файл", command=self.save_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Отмена", command=self.cancel).pack(side=tk.LEFT, padx=5)

        self.status_label = ttk.Label(self.window, text="Статус: готов", foreground='#4A90E2')
        self.status_label.pack(pady=2)

        self.window.transient(parent)
        self.window.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 350
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 325
        self.window.geometry(f"+{x}+{y}")

        self.add_log("Объект системного шума создан, ожидание команды.")

    def draw_axes(self):
        self.canvas.delete("all")
        w, h = 650, 100
        self.canvas.create_line(50, 50, 630, 50, fill='#4A90E2', width=2)
        self.canvas.create_line(50, 10, 50, 90, fill='#4A90E2', width=2)

    def add_log(self, msg):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def update_canvas(self, cpu_vals):
        if len(cpu_vals) < 2:
            return
        if len(cpu_vals) > 200:
            cpu_vals = cpu_vals[-200:]
        w, h = 650, 100
        step = (w - 60) / len(cpu_vals)
        points = []
        for i, val in enumerate(cpu_vals):
            x = 50 + i * step
            y = 50 - val * 35
            points.append((x, y))
        self.canvas.delete("wave")
        for i in range(len(points)-1):
            self.canvas.create_line(points[i][0], points[i][1],
                                    points[i+1][0], points[i+1][1],
                                    fill='#00ffcc', width=2, tags="wave")

    def start_collect(self):
        self.add_log("▶ start_collect: вызван")
        if self.is_collecting:
            self.add_log("ℹ️ start_collect: уже идёт сбор")
            return
        self.is_collecting = True
        self.samples = bytearray()
        self.status_label.config(text="Статус: сбор...")
        self.add_log("🚀 Запуск потока сбора системных данных...")
        threading.Thread(target=self._collect_data, daemon=True).start()

    def _collect_data(self):
        self.add_log("⚙️ _collect_data: поток запущен")
        try:
            start_time = time.time()
            last_log_time = time.time()
            cpu_history = []
            while time.time() - start_time < self.duration:
                data = []
                t1 = time.perf_counter_ns()
                time.sleep(0.001)
                t2 = time.perf_counter_ns()
                delta = t2 - t1
                data.append(struct.pack('Q', delta))

                if PSUTIL_AVAILABLE:
                    cpu = psutil.cpu_percent(interval=None) / 100.0
                else:
                    cpu = (delta % 1000) / 1000.0
                data.append(struct.pack('d', cpu))
                cpu_history.append(cpu)

                if PSUTIL_AVAILABLE:
                    mem = psutil.virtual_memory().percent / 100.0
                else:
                    mem = (os.times().system % 100) / 100.0
                data.append(struct.pack('d', mem))

                if PSUTIL_AVAILABLE:
                    uptime = time.time() - psutil.boot_time()
                else:
                    uptime = time.time() % 1000
                data.append(struct.pack('d', uptime % 1.0))

                pid = os.getpid()
                data.append(struct.pack('i', pid))

                times = os.times()
                data.append(struct.pack('d', times.user % 1.0))
                data.append(struct.pack('d', times.system % 1.0))

                chunk = b''.join(data)
                self.samples.extend(chunk)

                now = time.time()
                if now - last_log_time > 0.5:
                    self.window.after(0, lambda vals=cpu_history: self.update_canvas(vals))
                    hex_preview = chunk[:16].hex() if chunk else "(пусто)"
                    self.window.after(0, lambda: self.add_log(f"📊 Собрано {len(self.samples)} байт, hex: {hex_preview}"))
                    last_log_time = now

                time.sleep(0.02)

            self.is_collecting = False
            self.add_log(f"✅ Сбор завершён, всего байт: {len(self.samples)}")
            self.window.after(0, lambda: self.status_label.config(text="Статус: сбор завершён, нажмите 'Готово' для генерации ключа"))
        except Exception as e:
            self.is_collecting = False
            error_msg = f"❌ Ошибка сбора: {str(e)}"
            self.add_log(error_msg)
            self.window.after(0, lambda: self.status_label.config(text="Статус: ошибка"))
            self.window.after(0, lambda: messagebox.showerror("Ошибка сбора", error_msg))

    def generate_key_from_system(self):
        self.add_log("🔑 generate_key_from_system: начало")
        if len(self.samples) < 100:
            self.add_log("⚠️ generate_key_from_system: данных недостаточно")
            messagebox.showwarning("Мало данных", "Соберите больше системных данных.")
            return None
        self.add_log(f"📊 Всего байт: {len(self.samples)}, хэширую SHA-256...")
        digest = hashlib.sha256(self.samples).digest()
        key = base64.urlsafe_b64encode(digest).decode('utf-8')
        self.add_log(f"✅ Ключ сгенерирован (первые 10 симв: {key[:10]}...)")
        return key

    def finish(self):
        self.add_log("🏁 finish: вызван")
        if self.is_collecting:
            self.add_log("⏳ finish: сбор ещё идёт, жду")
            messagebox.showinfo("Ожидание", "Подождите окончания сбора.")
            return
        self.add_log("🔜 finish: сбор завершён, генерирую ключ...")
        key = self.generate_key_from_system()
        if key:
            self.add_log("📨 finish: ключ получен, вызываю callback")
            try:
                self.callback(key)
                self.add_log("✅ finish: callback выполнен успешно")
                self.status_label.config(text="Статус: ключ сгенерирован, окно можно закрыть")
            except Exception as e:
                self.add_log(f"❌ finish: ошибка в callback: {e}")
                messagebox.showerror("Ошибка", f"Ошибка в callback: {e}")
        else:
            self.add_log("❌ finish: ключ не сгенерирован (None)")

    def show_dump(self):
        if len(self.samples) == 0:
            messagebox.showinfo("Нет данных", "Сначала соберите данные.")
            return
        dump_win = tk.Toplevel(self.window)
        dump_win.title("Hex-дамп системных данных")
        dump_win.geometry("700x500")
        dump_win.configure(bg='#1a1a2e')
        text = scrolledtext.ScrolledText(dump_win, font=('Courier', 10), bg='#1a1a2e', fg='#00ffcc')
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        dump = hex_dump(self.samples, max_bytes=512)
        text.insert(tk.END, dump)
        text.config(state=tk.DISABLED)

    def save_data(self):
        if len(self.samples) == 0:
            messagebox.showinfo("Нет данных", "Сначала соберите данные.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Бинарные файлы", "*.bin"), ("Все", "*.*")])
        if path:
            try:
                with open(path, 'wb') as f:
                    f.write(self.samples)
                self.add_log(f"✅ Данные сохранены в {path}")
                messagebox.showinfo("Сохранено", f"Файл сохранён:\n{path}")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

    def cancel(self):
        self.add_log("❌ cancel: отмена")
        self.is_collecting = False
        self.window.destroy()


# ===================================================================
# КОНТЕКСТНОЕ МЕНЮ (без изменений)
# ===================================================================

class ContextMenu:
    @staticmethod
    def add_to(widget, root):
        menu = tk.Menu(widget, tearoff=0, bg='#1a1a2e', fg='#4A90E2', activebackground='#2a2a4e', activeforeground='#ffffff')
        menu.add_command(label="Вырезать", command=lambda: ContextMenu.cut(widget))
        menu.add_command(label="Копировать", command=lambda: ContextMenu.copy(widget))
        menu.add_command(label="Вставить", command=lambda: ContextMenu.paste(widget))
        menu.add_separator()
        menu.add_command(label="Очистить", command=lambda: ContextMenu.clear(widget))
        
        def show_menu(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
        
        widget.bind("<Button-3>", show_menu)
        return menu

    @staticmethod
    def cut(widget):
        try:
            widget.event_generate("<<Cut>>")
        except:
            pass

    @staticmethod
    def copy(widget):
        try:
            widget.event_generate("<<Copy>>")
        except:
            pass

    @staticmethod
    def paste(widget):
        try:
            widget.event_generate("<<Paste>>")
        except:
            pass

    @staticmethod
    def clear(widget):
        try:
            widget.delete("1.0", tk.END)
        except:
            pass


# ===================================================================
# ОСНОВНОЙ КЛАСС ПРИЛОЖЕНИЯ (полностью рабочий)
# ===================================================================

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🕵️ Крипто-инструмент (Neon Style)")
        self.root.geometry("920x840")
        self.root.resizable(True, True)
        self.root.configure(bg='#1a1a2e')

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', background='#1a1a2e', foreground='#4A90E2', fieldbackground='#2a2a3e')
        self.style.configure('TLabel', background='#1a1a2e', foreground='#4A90E2', font=('Consolas', 10))
        self.style.configure('TFrame', background='#1a1a2e')
        self.style.configure('TNotebook', background='#1a1a2e')
        self.style.configure('TNotebook.Tab', background='#2a2a3e', foreground='#4A90E2', padding=[10, 5])
        self.style.map('TNotebook.Tab', background=[('selected', '#640F87')])
        self.style.configure('TLabelframe', background='#1a1a2e', foreground='#4A90E2', bordercolor='#640F87')
        self.style.configure('TLabelframe.Label', background='#1a1a2e', foreground='#4A90E2')
        self.style.configure('TButton', background='#2a2a3e', foreground='#4A90E2', bordercolor='#640F87',
                             font=('Consolas', 9), padding=6)
        self.style.map('TButton', background=[('active', '#640F87')], foreground=[('active', 'white')])
        self.style.configure('TEntry', fieldbackground='#2a2a3e', foreground='#4A90E2', insertcolor='#4A90E2')
        self.style.configure('TCombobox', fieldbackground='#2a2a3e', foreground='#4A90E2')

        self.status_var = tk.StringVar()
        self.status_var.set("🟢 Готов к работе.")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W,
                               background='#1a1a2e', foreground='#4A90E2')
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=2)

        self.root.bind_all('<Control-Key>', self.on_control_key)

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tab_sym = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sym, text="🔐 AES")
        self.setup_symmetric_tab()

        self.tab_rsa = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_rsa, text="🔑 RSA")
        self.setup_rsa_tab()

        self.tab_hash = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_hash, text="🔏 Хэши")
        self.setup_hash_tab()

        self.tab_chacha = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_chacha, text="⚡ ChaCha20")
        self.setup_chacha_tab()

        self.tab_kuz = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_kuz, text="🛡️ Кузнечик")
        self.setup_kuznechik_tab()

    def on_control_key(self, event):
        if (event.state & 0x4) and (event.keycode == 86 or event.keycode == 118):
            widget = self.root.focus_get()
            if widget and isinstance(widget, (tk.Text, tk.Entry, scrolledtext.ScrolledText)):
                try:
                    text = self.root.clipboard_get()
                    widget.insert(tk.INSERT, text)
                    return "break"
                except tk.TclError:
                    pass

    def add_paste_button(self, parent, widget, row=None, col=None, columnspan=1):
        btn = ttk.Button(parent, text="📋 Вставить", 
                         command=lambda: self.paste_to_widget(widget))
        if row is not None and col is not None:
            btn.grid(row=row, column=col, columnspan=columnspan, padx=2, pady=2)
        else:
            btn.pack(side=tk.LEFT, padx=2)
        return btn

    def paste_to_widget(self, widget):
        try:
            text = self.root.clipboard_get()
            widget.insert(tk.INSERT, text)
            self.status_var.set("Вставлено из буфера.")
        except tk.TclError:
            self.status_var.set("Буфер обмена пуст.")

    def add_expiration_ui(self, parent, expiration_var, expiration_label_var):
        exp_frame = ttk.Frame(parent)
        exp_frame.pack(fill=tk.X, pady=2)
        ttk.Button(exp_frame, text="⏳ Задать срок", 
                   command=lambda: self.set_expiration_dialog(expiration_var, expiration_label_var)).pack(side=tk.LEFT, padx=5)
        self.exp_label = ttk.Label(exp_frame, textvariable=expiration_label_var, foreground='#4A90E2')
        self.exp_label.pack(side=tk.LEFT, padx=10)

    def set_expiration_dialog(self, expiration_var, expiration_label_var):
        def callback(dt):
            expiration_var.set(dt.isoformat())
            expiration_label_var.set(f"Срок до: {dt.strftime('%d.%m.%Y %H:%M')}")
            self.status_var.set(f"Срок действия установлен до {dt.strftime('%d.%m.%Y %H:%M')}")
        ExpirationDialog(self.root, callback)

    def clear_expiration(self, expiration_var, expiration_label_var):
        expiration_var.set("")
        expiration_label_var.set("Срок не установлен")
        self.status_var.set("Срок действия сброшен")

    def add_expiration_to_data(self, data: str, expiration_var) -> str:
        exp_str = expiration_var.get()
        if exp_str:
            return f"EXPIRES:{exp_str};{data}"
        return data

    def check_expiration(self, data: str):
        if data.startswith("EXPIRES:"):
            parts = data.split(";", 1)
            if len(parts) == 2:
                exp_iso = parts[0].replace("EXPIRES:", "")
                try:
                    exp_dt = datetime.fromisoformat(exp_iso)
                    if datetime.now() > exp_dt:
                        return False, "Срок действия истёк!", None
                    else:
                        return True, "Срок действия в силе.", parts[1]
                except ValueError:
                    return False, "Неверный формат даты в данных!", None
        return True, "Без ограничения срока.", data

    # ==================== ВКЛАДКА AES ====================
    def setup_symmetric_tab(self):
        frame = self.tab_sym
        self.aes_cipher = None
        self.aes_expiration = tk.StringVar(value="")
        self.aes_exp_label_var = tk.StringVar(value="Срок не установлен")

        key_frame = ttk.LabelFrame(frame, text="Ключ (сохраните в надёжном месте)", padding=10)
        key_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(key_frame, text="Ключ:").grid(row=0, column=0, sticky=tk.W)
        self.aes_key_var = tk.StringVar()
        key_entry = ttk.Entry(key_frame, textvariable=self.aes_key_var, width=70)
        key_entry.grid(row=0, column=1, padx=5, sticky=tk.W+tk.E)
        ContextMenu.add_to(key_entry, self.root)

        btn_frame = ttk.Frame(key_frame)
        btn_frame.grid(row=0, column=2, padx=5)
        ttk.Button(btn_frame, text="Сгенерировать", command=self.aes_generate_key).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🖱 По движению мыши", command=self.aes_generate_key_from_mouse).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🎤 Микрофон (10с)", command=self.aes_generate_key_from_microphone).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="📷 Камера (30 кадров)", command=self.aes_generate_key_from_camera).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🖥 Система (10с)", command=self.aes_generate_key_from_system).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Сохранить", command=self.aes_save_key).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Загрузить", command=self.aes_load_key).pack(side=tk.LEFT, padx=2)

        key_entry.bind('<KeyRelease>', self.aes_on_key_change)
        key_entry.bind('<FocusOut>', self.aes_on_key_change)

        self.add_expiration_ui(frame, self.aes_expiration, self.aes_exp_label_var)
        ttk.Button(frame, text="❌ Сбросить срок", 
                   command=lambda: self.clear_expiration(self.aes_expiration, self.aes_exp_label_var)).pack(pady=2)

        input_frame = ttk.LabelFrame(frame, text="Входные данные", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        ttk.Label(input_frame, text="Введите текст для шифрования или зашифрованную строку:").pack(anchor=tk.W)
        self.aes_input = scrolledtext.ScrolledText(input_frame, height=5, wrap=tk.WORD,
                                                   bg='#2a2a3e', fg='#4A90E2', insertbackground='#4A90E2')
        self.aes_input.pack(fill=tk.BOTH, expand=True, pady=5)
        ContextMenu.add_to(self.aes_input, self.root)

        action_frame = ttk.Frame(frame)
        action_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(action_frame, text="🔒 Зашифровать", command=self.aes_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="🔓 Расшифровать", command=self.aes_decrypt).pack(side=tk.LEFT, padx=5)
        self.add_paste_button(action_frame, self.aes_input)
        ttk.Button(action_frame, text="📋 Копировать результат", command=lambda: self.copy_text(self.aes_output)).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Очистить", command=lambda: self.clear_texts(self.aes_input, self.aes_output)).pack(side=tk.LEFT, padx=5)

        output_frame = ttk.LabelFrame(frame, text="Результат", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.aes_output = scrolledtext.ScrolledText(output_frame, height=5, wrap=tk.WORD,
                                                    bg='#2a2a3e', fg='#4A90E2', insertbackground='#4A90E2')
        self.aes_output.pack(fill=tk.BOTH, expand=True, pady=5)
        ContextMenu.add_to(self.aes_output, self.root)

        self.aes_generate_key()

    # Методы для AES
    def aes_generate_key_from_microphone(self):
        def on_key_generated(key_str):
            try:
                cipher = AESCipher(key_str)
                self.aes_cipher = cipher
                self.aes_key_var.set(key_str)
                self.status_var.set("✅ Ключ из микрофона (10с).")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        MicrophoneEntropyGenerator(self.root, on_key_generated, duration=10)

    def aes_generate_key_from_camera(self):
        def on_key_generated(key_str):
            try:
                cipher = AESCipher(key_str)
                self.aes_cipher = cipher
                self.aes_key_var.set(key_str)
                self.status_var.set("✅ Ключ из камеры.")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        CameraEntropyGenerator(self.root, on_key_generated, num_frames=30)

    def aes_generate_key_from_system(self):
        def on_key_generated(key_str):
            try:
                cipher = AESCipher(key_str)
                self.aes_cipher = cipher
                self.aes_key_var.set(key_str)
                self.status_var.set("✅ Ключ из системного шума (10с).")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        SystemEntropyGenerator(self.root, on_key_generated, duration=10)

    def aes_generate_key(self):
        try:
            cipher = AESCipher()
            self.aes_cipher = cipher
            self.aes_key_var.set(cipher.get_key_str())
            self.status_var.set("Сгенерирован новый AES-ключ.")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def aes_generate_key_from_mouse(self):
        def on_key_generated(key_str):
            try:
                cipher = AESCipher(key_str)
                self.aes_cipher = cipher
                self.aes_key_var.set(key_str)
                self.status_var.set("Ключ из движений мыши.")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        MouseEntropyGenerator(self.root, on_key_generated)

    def aes_on_key_change(self, event=None):
        key_str = self.aes_key_var.get().strip()
        if not key_str:
            return
        try:
            cipher = AESCipher(key_str)
            self.aes_cipher = cipher
            self.status_var.set("Ключ обновлён.")
        except Exception as e:
            self.status_var.set(f"Ошибка в ключе: {e}")

    def aes_encrypt(self):
        if self.aes_cipher is None:
            messagebox.showerror("Ошибка", "Нет валидного ключа.")
            return
        plain = self.aes_input.get("1.0", tk.END).strip()
        if not plain:
            messagebox.showwarning("Предупреждение", "Введите текст для шифрования.")
            return
        plain_with_exp = self.add_expiration_to_data(plain, self.aes_expiration)
        try:
            encrypted = self.aes_cipher.encrypt(plain_with_exp)
            self.aes_output.delete("1.0", tk.END)
            self.aes_output.insert("1.0", encrypted)
            self.status_var.set("Текст зашифрован AES.")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def aes_decrypt(self):
        if self.aes_cipher is None:
            messagebox.showerror("Ошибка", "Нет валидного ключа.")
            return
        encrypted = self.aes_input.get("1.0", tk.END).strip()
        if not encrypted:
            messagebox.showwarning("Предупреждение", "Введите зашифрованный текст.")
            return
        try:
            decrypted = self.aes_cipher.decrypt(encrypted)
            ok, msg, clean_data = self.check_expiration(decrypted)
            if ok:
                self.aes_output.delete("1.0", tk.END)
                self.aes_output.insert("1.0", clean_data)
                self.status_var.set(msg)
            else:
                messagebox.showerror("Ошибка", msg)
                self.status_var.set("Ошибка: " + msg)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def aes_save_key(self):
        key_str = self.aes_key_var.get().strip()
        if not key_str:
            messagebox.showwarning("Нет ключа", "Нечего сохранять.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Файлы ключей", "*.key"), ("Все", "*.*")])
        if path:
            try:
                with open(path, 'w') as f:
                    f.write(key_str)
                self.status_var.set(f"Ключ сохранён в {path}")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

    def aes_load_key(self):
        path = filedialog.askopenfilename(filetypes=[("Файлы ключей", "*.key"), ("Все", "*.*")])
        if path:
            try:
                with open(path, 'r') as f:
                    key_str = f.read().strip()
                cipher = AESCipher(key_str)
                self.aes_cipher = cipher
                self.aes_key_var.set(key_str)
                self.status_var.set(f"Ключ загружен из {path}")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

    # ==================== ВКЛАДКА RSA ====================
    def setup_rsa_tab(self):
        frame = self.tab_rsa
        self.rsa = RSACipher()
        self.rsa_expiration = tk.StringVar(value="")
        self.rsa_exp_label_var = tk.StringVar(value="Срок не установлен")

        ttk.Label(frame, text="Публичный ключ (PEM):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.rsa_pub_text = scrolledtext.ScrolledText(frame, height=4, width=80,
                                                      font=('Courier', 8), bg='#2a2a3e', fg='#4A90E2')
        self.rsa_pub_text.grid(row=1, column=0, columnspan=4, padx=5, pady=2, sticky=tk.W+tk.E)
        ContextMenu.add_to(self.rsa_pub_text, self.root)

        ttk.Label(frame, text="Приватный ключ (PEM):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.rsa_priv_text = scrolledtext.ScrolledText(frame, height=4, width=80,
                                                       font=('Courier', 8), bg='#2a2a3e', fg='#4A90E2')
        self.rsa_priv_text.grid(row=3, column=0, columnspan=4, padx=5, pady=2, sticky=tk.W+tk.E)
        ContextMenu.add_to(self.rsa_priv_text, self.root)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=4, column=0, columnspan=4, pady=5)
        ttk.Button(btn_frame, text="Сгенерировать пару (2048)", command=self.rsa_generate_keys).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🖱 По движению мыши", command=self.rsa_generate_key_from_mouse).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🎤 Микрофон (10с)", command=self.rsa_generate_key_from_microphone).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="📷 Камера (30 кадров)", command=self.rsa_generate_key_from_camera).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🖥 Система (10с)", command=self.rsa_generate_key_from_system).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Загрузить публичный", command=self.rsa_load_public).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Загрузить приватный", command=self.rsa_load_private).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Сохранить ключи", command=self.rsa_save_keys).pack(side=tk.LEFT, padx=5)

        exp_rsa_frame = ttk.Frame(frame)
        exp_rsa_frame.grid(row=5, column=0, columnspan=4, pady=5, sticky=tk.W)
        ttk.Button(exp_rsa_frame, text="⏳ Задать срок", 
                   command=lambda: self.set_expiration_dialog(self.rsa_expiration, self.rsa_exp_label_var)).pack(side=tk.LEFT, padx=5)
        ttk.Label(exp_rsa_frame, textvariable=self.rsa_exp_label_var, foreground='#4A90E2').pack(side=tk.LEFT, padx=10)
        ttk.Button(exp_rsa_frame, text="❌ Сбросить срок", 
                   command=lambda: self.clear_expiration(self.rsa_expiration, self.rsa_exp_label_var)).pack(side=tk.LEFT, padx=5)

        ttk.Label(frame, text="Текст для шифрования / расшифровки:").grid(row=6, column=0, sticky=tk.W, padx=5, pady=2)
        self.rsa_input = scrolledtext.ScrolledText(frame, height=3, width=80,
                                                   bg='#2a2a3e', fg='#4A90E2')
        self.rsa_input.grid(row=7, column=0, columnspan=4, padx=5, pady=2)
        ContextMenu.add_to(self.rsa_input, self.root)

        btn_action = ttk.Frame(frame)
        btn_action.grid(row=8, column=0, columnspan=4, pady=5)
        ttk.Button(btn_action, text="🔒 Зашифровать (публичным)", command=self.rsa_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_action, text="🔓 Расшифровать (приватным)", command=self.rsa_decrypt).pack(side=tk.LEFT, padx=5)
        self.add_paste_button(btn_action, self.rsa_input)
        ttk.Button(btn_action, text="📋 Копировать", command=lambda: self.copy_text(self.rsa_output)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_action, text="Очистить", command=lambda: self.clear_texts(self.rsa_input, self.rsa_output)).pack(side=tk.LEFT, padx=5)

        ttk.Label(frame, text="Результат:").grid(row=9, column=0, sticky=tk.W, padx=5, pady=2)
        self.rsa_output = scrolledtext.ScrolledText(frame, height=3, width=80,
                                                    bg='#2a2a3e', fg='#4A90E2')
        self.rsa_output.grid(row=10, column=0, columnspan=4, padx=5, pady=2)
        ContextMenu.add_to(self.rsa_output, self.root)

    def rsa_generate_keys(self):
        try:
            pub, priv = self.rsa.generate_keys()
            self.rsa_pub_text.delete("1.0", tk.END)
            self.rsa_pub_text.insert("1.0", pub)
            self.rsa_priv_text.delete("1.0", tk.END)
            self.rsa_priv_text.insert("1.0", priv)
            self.status_var.set("Новая RSA-пара сгенерирована.")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def rsa_generate_key_from_mouse(self):
        def on_key_generated(key_str):
            try:
                self.rsa_generate_keys()
                self.status_var.set("RSA из движений мыши.")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        MouseEntropyGenerator(self.root, on_key_generated)

    def rsa_generate_key_from_microphone(self):
        def on_key_generated(key_str):
            try:
                self.rsa_generate_keys()
                self.status_var.set("RSA из микрофона (10с).")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        MicrophoneEntropyGenerator(self.root, on_key_generated, duration=10)

    def rsa_generate_key_from_camera(self):
        def on_key_generated(key_str):
            try:
                self.rsa_generate_keys()
                self.status_var.set("RSA из камеры.")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        CameraEntropyGenerator(self.root, on_key_generated, num_frames=30)

    def rsa_generate_key_from_system(self):
        def on_key_generated(key_str):
            try:
                self.rsa_generate_keys()
                self.status_var.set("RSA из системного шума (10с).")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        SystemEntropyGenerator(self.root, on_key_generated, duration=10)

    def rsa_load_public(self):
        path = filedialog.askopenfilename(filetypes=[("PEM файлы", "*.pem"), ("Все", "*.*")])
        if path:
            try:
                with open(path, 'r') as f:
                    pem = f.read()
                self.rsa.load_public_key(pem)
                self.rsa_pub_text.delete("1.0", tk.END)
                self.rsa_pub_text.insert("1.0", pem)
                self.status_var.set("Публичный ключ загружен.")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

    def rsa_load_private(self):
        path = filedialog.askopenfilename(filetypes=[("PEM файлы", "*.pem"), ("Все", "*.*")])
        if path:
            try:
                with open(path, 'r') as f:
                    pem = f.read()
                self.rsa.load_private_key(pem)
                self.rsa_priv_text.delete("1.0", tk.END)
                self.rsa_priv_text.insert("1.0", pem)
                self.status_var.set("Приватный ключ загружен.")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

    def rsa_save_keys(self):
        pub = self.rsa_pub_text.get("1.0", tk.END).strip()
        priv = self.rsa_priv_text.get("1.0", tk.END).strip()
        if not pub or not priv:
            messagebox.showwarning("Нет ключей", "Сначала сгенерируйте или загрузите ключи.")
            return
        folder = filedialog.askdirectory()
        if folder:
            try:
                with open(os.path.join(folder, "public.pem"), 'w') as f:
                    f.write(pub)
                with open(os.path.join(folder, "private.pem"), 'w') as f:
                    f.write(priv)
                self.status_var.set(f"Ключи сохранены в {folder}")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

    def rsa_encrypt(self):
        text = self.rsa_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Введите текст", "Поле ввода пустое.")
            return
        text_with_exp = self.add_expiration_to_data(text, self.rsa_expiration)
        try:
            encrypted = self.rsa.encrypt(text_with_exp)
            self.rsa_output.delete("1.0", tk.END)
            self.rsa_output.insert("1.0", encrypted)
            self.status_var.set("Текст зашифрован RSA.")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def rsa_decrypt(self):
        text = self.rsa_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Введите текст", "Поле ввода пустое.")
            return
        try:
            decrypted = self.rsa.decrypt(text)
            ok, msg, clean_data = self.check_expiration(decrypted)
            if ok:
                self.rsa_output.delete("1.0", tk.END)
                self.rsa_output.insert("1.0", clean_data)
                self.status_var.set(msg)
            else:
                messagebox.showerror("Ошибка", msg)
                self.status_var.set("Ошибка: " + msg)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    # ==================== ВКЛАДКА ХЭШИ ====================
    def setup_hash_tab(self):
        frame = self.tab_hash
        ttk.Label(frame, text="Введите текст для вычисления хэша:").pack(anchor=tk.W, padx=5, pady=2)
        self.hash_input = scrolledtext.ScrolledText(frame, height=4, width=80,
                                                    bg='#2a2a3e', fg='#4A90E2')
        self.hash_input.pack(padx=5, pady=2, fill=tk.BOTH, expand=True)
        ContextMenu.add_to(self.hash_input, self.root)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="SHA-256", command=lambda: self.compute_hash("sha256")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="SHA-3 (256)", command=lambda: self.compute_hash("sha3_256")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="BLAKE2b", command=lambda: self.compute_hash("blake2b")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="SHA-512", command=lambda: self.compute_hash("sha512")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Streebog-256", command=lambda: self.compute_hash("streebog256")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Streebog-512", command=lambda: self.compute_hash("streebog512")).pack(side=tk.LEFT, padx=5)
        self.add_paste_button(btn_frame, self.hash_input)
        ttk.Button(btn_frame, text="Очистить", command=lambda: self.clear_texts(self.hash_input, self.hash_output)).pack(side=tk.LEFT, padx=5)

        ttk.Label(frame, text="Хэш (результат):").pack(anchor=tk.W, padx=5, pady=2)
        self.hash_output = scrolledtext.ScrolledText(frame, height=3, width=80, font=('Courier', 10),
                                                     bg='#2a2a3e', fg='#4A90E2')
        self.hash_output.pack(padx=5, pady=2, fill=tk.BOTH, expand=True)
        ContextMenu.add_to(self.hash_output, self.root)

    def compute_hash(self, algo):
        text = self.hash_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Введите текст", "Поле ввода пустое.")
            return
        if algo == "sha256":
            result = HashTool.compute_sha256(text)
        elif algo == "sha3_256":
            result = HashTool.compute_sha3_256(text)
        elif algo == "blake2b":
            result = HashTool.compute_blake2b(text)
        elif algo == "sha512":
            result = HashTool.compute_sha512(text)
        elif algo == "streebog256":
            result = HashTool.compute_streebog256(text)
        elif algo == "streebog512":
            result = HashTool.compute_streebog512(text)
        else:
            result = "Неизвестный алгоритм"
        self.hash_output.delete("1.0", tk.END)
        self.hash_output.insert("1.0", result)
        self.status_var.set(f"Хэш {algo} вычислен.")

    # ==================== ВКЛАДКА ChaCha20 ====================
    def setup_chacha_tab(self):
        frame = self.tab_chacha
        self.chacha = None
        self.chacha_expiration = tk.StringVar(value="")
        self.chacha_exp_label_var = tk.StringVar(value="Срок не установлен")

        ttk.Label(frame, text="Ключ (base64):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.chacha_key_var = tk.StringVar()
        chacha_key_entry = ttk.Entry(frame, textvariable=self.chacha_key_var, width=60)
        chacha_key_entry.grid(row=0, column=1, padx=5, pady=2, sticky=tk.W+tk.E)
        ContextMenu.add_to(chacha_key_entry, self.root)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=0, column=2, padx=5)
        ttk.Button(btn_frame, text="Сгенерировать", command=self.chacha_generate_key).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🖱 По движению мыши", command=self.chacha_generate_key_from_mouse).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🎤 Микрофон (10с)", command=self.chacha_generate_key_from_microphone).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="📷 Камера (30 кадров)", command=self.chacha_generate_key_from_camera).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🖥 Система (10с)", command=self.chacha_generate_key_from_system).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Сохранить", command=self.chacha_save_key).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Загрузить", command=self.chacha_load_key).pack(side=tk.LEFT, padx=2)

        exp_chacha_frame = ttk.Frame(frame)
        exp_chacha_frame.grid(row=1, column=0, columnspan=3, pady=5, sticky=tk.W)
        ttk.Button(exp_chacha_frame, text="⏳ Задать срок", 
                   command=lambda: self.set_expiration_dialog(self.chacha_expiration, self.chacha_exp_label_var)).pack(side=tk.LEFT, padx=5)
        ttk.Label(exp_chacha_frame, textvariable=self.chacha_exp_label_var, foreground='#4A90E2').pack(side=tk.LEFT, padx=10)
        ttk.Button(exp_chacha_frame, text="❌ Сбросить срок", 
                   command=lambda: self.clear_expiration(self.chacha_expiration, self.chacha_exp_label_var)).pack(side=tk.LEFT, padx=5)

        ttk.Label(frame, text="Введите текст:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.chacha_input = scrolledtext.ScrolledText(frame, height=4, width=80,
                                                      bg='#2a2a3e', fg='#4A90E2')
        self.chacha_input.grid(row=3, column=0, columnspan=3, padx=5, pady=2)
        ContextMenu.add_to(self.chacha_input, self.root)

        btn_action = ttk.Frame(frame)
        btn_action.grid(row=4, column=0, columnspan=3, pady=5)
        ttk.Button(btn_action, text="🔒 Зашифровать", command=self.chacha_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_action, text="🔓 Расшифровать", command=self.chacha_decrypt).pack(side=tk.LEFT, padx=5)
        self.add_paste_button(btn_action, self.chacha_input)
        ttk.Button(btn_action, text="📋 Копировать результат", command=lambda: self.copy_text(self.chacha_output)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_action, text="Очистить", command=lambda: self.clear_texts(self.chacha_input, self.chacha_output)).pack(side=tk.LEFT, padx=5)

        ttk.Label(frame, text="Результат:").grid(row=5, column=0, sticky=tk.W, padx=5, pady=2)
        self.chacha_output = scrolledtext.ScrolledText(frame, height=4, width=80,
                                                       bg='#2a2a3e', fg='#4A90E2')
        self.chacha_output.grid(row=6, column=0, columnspan=3, padx=5, pady=2)
        ContextMenu.add_to(self.chacha_output, self.root)

    def chacha_generate_key(self):
        cipher = ChaCha20Cipher()
        self.chacha = cipher
        self.chacha_key_var.set(cipher.get_key_str())
        self.status_var.set("Новый ключ ChaCha20 сгенерирован.")

    def chacha_generate_key_from_mouse(self):
        def on_key_generated(key_str):
            try:
                cipher = ChaCha20Cipher(key_str)
                self.chacha = cipher
                self.chacha_key_var.set(key_str)
                self.status_var.set("ChaCha из движений мыши.")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        MouseEntropyGenerator(self.root, on_key_generated)

    def chacha_generate_key_from_microphone(self):
        def on_key_generated(key_str):
            try:
                cipher = ChaCha20Cipher(key_str)
                self.chacha = cipher
                self.chacha_key_var.set(key_str)
                self.status_var.set("ChaCha из микрофона (10с).")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        MicrophoneEntropyGenerator(self.root, on_key_generated, duration=10)

    def chacha_generate_key_from_camera(self):
        def on_key_generated(key_str):
            try:
                cipher = ChaCha20Cipher(key_str)
                self.chacha = cipher
                self.chacha_key_var.set(key_str)
                self.status_var.set("ChaCha из камеры.")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        CameraEntropyGenerator(self.root, on_key_generated, num_frames=30)

    def chacha_generate_key_from_system(self):
        def on_key_generated(key_str):
            try:
                cipher = ChaCha20Cipher(key_str)
                self.chacha = cipher
                self.chacha_key_var.set(key_str)
                self.status_var.set("ChaCha из системного шума (10с).")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        SystemEntropyGenerator(self.root, on_key_generated, duration=10)

    def chacha_load_key(self):
        path = filedialog.askopenfilename(filetypes=[("Файлы ключей", "*.key"), ("Все", "*.*")])
        if path:
            try:
                with open(path, 'r') as f:
                    key_str = f.read().strip()
                cipher = ChaCha20Cipher(key_str)
                self.chacha = cipher
                self.chacha_key_var.set(key_str)
                self.status_var.set(f"Ключ ChaCha20 загружен из {path}")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

    def chacha_save_key(self):
        key_str = self.chacha_key_var.get().strip()
        if not key_str:
            messagebox.showwarning("Нет ключа", "Нечего сохранять.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Файлы ключей", "*.key"), ("Все", "*.*")])
        if path:
            try:
                with open(path, 'w') as f:
                    f.write(key_str)
                self.status_var.set(f"Ключ ChaCha20 сохранён в {path}")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

    def chacha_encrypt(self):
        if not self.chacha:
            messagebox.showwarning("Нет ключа", "Сгенерируйте или загрузите ключ.")
            return
        text = self.chacha_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Введите текст", "Поле ввода пустое.")
            return
        text_with_exp = self.add_expiration_to_data(text, self.chacha_expiration)
        try:
            encrypted = self.chacha.encrypt(text_with_exp)
            self.chacha_output.delete("1.0", tk.END)
            self.chacha_output.insert("1.0", encrypted)
            self.status_var.set("Текст зашифрован ChaCha20.")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def chacha_decrypt(self):
        if not self.chacha:
            messagebox.showwarning("Нет ключа", "Сгенерируйте или загрузите ключ.")
            return
        text = self.chacha_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Введите текст", "Поле ввода пустое.")
            return
        try:
            decrypted = self.chacha.decrypt(text)
            ok, msg, clean_data = self.check_expiration(decrypted)
            if ok:
                self.chacha_output.delete("1.0", tk.END)
                self.chacha_output.insert("1.0", clean_data)
                self.status_var.set(msg)
            else:
                messagebox.showerror("Ошибка", msg)
                self.status_var.set("Ошибка: " + msg)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    # ==================== ВКЛАДКА КУЗНЕЧИК ====================
    def setup_kuznechik_tab(self):
        frame = self.tab_kuz
        self.kuz = None
        self.kuz_expiration = tk.StringVar(value="")
        self.kuz_exp_label_var = tk.StringVar(value="Срок не установлен")

        if not KUZNECHIK_AVAILABLE:
            ttk.Label(frame, text="Библиотека gostcrypto не установлена.\n"
                                  "Установите: pip install gostcrypto",
                      foreground="red", font=('Arial', 10, 'bold')).pack(pady=20)
            return

        key_frame = ttk.LabelFrame(frame, text="Ключ (256 бит / 32 байта)", padding=10)
        key_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(key_frame, text="Ключ (base64):").grid(row=0, column=0, sticky=tk.W)
        self.kuz_key_var = tk.StringVar()
        key_entry = ttk.Entry(key_frame, textvariable=self.kuz_key_var, width=70)
        key_entry.grid(row=0, column=1, padx=5, sticky=tk.W+tk.E)
        ContextMenu.add_to(key_entry, self.root)

        btn_frame = ttk.Frame(key_frame)
        btn_frame.grid(row=0, column=2, padx=5)
        ttk.Button(btn_frame, text="Сгенерировать", command=self.kuz_generate_key).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🖱 По движению мыши", command=self.kuz_generate_key_from_mouse).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🎤 Микрофон (10с)", command=self.kuz_generate_key_from_microphone).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="📷 Камера (30 кадров)", command=self.kuz_generate_key_from_camera).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🖥 Система (10с)", command=self.kuz_generate_key_from_system).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Сохранить", command=self.kuz_save_key).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Загрузить", command=self.kuz_load_key).pack(side=tk.LEFT, padx=2)

        exp_kuz_frame = ttk.Frame(key_frame)
        exp_kuz_frame.grid(row=1, column=0, columnspan=3, pady=5, sticky=tk.W)
        ttk.Button(exp_kuz_frame, text="⏳ Задать срок", 
                   command=lambda: self.set_expiration_dialog(self.kuz_expiration, self.kuz_exp_label_var)).pack(side=tk.LEFT, padx=5)
        ttk.Label(exp_kuz_frame, textvariable=self.kuz_exp_label_var, foreground='#4A90E2').pack(side=tk.LEFT, padx=10)
        ttk.Button(exp_kuz_frame, text="❌ Сбросить срок", 
                   command=lambda: self.clear_expiration(self.kuz_expiration, self.kuz_exp_label_var)).pack(side=tk.LEFT, padx=5)

        input_frame = ttk.LabelFrame(frame, text="Входные данные", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        ttk.Label(input_frame, text="Введите текст для шифрования или зашифрованную строку:").pack(anchor=tk.W)
        self.kuz_input = scrolledtext.ScrolledText(input_frame, height=5, wrap=tk.WORD,
                                                   bg='#2a2a3e', fg='#4A90E2')
        self.kuz_input.pack(fill=tk.BOTH, expand=True, pady=5)
        ContextMenu.add_to(self.kuz_input, self.root)

        action_frame = ttk.Frame(frame)
        action_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(action_frame, text="🔒 Зашифровать", command=self.kuz_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="🔓 Расшифровать", command=self.kuz_decrypt).pack(side=tk.LEFT, padx=5)
        self.add_paste_button(action_frame, self.kuz_input)
        ttk.Button(action_frame, text="📋 Копировать результат", command=lambda: self.copy_text(self.kuz_output)).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Очистить", command=lambda: self.clear_texts(self.kuz_input, self.kuz_output)).pack(side=tk.LEFT, padx=5)

        output_frame = ttk.LabelFrame(frame, text="Результат", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.kuz_output = scrolledtext.ScrolledText(output_frame, height=5, wrap=tk.WORD,
                                                    bg='#2a2a3e', fg='#4A90E2')
        self.kuz_output.pack(fill=tk.BOTH, expand=True, pady=5)
        ContextMenu.add_to(self.kuz_output, self.root)

        self.kuz_generate_key()

    def kuz_generate_key(self):
        try:
            cipher = KuznechikCipher()
            self.kuz = cipher
            self.kuz_key_var.set(cipher.get_key_str())
            self.status_var.set("Новый ключ Кузнечика сгенерирован.")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def kuz_generate_key_from_mouse(self):
        def on_key_generated(key_str):
            try:
                cipher = KuznechikCipher(key_str)
                self.kuz = cipher
                self.kuz_key_var.set(key_str)
                self.status_var.set("Кузнечик из движений мыши.")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        MouseEntropyGenerator(self.root, on_key_generated)

    def kuz_generate_key_from_microphone(self):
        def on_key_generated(key_str):
            try:
                cipher = KuznechikCipher(key_str)
                self.kuz = cipher
                self.kuz_key_var.set(key_str)
                self.status_var.set("Кузнечик из микрофона (10с).")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        MicrophoneEntropyGenerator(self.root, on_key_generated, duration=10)

    def kuz_generate_key_from_camera(self):
        def on_key_generated(key_str):
            try:
                cipher = KuznechikCipher(key_str)
                self.kuz = cipher
                self.kuz_key_var.set(key_str)
                self.status_var.set("Кузнечик из камеры.")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        CameraEntropyGenerator(self.root, on_key_generated, num_frames=30)

    def kuz_generate_key_from_system(self):
        def on_key_generated(key_str):
            try:
                cipher = KuznechikCipher(key_str)
                self.kuz = cipher
                self.kuz_key_var.set(key_str)
                self.status_var.set("Кузнечик из системного шума (10с).")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        SystemEntropyGenerator(self.root, on_key_generated, duration=10)

    def kuz_load_key(self):
        path = filedialog.askopenfilename(filetypes=[("Файлы ключей", "*.key"), ("Все", "*.*")])
        if path:
            try:
                with open(path, 'r') as f:
                    key_str = f.read().strip()
                cipher = KuznechikCipher(key_str)
                self.kuz = cipher
                self.kuz_key_var.set(key_str)
                self.status_var.set(f"Ключ Кузнечика загружен из {path}")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

    def kuz_save_key(self):
        key_str = self.kuz_key_var.get().strip()
        if not key_str:
            messagebox.showwarning("Нет ключа", "Нечего сохранять.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Файлы ключей", "*.key"), ("Все", "*.*")])
        if path:
            try:
                with open(path, 'w') as f:
                    f.write(key_str)
                self.status_var.set(f"Ключ Кузнечика сохранён в {path}")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

    def kuz_encrypt(self):
        if not self.kuz:
            messagebox.showwarning("Нет ключа", "Сгенерируйте или загрузите ключ.")
            return
        text = self.kuz_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Введите текст", "Поле ввода пустое.")
            return
        text_with_exp = self.add_expiration_to_data(text, self.kuz_expiration)
        try:
            encrypted = self.kuz.encrypt(text_with_exp)
            self.kuz_output.delete("1.0", tk.END)
            self.kuz_output.insert("1.0", encrypted)
            self.status_var.set("Текст зашифрован Кузнечиком.")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def kuz_decrypt(self):
        if not self.kuz:
            messagebox.showwarning("Нет ключа", "Сгенерируйте или загрузите ключ.")
            return
        text = self.kuz_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Введите текст", "Поле ввода пустое.")
            return
        try:
            decrypted = self.kuz.decrypt(text)
            ok, msg, clean_data = self.check_expiration(decrypted)
            if ok:
                self.kuz_output.delete("1.0", tk.END)
                self.kuz_output.insert("1.0", clean_data)
                self.status_var.set(msg)
            else:
                messagebox.showerror("Ошибка", msg)
                self.status_var.set("Ошибка: " + msg)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    # ==================== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ====================
    def copy_text(self, widget):
        text = widget.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Нет данных", "Нечего копировать.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        self.status_var.set("Скопировано в буфер обмена.")

    def clear_texts(self, *widgets):
        for w in widgets:
            try:
                w.delete("1.0", tk.END)
            except:
                pass
        self.status_var.set("Поля очищены.")


# ===================================================================
# ЗАПУСК
# ===================================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()