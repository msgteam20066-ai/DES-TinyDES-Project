"""DES minh họa trên lớp: CHỈ 3 tab, GUI tách riêng khỏi lõi DES.

1) Mã hóa/Giải mã + mô phỏng 16 vòng tích hợp
2) Mã hóa/Giải mã tệp
3) Minh họa tấn công brute-force trên 12 bit ứng viên

Không padding: dữ liệu nhập bắt buộc có độ dài dương và chia hết cho 8 byte.
"""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from time import perf_counter
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from attack_demo import build_attack_report
from des.data import decrypt_data, decrypt_file, encrypt_data, encrypt_file
from des.examples import DEMO_CASES, find_standard_case
from des.formats import bytes_to_hex, parse_hex, parse_key, parse_plaintext
from des.trace import trace_decrypt_block, trace_encrypt_block
from des_trace_ui import DESRoundViewer


class DESApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DES - Mã hóa và giải mã")
        self.geometry("1200x820")
        self.minsize(980, 680)
        self._style()
        self._build_tabs()

    def _style(self) -> None:
        s = ttk.Style(self)
        if "vista" in s.theme_names():
            s.theme_use("vista")
        s.configure("Title.TLabel", font=("Segoe UI", 15, "bold"))
        s.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(10, 7))
        s.configure("TButton", padding=(7, 5))

    def _build_tabs(self) -> None:
        heading = ttk.Frame(self, padding=(12, 8))
        heading.pack(fill="x")
        ttk.Label(heading, text="THUẬT TOÁN DES", style="Title.TLabel").pack(anchor="w")

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        self.main_tab = ttk.Frame(self.tabs, padding=8)
        self.file_tab = ttk.Frame(self.tabs, padding=12)
        self.attack_tab = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.main_tab, text="Mã hóa / Giải mã")
        self.tabs.add(self.file_tab, text="Mã hóa tệp")
        self.tabs.add(self.attack_tab, text="Demo tấn công")
        self._build_main()
        self._build_files()
        self._build_attack()

    # ------------------ PHẦN 1: mã hóa, giải mã + mô phỏng ------------------
    def _build_main(self) -> None:
        self.main_tab.rowconfigure(0, weight=1)
        self.main_tab.columnconfigure(0, weight=1)
        splitter = ttk.PanedWindow(self.main_tab, orient="vertical")
        splitter.grid(row=0, column=0, sticky="nsew")
        operations = ttk.Frame(splitter, padding=(2, 2))
        simulation = ttk.Frame(splitter, padding=(2, 2))
        splitter.add(operations, weight=1)
        splitter.add(simulation, weight=3)
        self.main_splitter = splitter
        self.main_operations = operations
        self.inputs_collapsed = False
        operations.columnconfigure(0, weight=1)

        # Chọn ca kiểm tra dùng chung với tests.py; không cần tab Kiểm thử riêng.
        presets = ttk.Frame(operations)
        presets.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(presets, text="Ví dụ:").pack(side="left")
        self.example_name = tk.StringVar(value=DEMO_CASES[0].name)
        ttk.Combobox(presets, textvariable=self.example_name, state="readonly", width=30,
                     values=[c.name for c in DEMO_CASES]).pack(side="left", padx=(6, 6))
        ttk.Button(presets, text="Nạp ca", command=self._load_example).pack(side="left")
        

        inputs = ttk.Frame(operations)
        inputs.grid(row=1, column=0, sticky="ew")
        inputs.columnconfigure(0, weight=5)
        inputs.columnconfigure(1, weight=4)
        plaintext_frame = ttk.LabelFrame(inputs, text="Bản rõ", padding=6)
        plaintext_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        plaintext_frame.columnconfigure(0, weight=1)
        self.plain_mode = tk.StringVar(value="hex")
        mode_bar = ttk.Frame(plaintext_frame)
        mode_bar.grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(mode_bar, text="Text", variable=self.plain_mode, value="text").pack(side="left")
        ttk.Radiobutton(mode_bar, text="HEX", variable=self.plain_mode, value="hex").pack(side="left", padx=10)
        self.plain_input = ScrolledText(plaintext_frame, height=2, wrap="word", font=("Consolas", 10))
        self.plain_input.grid(row=1, column=0, sticky="ew", pady=(3, 0))
        ttk.Label(plaintext_frame, text="Độ dài: bội số của 8 byte").grid(row=2, column=0, sticky="w")

        key_frame = ttk.LabelFrame(inputs, text="Khóa DES", padding=6)
        key_frame.grid(row=0, column=1, sticky="nsew")
        key_frame.columnconfigure(0, weight=1)
        self.key_mode = tk.StringVar(value="hex")
        kmodes = ttk.Frame(key_frame)
        kmodes.grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(kmodes, text="Text", variable=self.key_mode, value="text").pack(side="left")
        ttk.Radiobutton(kmodes, text="HEX", variable=self.key_mode, value="hex").pack(side="left", padx=10)
        self.key_entry = ttk.Entry(key_frame, font=("Consolas", 11))
        self.key_entry.grid(row=1, column=0, sticky="ew", pady=(7, 3))
        ttk.Label(key_frame, text="8 byte (Text) hoặc 16 ký tự HEX").grid(row=2, column=0, sticky="w")

        actions = ttk.Frame(operations)
        actions.grid(row=2, column=0, sticky="ew", pady=(6, 5))
        ttk.Button(actions, text="Mã hóa", style="Primary.TButton", command=self._encrypt).pack(side="left")
        ttk.Button(actions, text="Giải mã", command=self._decrypt).pack(side="left", padx=5)
        ttk.Button(actions, text="Xóa kết quả", command=self._clear_result).pack(side="right")

        results = ttk.LabelFrame(operations, text="Kết quả", padding=6)
        results.grid(row=3, column=0, sticky="ew")
        results.columnconfigure(0, weight=1)
        results.columnconfigure(1, weight=1)
        ttk.Label(results, text="Bản mã (HEX):").grid(row=0, column=0, sticky="w")
        ttk.Label(results, text="Bản rõ sau giải mã:").grid(row=0, column=1, sticky="w", padx=(8, 0))
        self.cipher_input = ScrolledText(results, height=1, wrap="word", font=("Consolas", 10))
        self.cipher_input.grid(row=1, column=0, sticky="ew", padx=(0, 4))
        self.recovered_output = ScrolledText(results, height=1, wrap="word", font=("Consolas", 10))
        self.recovered_output.grid(row=1, column=1, sticky="ew", padx=(4, 0))
        self.status = tk.StringVar(value="Sẵn sàng.")
        self.expected_status = tk.StringVar(value="")
        ttk.Label(results, textvariable=self.status).grid(row=2, column=0, columnspan=2, sticky="w", pady=(5, 0))
        ttk.Label(results, textvariable=self.expected_status, font=("Segoe UI", 9, "bold")).grid(row=3, column=0, columnspan=2, sticky="w")

        # Mô phỏng nằm TRONG CÙNG tab, tự kích hoạt ngay sau mã hóa hoặc giải mã.
        block_header = ttk.Frame(simulation)
        block_header.pack(fill="x", pady=(0, 4))
        ttk.Label(block_header, text="Mô phỏng 16 vòng Feistel", font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Label(block_header, text="Khối:").pack(side="left", padx=(22, 5))
        self.block_number = tk.IntVar(value=1)
        self.block_select = ttk.Spinbox(block_header, from_=1, to=1, width=4, state="disabled",
                                        textvariable=self.block_number, command=self._render_block)
        self.block_select.pack(side="left")
        self.block_select.bind("<Return>", lambda _event: self._render_block())
        self.block_select.bind("<FocusOut>", lambda _event: self._render_block())
        self.block_count_var = tk.StringVar(value="Chưa có dữ liệu")
        ttk.Label(block_header, textvariable=self.block_count_var).pack(side="left", padx=6)
        self.toggle_inputs_button = ttk.Button(block_header, text="Mở rộng mô phỏng",
                                               command=self._toggle_inputs)
        self.toggle_inputs_button.pack(side="right")
        self.trace_view = DESRoundViewer(simulation)
        self.trace_view.pack(fill="both", expand=True)

        # Dữ liệu chỉ được thay đổi bởi nút mã hóa/giải mã, không dùng đầu vào riêng cho trace.
        self.active_data: bytes | None = None
        self.active_key: bytes | None = None
        self.active_output: bytes | None = None
        self.active_direction: str | None = None
        self._load_example()
        # Phần nhập liệu đủ cao để luôn thấy nút Mã hóa và Giải mã.
        self.after_idle(lambda: splitter.sashpos(0, 390))

    def _toggle_inputs(self) -> None:
        if self.inputs_collapsed:
            self.main_splitter.insert(0, self.main_operations, weight=1)
            self.inputs_collapsed = False
            self.toggle_inputs_button.configure(text="Mở rộng mô phỏng")
            self.after_idle(lambda: self.main_splitter.sashpos(0, 390))
        else:
            self.main_splitter.forget(self.main_operations)
            self.inputs_collapsed = True
            self.toggle_inputs_button.configure(text="Hiện phần nhập")

    @staticmethod
    def _replace_text(widget: ScrolledText, value: str) -> None:
        widget.delete("1.0", "end")
        widget.insert("1.0", value)

    def _recovered_display(self, raw: bytes) -> str:
        if self.plain_mode.get() == "text":
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                pass
        return bytes_to_hex(raw)

    def _get_key(self) -> bytes:
        return parse_key(self.key_entry.get(), self.key_mode.get())

    def _get_plain(self) -> bytes:
        return parse_plaintext(self.plain_input.get("1.0", "end-1c"), self.plain_mode.get())

    def _load_example(self) -> None:
        case = next(c for c in DEMO_CASES if c.name == self.example_name.get())
        self.plain_mode.set("hex")
        self.key_mode.set("hex")
        self._replace_text(self.plain_input, case.plain_hex)
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, case.key_hex)
        self._clear_result()
        self.status.set(f"Đã nạp: {case.name}")

    def _clear_result(self) -> None:
        self._replace_text(self.cipher_input, "")
        self._replace_text(self.recovered_output, "")
        self.status.set("Sẵn sàng.")
        self.expected_status.set("")
        self.active_data = self.active_key = self.active_output = self.active_direction = None
        self.block_count_var.set("Chưa có dữ liệu")
        self.block_select.configure(to=1, state="disabled")
        self.block_number.set(1)
        self.trace_view.clear()

    def _activate_trace(self, source: bytes, key: bytes, output: bytes, direction: str) -> None:
        self.active_data, self.active_key = source, key
        self.active_output, self.active_direction = output, direction
        count = len(source) // 8
        self.block_count_var.set(f"/ {count}")
        self.block_select.configure(to=count, state="readonly" if count > 1 else "disabled")
        self.block_number.set(1)
        self._render_block()

    def _render_block(self) -> None:
        if self.active_data is None or self.active_key is None or self.active_output is None:
            return
        count = len(self.active_data) // 8
        try:
            try:
                index = int(self.block_select.get())
            except (TypeError, ValueError, tk.TclError):
                index = 1
            index = max(1, min(count, index))
            self.block_number.set(index)
            block = self.active_data[(index - 1) * 8:index * 8]
            tracer = trace_encrypt_block if self.active_direction == "encrypt" else trace_decrypt_block
            t = tracer(block, self.active_key)
            if t.output_block != self.active_output[(index - 1) * 8:index * 8]:
                raise RuntimeError("Kết quả mô phỏng khác kết quả mã hóa/giải mã chính!")
            self.trace_view.load_trace(t, index, count)
        except (ValueError, RuntimeError) as exc:
            messagebox.showerror("Không thể xem khối", str(exc), parent=self)

    def _encrypt(self) -> None:
        try:
            plain, key = self._get_plain(), self._get_key()
            start = perf_counter()
            cipher = encrypt_data(plain, key)
            t_enc = (perf_counter() - start) * 1000
            start = perf_counter()
            recovered = decrypt_data(cipher, key)
            t_dec = (perf_counter() - start) * 1000
            if recovered != plain:
                raise RuntimeError("LỖI: giải mã không khôi phục bản rõ!")
            self._replace_text(self.cipher_input, bytes_to_hex(cipher))
            self._replace_text(self.recovered_output, self._recovered_display(recovered))
            self.status.set(f"{len(plain)} byte | {len(plain)//8} khối | Mã hóa: {t_enc:.3f} ms | Giải mã: {t_dec:.3f} ms | Khôi phục: PASS")
            standard = find_standard_case(plain, key)
            if standard:
                actual = bytes_to_hex(cipher)
                matches = actual == standard.expected_cipher_hex
                self.expected_status.set(f"Đối chiếu: {standard.expected_cipher_hex} | Kết quả: {actual} | {'PASS' if matches else 'FAIL'}")
                if not matches:
                    raise RuntimeError("Sai kết quả test vector chuẩn DES!")
            else:
                self.expected_status.set("Đối chiếu mã hóa/giải mã: PASS")
            self._activate_trace(plain, key, cipher, "encrypt")
        except (ValueError, RuntimeError) as exc:
            self._clear_result()
            messagebox.showerror("Không thể mã hóa", str(exc), parent=self)

    def _decrypt(self) -> None:
        try:
            cipher = parse_hex(self.cipher_input.get("1.0", "end-1c"), "Bản mã")
            key = self._get_key()
            start = perf_counter()
            plain = decrypt_data(cipher, key)
            t_dec = (perf_counter() - start) * 1000
            self._replace_text(self.recovered_output, self._recovered_display(plain))
            self.status.set(f"Đã giải mã {len(cipher)} byte = {len(cipher)//8} khối trong {t_dec:.3f} ms")
            self.expected_status.set("Giải mã với khóa con K16 đến K1")
            self._activate_trace(cipher, key, plain, "decrypt")
        except (ValueError, RuntimeError) as exc:
            self._clear_result()
            messagebox.showerror("Không thể giải mã", str(exc), parent=self)

    # ------------------ PHẦN 2: xử lý tệp ------------------
    def _build_files(self) -> None:
        self.file_tab.columnconfigure(0, weight=1)
        self.file_tab.rowconfigure(3, weight=1)
        ttk.Label(self.file_tab, text="Mã hóa và giải mã tệp", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(self.file_tab, text="Tệp cần có kích thước chia hết cho 8 byte.").grid(row=1, column=0, sticky="w", pady=(4, 10))
        keyframe = ttk.LabelFrame(self.file_tab, text="Khóa DES dùng cho tệp", padding=10)
        keyframe.grid(row=2, column=0, sticky="ew")
        keyframe.columnconfigure(2, weight=1)
        self.file_key_mode = tk.StringVar(value="text")
        ttk.Label(keyframe, text="Kiểu khóa:").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(keyframe, text="Text", value="text", variable=self.file_key_mode).grid(row=0, column=1, sticky="w", padx=10)
        ttk.Radiobutton(keyframe, text="HEX", value="hex", variable=self.file_key_mode).grid(row=0, column=2, sticky="w")
        ttk.Label(keyframe, text="Khóa:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.file_key_entry = ttk.Entry(keyframe, font=("Consolas", 11))
        self.file_key_entry.grid(row=1, column=1, columnspan=2, sticky="ew", padx=(10, 0), pady=(8, 0))
        self.file_key_entry.insert(0, "8byteKEY")

        body = ttk.Frame(self.file_tab)
        body.grid(row=3, column=0, sticky="nsew", pady=(10, 0))
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(1, weight=1)
        enc_frame = ttk.LabelFrame(body, text="Mã hóa tệp", padding=9)
        dec_frame = ttk.LabelFrame(body, text="Giải mã tệp", padding=9)
        enc_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        dec_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        self.enc_src, self.enc_dst = tk.StringVar(), tk.StringVar()
        self.dec_src, self.dec_dst = tk.StringVar(), tk.StringVar()
        self._path_row(enc_frame, 0, "Nguồn:", self.enc_src, self._choose_enc_source)
        self._path_row(enc_frame, 1, "Đầu ra:", self.enc_dst, self._choose_enc_dest)
        self._path_row(dec_frame, 0, "Tệp .des:", self.dec_src, self._choose_dec_source)
        self._path_row(dec_frame, 1, "Đầu ra:", self.dec_dst, self._choose_dec_dest)
        ttk.Button(enc_frame, text="Mã hóa tệp", style="Primary.TButton", command=self._encrypt_file).pack(anchor="w", pady=10)
        ttk.Button(dec_frame, text="Giải mã tệp", style="Primary.TButton", command=self._decrypt_file).pack(anchor="w", pady=10)
        results = ttk.LabelFrame(body, text="Nhật ký xử lý tệp", padding=9)
        results.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(10, 0))
        results.columnconfigure(0, weight=1)
        results.rowconfigure(0, weight=1)
        self.file_log = ScrolledText(results, height=12, wrap="word", font=("Consolas", 10))
        self.file_log.grid(row=0, column=0, sticky="nsew")
        self.file_log.insert("1.0", "")

    @staticmethod
    def _path_row(frame, row, title, variable, command):
        line = ttk.Frame(frame)
        line.pack(fill="x", pady=(5, 0))
        ttk.Label(line, text=title, width=9).pack(side="left")
        ttk.Entry(line, textvariable=variable).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(line, text="Chọn...", command=command).pack(side="left")

    def _choose_enc_source(self):
        path = filedialog.askopenfilename(title="Chọn file bản rõ")
        if path:
            self.enc_src.set(path)
            self.enc_dst.set(path + ".des")
            self.dec_src.set(path + ".des")
            p = Path(path)
            self.dec_dst.set(str(p.with_name(f"{p.stem}_decrypted{p.suffix}")))

    def _choose_enc_dest(self):
        path = filedialog.asksaveasfilename(title="Lưu bản mã", defaultextension=".des",
                                            filetypes=[("Tệp DES", "*.des"), ("Tất cả", "*.*")])
        if path:
            self.enc_dst.set(path)
            self.dec_src.set(path)

    def _choose_dec_source(self):
        path = filedialog.askopenfilename(title="Chọn file DES")
        if path:
            self.dec_src.set(path)
            p = Path(path)
            name = p.name[:-4] if p.name.lower().endswith(".des") else p.name
            name_path = Path(name)
            self.dec_dst.set(str(p.with_name(f"{name_path.stem}_decrypted{name_path.suffix}")))

    def _choose_dec_dest(self):
        path = filedialog.asksaveasfilename(title="Lưu tệp đã giải mã")
        if path:
            self.dec_dst.set(path)

    def _run_file(self, direction: str):
        try:
            source, dest = (self.enc_src.get(), self.enc_dst.get()) if direction == "encrypt" else (self.dec_src.get(), self.dec_dst.get())
            if not source.strip() or not dest.strip():
                raise ValueError("Cần chọn tệp nguồn và tệp đích.")
            key = parse_key(self.file_key_entry.get(), self.file_key_mode.get())
            t0 = perf_counter()
            processed = (encrypt_file if direction == "encrypt" else decrypt_file)(source, dest, key)
            elapsed = (perf_counter() - t0) * 1000
            operation = "MÃ HÓA" if direction == "encrypt" else "GIẢI MÃ"
            self.file_log.insert("end", f"\n[{operation} THÀNH CÔNG]\nNguồn: {source}\nĐích: {dest}\n"
                                        f"{processed} byte = {processed//8} khối | {elapsed:.3f} ms\n")
            self.file_log.see("end")
        except (ValueError, OSError) as exc:
            messagebox.showerror("Lỗi xử lý tệp", str(exc), parent=self)

    def _encrypt_file(self):
        self._run_file("encrypt")

    def _decrypt_file(self):
        self._run_file("decrypt")

    # ------------------ PHẦN 3: tấn công ------------------
    def _build_attack(self):
        self.attack_tab.columnconfigure(0, weight=1)
        self.attack_tab.rowconfigure(2, weight=1)
        ttk.Label(self.attack_tab, text="Tấn công vét cạn", style="Title.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        message = (
            "Bản rõ đã biết: ATTACK!!. Chương trình thử 4.096 khóa ứng viên "
            "và so sánh với bản mã mục tiêu."
        )
        toolbar = ttk.Frame(self.attack_tab)
        toolbar.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(toolbar, text="Chạy tấn công", style="Primary.TButton", command=self._run_attack).pack(side="left")
        
        frame = ttk.LabelFrame(self.attack_tab, text="Kết quả brute-force", padding=10)
        frame.grid(row=2, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        ttk.Label(frame, text=message, wraplength=1080, justify="left").grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.attack_output = ScrolledText(frame, wrap="word", font=("Consolas", 11))
        self.attack_output.grid(row=1, column=0, sticky="nsew")

    def _run_attack(self):
        self._replace_text(self.attack_output, "Đang thử các khóa ứng viên...\n")
        self.update_idletasks()
        self._replace_text(self.attack_output, build_attack_report())


def main():
    DESApp().mainloop()


if __name__ == "__main__":
    main()
