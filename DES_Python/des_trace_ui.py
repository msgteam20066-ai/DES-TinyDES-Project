"""Khung quan sát 16 vòng DES NHÚNG trong tab Mã hóa / Giải mã.

Không có cửa sổ / tab đầu vào riêng: dữ liệu trace đến từ nút mã hóa hoặc giải mã.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from des.trace import DESTrace, RoundTrace


class DESRoundViewer(ttk.Frame):
    """Khung tổng hợp IP/PC1, 16 vòng, hàm F và bước FP cho 1 khối."""

    def __init__(self, parent):
        super().__init__(parent, padding=(2, 2))
        self.current_trace: DESTrace | None = None
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self._build()

    def _build(self):
        overview = ttk.LabelFrame(self, text="Tổng quan", padding=4)
        overview.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        self.summary = tk.StringVar(value="Thực hiện mã hóa hoặc giải mã để xem các vòng DES.")
        ttk.Label(overview, textvariable=self.summary, justify="left",
                  font=("Consolas", 9)).pack(anchor="w")

        # Hai vùng hiển thị dùng chung toàn bộ chiều cao còn lại.
        # Không chia đôi chiều cao màn hình như phiên bản cũ.
        self.content_tabs = ttk.Notebook(self)
        self.content_tabs.grid(row=1, column=0, sticky="nsew")
        table_box = ttk.Frame(self.content_tabs, padding=4)
        self.content_tabs.add(table_box, text="Bảng 16 vòng")
        table_box.rowconfigure(1, weight=1)
        table_box.columnconfigure(0, weight=1)
        table_header = ttk.Frame(table_box)
        table_header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 3))
        ttk.Label(table_header, text="Nhấp đúp vào vòng cần xem.").pack(side="left")
        ttk.Button(table_header, text="Xem toàn bảng", command=self._open_table_window).pack(side="right")
        ttk.Button(table_header, text="Xem chi tiết", command=lambda: self.content_tabs.select(1)).pack(side="right", padx=4)

        columns = ("round", "key", "lin", "rin", "f", "lout", "rout")
        self.round_table = ttk.Treeview(table_box, columns=columns, show="headings",
                                        selectmode="browse", height=8)
        settings = {
            "round": ("Vòng", 55), "key": ("Khóa con", 165),
            "lin": ("L trước", 105), "rin": ("R trước", 105),
            "f": ("F(R,K)", 105), "lout": ("L sau", 105), "rout": ("R sau", 105),
        }
        for name, (title, width) in settings.items():
            self.round_table.heading(name, text=title)
            self.round_table.column(name, width=width, minwidth=55, stretch=True, anchor="center")
        self.round_table.grid(row=1, column=0, sticky="nsew")
        table_scroll = ttk.Scrollbar(table_box, orient="vertical", command=self.round_table.yview)
        table_scroll.grid(row=1, column=1, sticky="ns")
        self.round_table.configure(yscrollcommand=table_scroll.set)
        self.round_table.bind("<<TreeviewSelect>>", self._on_selection)
        self.round_table.bind("<Double-1>", self._on_table_doubleclick)

        detail_box = ttk.Frame(self.content_tabs, padding=4)
        self.content_tabs.add(detail_box, text="Chi tiết vòng")
        detail_box.columnconfigure(0, weight=1)
        detail_box.rowconfigure(1, weight=1)
        toolbar = ttk.Frame(detail_box)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        self.round_title = tk.StringVar(value="Vòng – / 16")
        ttk.Label(toolbar, textvariable=self.round_title,
                  font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(toolbar, text="Sinh khóa", command=lambda: self.jump_to("A. SINH KHÓA")).pack(side="left", padx=(12, 2))
        ttk.Button(toolbar, text="Hàm F", command=lambda: self.jump_to("C. HÀM F")).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Feistel", command=lambda: self.jump_to("D. CẬP NHẬT")).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Mở rộng", command=self._open_details_window).pack(side="right", padx=(3, 0))
        ttk.Button(toolbar, text="Vòng sau", command=lambda: self.change_round(1)).pack(side="right", padx=2)
        ttk.Button(toolbar, text="Vòng trước", command=lambda: self.change_round(-1)).pack(side="right", padx=2)

        # ScrolledText có thanh cuộn dọc riêng: có thể đọc đến dòng cuối mỗi vòng.
        self.details = ScrolledText(detail_box, wrap="word", font=("Consolas", 10),
                                    height=11, state="disabled")
        self.details.grid(row=1, column=0, sticky="nsew")

    def _on_table_doubleclick(self, _event):
        if self.current_trace:
            self.content_tabs.select(1)

    def _open_table_window(self):
        if self.current_trace is None:
            return
        window = tk.Toplevel(self)
        window.title("DES - Bảng 16 vòng Feistel")
        window.geometry("1050x540")
        frame = ttk.Frame(window, padding=12)
        frame.pack(fill="both", expand=True)
        cols = tuple(self.round_table["columns"])
        table = ttk.Treeview(frame, columns=cols, show="headings", height=16)
        for name in cols:
            table.heading(name, text=self.round_table.heading(name)["text"])
            table.column(name, width=145 if name == "key" else 110,
                         anchor="center", stretch=True)
        for iid in self.round_table.get_children():
            table.insert("", "end", values=self.round_table.item(iid, "values"))
        table.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=table.yview)
        scrollbar.pack(side="right", fill="y")
        table.configure(yscrollcommand=scrollbar.set)

    def _open_details_window(self):
        if self.current_trace is None:
            return
        window = tk.Toplevel(self)
        window.title("DES - " + self.round_title.get())
        window.geometry("1040x660")
        contents = ScrolledText(window, wrap="word", font=("Consolas", 12))
        contents.pack(fill="both", expand=True, padx=12, pady=12)
        contents.insert("1.0", self.details.get("1.0", "end-1c"))
        contents.configure(state="disabled")

    def clear(self) -> None:
        self.current_trace = None
        self.summary.set("Chưa có mô phỏng.")
        for iid in self.round_table.get_children():
            self.round_table.delete(iid)
        self.round_title.set("Vòng – / 16")
        self._set_details("")

    def load_trace(self, trace: DESTrace, block_index: int, block_count: int) -> None:
        self.current_trace = trace
        operation = "MÃ HÓA" if trace.operation == "encrypt" else "GIẢI MÃ"
        output = "BẢN MÃ" if trace.operation == "encrypt" else "BẢN RÕ"
        self.summary.set(
            f"{operation} | Khối {block_index}/{block_count} | "
            f"Đầu vào={trace.input_block.hex().upper()}  Khóa={trace.key.hex().upper()}\n"
            f"IP={trace.ip_output64:016X}   L0={trace.left0:08X} R0={trace.right0:08X}\n"
            f"PC-1={trace.pc1_output56:014X}   C0={trace.c0:07X} D0={trace.d0:07X}\n"
            f"R16||L16={trace.preoutput64:016X} → FP → {output}={trace.output_block.hex().upper()}"
        )
        for iid in self.round_table.get_children():
            self.round_table.delete(iid)
        for r in trace.rounds:
            self.round_table.insert("", "end", iid=str(r.number), values=(
                f"{r.number:02d}", f"K{r.key_index:02d}={r.subkey48:012X}",
                f"{r.left_before:08X}", f"{r.right_before:08X}",
                f"{r.f_output32:08X}", f"{r.left_after:08X}", f"{r.right_after:08X}",
            ))
        self.select_round(1)
        self.content_tabs.select(0)

    def select_round(self, number: int) -> None:
        if self.current_trace is None or not 1 <= number <= 16:
            return
        iid = str(number)
        self.round_table.selection_set(iid)
        self.round_table.focus(iid)
        self.round_table.see(iid)
        self._show_round(number)

    def change_round(self, delta: int) -> None:
        if self.current_trace is None:
            return
        selected = self.round_table.selection()
        current = int(selected[0]) if selected else 1
        self.select_round(max(1, min(16, current + delta)))

    def _on_selection(self, _event) -> None:
        selected = self.round_table.selection()
        if selected and self.current_trace is not None:
            self._show_round(int(selected[0]))

    def _set_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")
        self.details.yview_moveto(0)

    def jump_to(self, heading: str) -> None:
        p = self.details.search(heading, "1.0", stopindex="end")
        if p:
            self.details.see(p)

    def _show_round(self, number: int) -> None:
        trace = self.current_trace
        if trace is None:
            return
        r: RoundTrace = trace.rounds[number - 1]
        self.round_title.set(f"VÒNG {number:02d}/16 – sử dụng K{r.key_index:02d}")
        notes = (
            "Mã hóa: dùng khóa con theo thứ tự K1 → K16."
            if trace.operation == "encrypt" else
            "Giải mã: dùng các khóa K16 → K1; C,D dưới đây là lịch SINH KHÓA GỐC (dịch trái)."
        )
        lines = [
            f"CHI TIẾT VÒNG {number:02d}/16 – {'MÃ HÓA' if trace.operation == 'encrypt' else 'GIẢI MÃ'}",
            notes,
            "",
            f"A. SINH KHÓA CON K{r.key_index:02d} (PC-1 → dịch vòng trái → PC-2)",
            f"   C trước = {r.c_before:07X}  D trước = {r.d_before:07X} (mỗi nửa 28 bit)",
            f"   Dịch vòng trái {r.shift} bit → C = {r.c_after:07X}  D = {r.d_after:07X}",
            f"   PC-2(C||D) → K{r.key_index:02d} = {r.subkey48:012X} (48 bit)",
            "",
            "B. ĐẦU VÀO VÒNG FEISTEL (32 bit mỗi nửa)",
            f"   L{number - 1:02d} = {r.left_before:08X}       R{number - 1:02d} = {r.right_before:08X}",
            "",
            "C. HÀM F(R, K)",
            "   1) E: mở rộng R từ 32 bit → 48 bit",
            f"      E(R) = {r.expanded48:012X}",
            f"      BIN  = {r.expanded48:048b}",
            "   2) XOR với khóa con 48 bit",
            f"      K{r.key_index:02d} = {r.subkey48:012X}",
            f"      E(R) XOR K{r.key_index:02d} = {r.mixed48:012X}",
            f"      BIN = {r.mixed48:048b}",
            "   3) S-box: chia thành 8 nhóm 6 bit; hàng=bit đầu/cuối, cột=4 bit giữa",
        ]
        for s in r.sboxes:
            lines.append(f"      S{s.number}: {s.input6:06b} → hàng {s.row} ({s.row:02b}), "
                         f"cột {s.column:2d} ({s.column:04b}) → {s.output4:04b} (HEX {s.output4:X})")
        lines.extend([
            f"      Ghép 8 S-box = {r.sboxes_output32:08X} (32 bit)",
            "   4) P-box: hoán vị 32 bit",
            f"      F(R,K{r.key_index:02d}) = {r.f_output32:08X}",
            "",
            "D. CẬP NHẬT FEISTEL",
            f"   L{number:02d} = R{number - 1:02d} = {r.left_after:08X}",
            f"   R{number:02d} = L{number - 1:02d} XOR F(R,K{r.key_index:02d})",
            f"       = {r.left_before:08X} XOR {r.f_output32:08X}",
            f"       = {r.right_after:08X}",
        ])
        if number == 16:
            end_label = "bản mã" if trace.operation == "encrypt" else "bản rõ"
            lines.extend([
                "", "E. KẾT THÚC 16 VÒNG",
                f"   Hoán đổi: R16 || L16 = {trace.preoutput64:016X}",
                f"   FP(R16 || L16) = {trace.output_block.hex().upper()} ({end_label})",
            ])
        self._set_details("\n".join(lines))
