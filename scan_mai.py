import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import scrolledtext
from tkinter import messagebox
import threading

import vulnerability_scanner.sql_injection_scan as sql_injection_scan
import vulnerability_scanner.zealot_oa_scan as zealot_oa_scan


class ScanProjectSelection:
    def __init__(self, master, original_var, project_list):
        self.master = master
        self.original_var = original_var
        self.project_list = project_list

        self.top = tk.Toplevel(master)
        self.top.title("选择扫描项目")

        # 设置新窗口的大小
        self.top.geometry("400x300")

        self.checkbox_vars = [tk.IntVar() for _ in project_list]

        for i, project in enumerate(project_list):
            checkbox = tk.Checkbutton(self.top, text=project, variable=self.checkbox_vars[i])
            checkbox.pack(padx=10, pady=5)

        confirm_button = ttk.Button(self.top, text="确认", command=self.confirm_selection)
        confirm_button.pack(pady=5)

    def confirm_selection(self):
        selected_projects = [var.get() for var in self.checkbox_vars]
        self.original_var.set(selected_projects)
        self.top.destroy()


class VulnerabilityScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("漏洞扫描器")

        # URL Entry
        self.url_label = ttk.Label(master, text="目标URL:")
        self.url_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

        self.url_entry = ttk.Entry(master, width=50)
        self.url_entry.grid(row=0, column=1, padx=10, pady=5, columnspan=2)

        # Proxy Entry
        self.proxy_label = ttk.Label(master, text="代理:")
        self.proxy_label.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

        self.proxy_entry = ttk.Entry(master, width=50)
        self.proxy_entry.grid(row=1, column=1, padx=10, pady=5, columnspan=2)

        # Target File Selection
        self.file_label = ttk.Label(master, text="选择目标文件:")
        self.file_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)

        self.browse_button = ttk.Button(master, text="选择文件", command=self.browse_file)
        self.browse_button.grid(row=2, column=1, padx=10, pady=5)

        # Scan Options
        self.scan_options_label = ttk.Label(master, text="选择要扫描的漏洞:")
        self.scan_options_label.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)

        self.scan_projects = ["1.泛微e-Weaver SQL注入", "2.致远OA前台密码修改(QVD-2023-21704)"]

        self.project_var = tk.StringVar(value=[1] * len(self.scan_projects))  # 默认全部选中

        self.scan_options_button = ttk.Button(master, text="选择扫描项目", command=self.open_project_selection)
        self.scan_options_button.grid(row=3, column=1, padx=10, pady=5)

        # Output Text
        self.output_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=80, height=20)
        self.output_text.grid(row=5, column=0, padx=10, pady=5, columnspan=3)

        # Scan Button
        self.scan_button = ttk.Button(master, text="开始扫描", command=self.start_scan)
        self.scan_button.grid(row=6, column=0, padx=10, pady=5)

        # Stop Button
        self.stop_button = ttk.Button(master, text="停止扫描", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=6, column=1, padx=10, pady=5)

        # Thread variables
        self.scan_thread = None
        self.stop_thread = threading.Event()

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, file_path)

    def read_urls_from_file(self, file_path):
        try:
            with open(file_path, 'r') as file:
                urls = file.read().splitlines()
            return urls
        except Exception as e:
            messagebox.showerror("错误", f"无法读取文件: {str(e)}")
            return []

    def append_to_output(self, text, color):
        self.output_text.tag_config(color, foreground=color)
        self.output_text.insert(tk.END, text + '\n', color)
        self.output_text.see(tk.END)

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)

    def open_project_selection(self):
        ScanProjectSelection(self.master, self.project_var, self.scan_projects)

    def start_scan(self):
        url_file_path = self.url_entry.get()
        proxy = self.proxy_entry.get()

        if not url_file_path:
            messagebox.showwarning("警告", "请选择包含目标URL的文件")
            return

        # Read URLs from the selected file
        urls = self.read_urls_from_file(url_file_path)

        if not urls:
            return

        # Disable scan button and enable stop button
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # Clear the output window
        self.clear_output()

        # Start the scan in a new thread
        self.scan_thread = threading.Thread(target=self.scan_urls, args=(urls, proxy))
        self.scan_thread.start()

    def stop_scan(self):
        # Set the stop_thread event to stop the scan
        self.stop_thread.set()

    def scan_urls(self, urls, proxy):
        proxies = {'http': proxy, 'https': proxy} if proxy else None
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.667.76 Safari/537.36",
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "Connection": "close",
            "Content-Type": "application/json",
        }

        selected_projects = [project for project, selected in zip(self.scan_projects, self.project_var.get()) if
                             selected]

        for url in urls:
            if self.stop_thread.is_set():
                break

            for project in selected_projects:
                if project == "1.泛微e-Weaver SQL注入":
                    sql_injection_scan.scan_sql_injection(url, proxies, headers, self.append_to_output)
                elif project == "2.致远OA前台密码修改(QVD-2023-21704)":
                    zealot_oa_scan.scan_zealot_oa(url, proxies, headers, self.append_to_output)

        # Enable scan button and disable stop button after the scan is complete
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.stop_thread.clear()


# 主程序入口
if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerGUI(root)
    root.mainloop()
