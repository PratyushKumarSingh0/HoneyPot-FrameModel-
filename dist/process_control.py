import tkinter as tk
import threading
import time

class Process:
    def __init__(self):
        self.running = False

    def start(self):
        self.running = True
        while self.running:
            print("Process is running...")
            time.sleep(1)  # Simulate a long-running process

    def stop(self):
        self.running = False
        print("Process has been stopped.")

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Process Control")
        self.root.geometry("400x300")  # Set the window size to 400x300 pixels

        self.process = None  # Initialize process as None
        self.thread = None

        # Create a frame for better layout
        self.frame = tk.Frame(root)
        self.frame.pack(expand=True, fill=tk.BOTH)

        self.status_label = tk.Label(self.frame, text="Status: Idle", font=("Arial", 14))
        self.status_label.pack(pady=20)

        self.start_button = tk.Button(self.frame, text="Start", command=self.start_process, width=15, height=2)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(self.frame, text="Stop", command=self.stop_process, width=15, height=2)
        self.stop_button.pack(pady=10)

        self.terminate_button = tk.Button(self.frame, text="Terminate", command=self.terminate_process, width=15, height=2)
        self.terminate_button.pack(pady=10)

    def start_process(self):
        if self.process is None or not self.process.running:
            self.process = Process()  # Create a new process instance
            self.thread = threading.Thread(target=self.process.start)
            self.thread.start()
            self.update_status("Status: Running")  # Update the status label

    def stop_process(self):
        if self.process and self.process.running:
            self.process.stop()
            self.thread.join()  # Wait for the thread to finish
            self.process = None  # Discard the process instance
            self.update_status("Status: Stopped")  # Update the status label

    def terminate_process(self):
        if self.process and self.process.running:
            self.process.stop()  # Stop the process immediately
            self.thread.join()  # Wait for the thread to finish
            self.process = None  # Discard the process instance
            self.update_status("Status: Terminated")  # Update the status label

    def update_status(self, message):
        self.status_label.config(text=message)  # Update the label text

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
